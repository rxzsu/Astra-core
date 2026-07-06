use std::collections::VecDeque;

use bytes::Bytes;

use crate::config::Config;
use crate::segment::*;

pub struct SendingWindow {
    cache: VecDeque<DataSegment>,
    total_in_flight_size: u32,
}

impl SendingWindow {
    pub fn new() -> Self {
        Self {
            cache: VecDeque::new(),
            total_in_flight_size: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    pub fn push(&mut self, number: u32, payload: Bytes) {
        let seg = DataSegment {
            conv: 0,
            option: SegmentOption(0),
            timestamp: 0,
            number,
            sending_next: 0,
            payload,
            timeout: 0,
            transmit: 0,
        };
        self.cache.push_back(seg);
    }

    pub fn first_number(&self) -> u32 {
        self.cache.front().map(|s| s.number).unwrap_or(0)
    }

    pub fn clear(&mut self, una: u32) {
        while let Some(front) = self.cache.front() {
            if front.number >= una {
                break;
            }
            self.cache.pop_front();
        }
    }

    pub fn handle_fast_ack(&mut self, number: u32, rto: u32) {
        for seg in &mut self.cache {
            if number.wrapping_sub(seg.number) > 0x7FFFFFFF {
                break;
            }
            if seg.transmit > 0 && seg.timeout > rto / 3 {
                seg.timeout -= rto / 3;
            }
        }
    }

    pub fn flush(&mut self, current: u32, rto: u32, max_in_flight_size: u32) -> Vec<DataSegment> {
        if self.is_empty() {
            return Vec::new();
        }

        let mut result = Vec::new();
        let mut in_flight = 0u32;

        for seg in &mut self.cache {
            if current.wrapping_sub(seg.timeout) >= 0x7FFFFFFF {
                continue;
            }
            if seg.transmit == 0 {
                self.total_in_flight_size += 1;
            }
            seg.timeout = current + rto;
            seg.timestamp = current;
            seg.transmit += 1;
            result.push(seg.clone());
            in_flight += 1;
            if in_flight >= max_in_flight_size {
                break;
            }
        }

        result
    }

    pub fn remove(&mut self, number: u32) -> bool {
        if let Some(idx) = self.cache.iter().position(|s| s.number == number) {
            if self.total_in_flight_size > 0 {
                self.total_in_flight_size -= 1;
            }
            self.cache.remove(idx);
            true
        } else {
            false
        }
    }

    pub fn loss_rate(&self) -> u32 {
        if self.total_in_flight_size == 0 {
            0
        } else {
            let total = self.cache.len() as u32;
            let lost = total.saturating_sub(self.total_in_flight_size);
            lost * 100 / self.total_in_flight_size
        }
    }
}

pub struct SendingWorker {
    window: SendingWindow,
    first_unacknowledged: u32,
    next_number: u32,
    remote_next_number: u32,
    control_window: u32,
    window_size: u32,
    first_unacknowledged_updated: bool,
    closed: bool,
}

impl SendingWorker {
    pub fn new(config: &Config) -> Self {
        Self {
            window: SendingWindow::new(),
            first_unacknowledged: 0,
            next_number: 0,
            remote_next_number: 32,
            control_window: config.sending_in_flight_size(),
            window_size: config.sending_buffer_size(),
            first_unacknowledged_updated: false,
            closed: false,
        }
    }

    pub fn release(&mut self) {
        self.window.cache.clear();
        self.closed = true;
    }

    pub fn process_receiving_next(&mut self, next_number: u32) {
        self.window.clear(next_number);
        self.find_first_unacknowledged();
    }

    fn find_first_unacknowledged(&mut self) {
        let first = self.first_unacknowledged;
        self.first_unacknowledged = if !self.window.is_empty() {
            self.window.first_number()
        } else {
            self.next_number
        };
        if first != self.first_unacknowledged {
            self.first_unacknowledged_updated = true;
        }
    }

    fn process_ack(&mut self, number: u32) -> bool {
        if number.wrapping_sub(self.first_unacknowledged) > 0x7FFFFFFF
            || number.wrapping_sub(self.next_number) < 0x7FFFFFFF
        {
            return false;
        }
        let removed = self.window.remove(number);
        if removed {
            self.find_first_unacknowledged();
        }
        removed
    }

    pub fn process_segment(&mut self, _current: u32, seg: &AckSegment, rto: u32) {
        if self.closed {
            return;
        }
        if self.remote_next_number < seg.receiving_window {
            self.remote_next_number = seg.receiving_window;
        }
        self.process_receiving_next(seg.receiving_next);

        if seg.is_empty() {
            return;
        }

        let mut maxack = 0u32;
        let mut maxack_removed = false;
        for &number in &seg.number_list {
            let removed = self.process_ack(number);
            if maxack < number {
                maxack = number;
                maxack_removed = removed;
            }
        }

        if maxack_removed {
            self.window.handle_fast_ack(maxack, rto);
        }
    }

    pub fn push(&mut self, payload: Bytes) -> bool {
        if self.closed {
            return false;
        }
        if self.window.len() as u32 > self.window_size {
            return false;
        }
        self.window.push(self.next_number, payload);
        self.next_number += 1;
        true
    }

    pub fn flush(&mut self, current: u32, config: &Config, rto: u32) -> Vec<DataSegment> {
        if self.closed {
            return Vec::new();
        }

        let mut cwnd = config.sending_in_flight_size();
        let window_gap = self.remote_next_number.wrapping_sub(self.first_unacknowledged);
        if cwnd > window_gap {
            cwnd = window_gap;
        }
        if cwnd > self.control_window {
            cwnd = self.control_window;
        }
        cwnd *= config.cwnd_multiplier;

        if !self.window.is_empty() {
            let segs = self.window.flush(current, rto, cwnd);
            self.first_unacknowledged_updated = false;
            segs
        } else {
            Vec::new()
        }
    }

    pub fn close_write(&mut self) {
        self.window.clear(0xFFFFFFFF);
    }

    pub fn is_empty(&self) -> bool {
        self.window.is_empty()
    }

    pub fn update_necessary(&self) -> bool {
        !self.is_empty()
    }

    pub fn first_unacknowledged(&self) -> u32 {
        self.first_unacknowledged
    }

    pub fn next_number(&self) -> u32 {
        self.next_number
    }
}
