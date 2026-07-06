use std::collections::HashMap;

use bytes::Bytes;

use crate::segment::*;

pub struct ReceivingWindow {
    cache: HashMap<u32, DataSegment>,
}

impl ReceivingWindow {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    pub fn set(&mut self, id: u32, seg: DataSegment) -> bool {
        if self.cache.contains_key(&id) {
            false
        } else {
            self.cache.insert(id, seg);
            true
        }
    }

    pub fn has(&self, id: u32) -> bool {
        self.cache.contains_key(&id)
    }

    pub fn remove(&mut self, id: u32) -> Option<DataSegment> {
        self.cache.remove(&id)
    }
}

pub struct AckList {
    timestamps: Vec<u32>,
    numbers: Vec<u32>,
    next_flush: Vec<u32>,
    flush_candidates: Vec<u32>,
    dirty: bool,
    mss: u32,
}

impl AckList {
    pub fn new(mss: u32) -> Self {
        Self {
            timestamps: Vec::with_capacity(128),
            numbers: Vec::with_capacity(128),
            next_flush: Vec::with_capacity(128),
            flush_candidates: Vec::with_capacity(128),
            dirty: false,
            mss,
        }
    }

    pub fn add(&mut self, number: u32, timestamp: u32) {
        self.timestamps.push(timestamp);
        self.numbers.push(number);
        self.next_flush.push(0);
        self.dirty = true;
    }

    pub fn clear(&mut self, una: u32) {
        let mut count = 0;
        for i in 0..self.numbers.len() {
            if self.numbers[i] < una {
                continue;
            }
            if i != count {
                self.numbers[count] = self.numbers[i];
                self.timestamps[count] = self.timestamps[i];
                self.next_flush[count] = self.next_flush[i];
            }
            count += 1;
        }
        if count < self.numbers.len() {
            self.numbers.truncate(count);
            self.timestamps.truncate(count);
            self.next_flush.truncate(count);
            self.dirty = true;
        }
    }

    pub fn need_flush(&self) -> bool {
        !self.numbers.is_empty()
    }

    pub fn flush(&mut self, current: u32, rto: u32, conv: u16) -> Vec<AckSegment> {
        self.flush_candidates.clear();

        let max_acks = ((self.mss as usize).saturating_sub(17)) / 4;
        let mut seg = AckSegment::new(max_acks);
        seg.conv = conv;

        let mut result = Vec::new();

        for i in 0..self.numbers.len() {
            if self.next_flush[i] > current {
                if self.flush_candidates.len() < self.flush_candidates.capacity() {
                    self.flush_candidates.push(self.numbers[i]);
                }
                continue;
            }
            seg.put_number(self.numbers[i]);
            seg.put_timestamp(self.timestamps[i]);
            let timeout = (rto / 2).max(20);
            self.next_flush[i] = current + timeout;

            if seg.is_full() {
                result.push(seg);
                seg = AckSegment::new(max_acks);
                seg.conv = conv;
                self.dirty = false;
            }
        }

        if self.dirty || !seg.is_empty() {
            for &n in &self.flush_candidates {
                if seg.is_full() {
                    break;
                }
                seg.put_number(n);
            }
            result.push(seg);
            self.dirty = false;
        }

        result
    }
}

pub struct ReceivingWorker {
    window: ReceivingWindow,
    acklist: AckList,
    next_number: u32,
    window_size: u32,
}

impl ReceivingWorker {
    pub fn new(mss: u32) -> Self {
        Self {
            window: ReceivingWindow::new(),
            acklist: AckList::new(mss + DATA_SEGMENT_OVERHEAD as u32),
            next_number: 0,
            window_size: 1024,
        }
    }

    pub fn set_window_size(&mut self, sz: u32) {
        self.window_size = sz;
    }

    pub fn release(&mut self) {
        self.window.cache.clear();
    }

    pub fn process_sending_next(&mut self, number: u32) {
        self.acklist.clear(number);
    }

    pub fn process_segment(&mut self, seg: &DataSegment) {
        let number = seg.number;
        let idx = number.wrapping_sub(self.next_number);
        if idx >= self.window_size {
            return;
        }
        self.acklist.clear(seg.sending_next);
        self.acklist.add(number, seg.timestamp);

        self.window.set(seg.number, seg.clone());
    }

    pub fn read_multi_buffer(&mut self) -> Vec<Bytes> {
        let mut result = Vec::new();
        loop {
            match self.window.remove(self.next_number) {
                Some(seg) => {
                    self.next_number += 1;
                    result.push(seg.payload);
                }
                None => break,
            }
        }
        result
    }

    pub fn is_data_available(&self) -> bool {
        self.window.has(self.next_number)
    }

    pub fn next_number(&self) -> u32 {
        self.next_number
    }

    pub fn flush_acks(&mut self, current: u32, rto: u32, conv: u16) -> Vec<AckSegment> {
        let mut segs = self.acklist.flush(current, rto, conv);
        for seg in &mut segs {
            seg.receiving_next = self.next_number;
            seg.receiving_window = self.next_number + self.window_size;
        }
        segs
    }

    pub fn update_necessary(&self) -> bool {
        self.acklist.need_flush()
    }

    pub fn close_read(&mut self) {}
}
