use std::time::Duration;

use crate::segment::DATA_SEGMENT_OVERHEAD;

#[derive(Clone)]
pub struct Config {
    pub mtu: u32,
    pub tti: u32,
    pub uplink_capacity: u32,
    pub downlink_capacity: u32,
    pub cwnd_multiplier: u32,
    pub max_sending_window: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mtu: 1350,
            tti: 50,
            uplink_capacity: 5,
            downlink_capacity: 20,
            cwnd_multiplier: 1,
            max_sending_window: 2 * 1024 * 1024,
        }
    }
}

impl Config {
    pub fn sending_in_flight_size(&self) -> u32 {
        let size = self.uplink_capacity * 1024 * 1024 / self.mtu / (1000 / self.tti);
        if size < 8 { 8 } else { size }
    }

    pub fn sending_buffer_size(&self) -> u32 {
        self.max_sending_window / self.mtu
    }

    pub fn receiving_in_flight_size(&self) -> u32 {
        let size = self.downlink_capacity * 1024 * 1024 / self.mtu / (1000 / self.tti);
        if size < 8 { 8 } else { size }
    }

    pub fn mss(&self) -> u32 {
        self.mtu - DATA_SEGMENT_OVERHEAD as u32
    }

    pub fn tti_duration(&self) -> Duration {
        Duration::from_millis(self.tti as u64)
    }
}
