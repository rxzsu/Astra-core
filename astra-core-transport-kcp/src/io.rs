use crate::segment::{read_segment, Segment};

pub struct KcpPacketReader;

impl KcpPacketReader {
    pub fn read(&self, data: &[u8]) -> Vec<Segment> {
        let mut result = Vec::new();
        let mut remaining = data;
        while !remaining.is_empty() {
            match read_segment(remaining) {
                Some((seg, rest)) => {
                    result.push(seg);
                    remaining = rest;
                }
                None => break,
            }
        }
        result
    }
}
