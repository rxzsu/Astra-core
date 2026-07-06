use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::Arc;

use tokio::sync::Mutex;

#[derive(Clone)]
struct Packet {
    seq: u64,
    data: Vec<u8>,
}

impl Ord for Packet {
    fn cmp(&self, other: &Self) -> Ordering {
        other.seq.cmp(&self.seq)
    }
}

impl PartialOrd for Packet {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Packet {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq
    }
}

impl Eq for Packet {}

#[derive(Clone)]
pub struct UploadQueue {
    inner: Arc<Mutex<UploadQueueInner>>,
}

struct UploadQueueInner {
    heap: BinaryHeap<Packet>,
    next_seq: u64,
    max_packets: usize,
}

impl Default for UploadQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl UploadQueue {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(UploadQueueInner {
                heap: BinaryHeap::new(),
                next_seq: 0,
                max_packets: 128,
            })),
        }
    }

    pub async fn push(&self, seq: u64, data: Vec<u8>) {
        let mut inner = self.inner.lock().await;
        if seq < inner.next_seq {
            return;
        }
        if inner.heap.len() >= inner.max_packets {
            return;
        }
        inner.heap.push(Packet { seq, data });
    }

    pub async fn try_pop(&self) -> Option<Vec<u8>> {
        let mut inner = self.inner.lock().await;
        if inner.heap.is_empty() {
            return None;
        }
        let next = inner.next_seq;
        if inner.heap.peek().map(|p| p.seq) == Some(next) {
            let pkt = inner.heap.pop().unwrap();
            inner.next_seq += 1;
            return Some(pkt.data);
        }
        None
    }

    pub async fn pop(&self) -> Option<Vec<u8>> {
        loop {
            if let Some(data) = self.try_pop().await {
                return Some(data);
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}
