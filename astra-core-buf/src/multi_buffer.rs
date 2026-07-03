use std::collections::VecDeque;

use crate::buffer::Buffer;

#[derive(Default)]
pub struct MultiBuffer {
    bufs: VecDeque<Buffer>,
    total_len: usize,
}

impl MultiBuffer {
    pub fn new() -> Self {
        MultiBuffer {
            bufs: VecDeque::new(),
            total_len: 0,
        }
    }

    pub fn with_buffer(buf: Buffer) -> Self {
        let len = buf.len();
        let mut mb = MultiBuffer::new();
        mb.total_len = len;
        mb.bufs.push_back(buf);
        mb
    }

    pub fn len(&self) -> usize {
        self.total_len
    }

    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }

    pub fn num_buffers(&self) -> usize {
        self.bufs.len()
    }

    pub fn push_back(&mut self, buf: Buffer) {
        self.total_len += buf.len();
        self.bufs.push_back(buf);
    }

    pub fn push_front(&mut self, buf: Buffer) {
        self.total_len += buf.len();
        self.bufs.push_front(buf);
    }

    pub fn pop_front(&mut self) -> Option<Buffer> {
        let buf = self.bufs.pop_front()?;
        self.total_len -= buf.len();
        Some(buf)
    }

    pub fn front(&self) -> Option<&Buffer> {
        self.bufs.front()
    }

    pub fn front_mut(&mut self) -> Option<&mut Buffer> {
        self.bufs.front_mut()
    }

    pub fn append(&mut self, other: &mut MultiBuffer) {
        for buf in other.bufs.drain(..) {
            self.total_len += buf.len();
            self.bufs.push_back(buf);
        }
    }

    pub fn cut_front(&mut self, n: usize) -> MultiBuffer {
        let mut result = MultiBuffer::new();
        let mut remaining = n;
        while remaining > 0 {
            let buf = match self.bufs.front_mut() {
                None => break,
                Some(buf) => buf,
            };
            let buf_len = buf.len();
            if buf_len <= remaining {
                remaining -= buf_len;
                self.total_len -= buf_len;
                result.push_back(self.bufs.pop_front().unwrap());
            } else {
                let take = remaining;
                let mut new_buf = Buffer::new();
                new_buf.extend(take).copy_from_slice(&buf.slice()[..take]);
                buf.advance(take);
                self.total_len -= take;
                remaining = 0;
                result.push_back(new_buf);
            }
        }
        result
    }

    pub fn split_off(&mut self, at: usize) -> MultiBuffer {
        let mut result = MultiBuffer::new();
        let mut count = 0usize;
        let split_idx = {
            let mut idx = 0;
            for buf in self.bufs.iter() {
                if count + buf.len() > at {
                    break;
                }
                count += buf.len();
                idx += 1;
            }
            idx
        };
        while self.bufs.len() > split_idx {
            let buf = self.bufs.pop_back().unwrap();
            self.total_len -= buf.len();
            result.push_front(buf);
        }
        result
    }

    pub fn iter(&self) -> impl Iterator<Item = &Buffer> {
        self.bufs.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Buffer> {
        self.bufs.iter_mut()
    }

    pub fn read_into(&mut self, data: &mut [u8]) -> usize {
        let mut copied = 0;
        while copied < data.len() {
            let buf = match self.bufs.front_mut() {
                None => break,
                Some(buf) => buf,
            };
            let n = data.len().min(buf.len());
            data[copied..copied + n].copy_from_slice(&buf.slice()[..n]);
            buf.advance(n);
            copied += n;
            self.total_len -= n;
            if buf.is_empty() {
                self.bufs.pop_front();
            }
        }
        copied
    }

    pub fn release_all(&mut self) {
        for buf in self.bufs.drain(..) {
            drop(buf);
        }
        self.total_len = 0;
    }

    pub fn copy_bytes(&self, data: &mut [u8]) -> usize {
        let mut copied = 0;
        for buf in &self.bufs {
            if copied >= data.len() {
                break;
            }
            let n = (data.len() - copied).min(buf.len());
            data[copied..copied + n].copy_from_slice(&buf.slice()[..n]);
            copied += n;
        }
        copied
    }
}

impl IntoIterator for MultiBuffer {
    type Item = Buffer;
    type IntoIter = std::collections::vec_deque::IntoIter<Buffer>;

    fn into_iter(self) -> Self::IntoIter {
        self.bufs.into_iter()
    }
}

impl From<Buffer> for MultiBuffer {
    fn from(buf: Buffer) -> Self {
        MultiBuffer::with_buffer(buf)
    }
}

impl std::fmt::Debug for MultiBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MultiBuffer({} buffers, {} bytes)", self.bufs.len(), self.total_len)
    }
}
