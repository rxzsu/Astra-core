use std::io::{self, Read, Write};

use crate::pool;

pub const SIZE: usize = 8192;

pub struct Buffer {
    data: Box<[u8; SIZE]>,
    start: usize,
    end: usize,
}

impl Buffer {
    pub fn new() -> Self {
        Buffer {
            data: pool::alloc(),
            start: 0,
            end: 0,
        }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        let mut b = Buffer::new();
        let len = data.len().min(SIZE);
        b.data[..len].copy_from_slice(&data[..len]);
        b.end = len;
        b
    }

    pub fn slice(&self) -> &[u8] {
        &self.data[self.start..self.end]
    }

    pub fn slice_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.start..self.end]
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> usize {
        SIZE
    }

    pub fn available(&self) -> usize {
        SIZE - self.end
    }

    pub fn is_full(&self) -> bool {
        self.end == SIZE
    }

    pub fn writable_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.end..]
    }

    pub fn set_end(&mut self, n: usize) {
        self.end = n;
    }

    pub fn clear(&mut self) {
        self.start = 0;
        self.end = 0;
    }

    pub fn advance(&mut self, n: usize) {
        let n = n.min(self.len());
        self.start += n;
        if self.start == self.end {
            self.clear();
        }
    }

    pub fn extend(&mut self, n: usize) -> &mut [u8] {
        let new_end = self.end + n;
        assert!(new_end <= SIZE, "buffer overflow");
        self.end = new_end;
        &mut self.data[self.end - n..self.end]
    }

    pub fn resize(&mut self, from: usize, to: usize) {
        assert!(to >= from);
        let len = self.len();
        assert!(from <= len && to <= len);
        self.start += from;
        self.end = self.start + (to - from);
    }

    pub fn byte(&self, index: usize) -> u8 {
        self.data[self.start + index]
    }

    pub fn set_byte(&mut self, index: usize, value: u8) {
        self.data[self.start + index] = value;
    }

    pub fn bytes_range(&self, from: isize, to: isize) -> &[u8] {
        let len = self.len() as isize;
        let f = if from < 0 { len + from } else { from } as usize;
        let t = if to < 0 { len + to } else { to } as usize;
        &self.data[self.start + f..self.start + t]
    }

    pub fn bytes_from(&self, from: isize) -> &[u8] {
        let len = self.len() as isize;
        let f = if from < 0 { len + from } else { from } as usize;
        &self.data[self.start + f..self.end]
    }

    pub fn bytes_to(&self, to: isize) -> &[u8] {
        let len = self.len() as isize;
        let t = if to < 0 { len + to } else { to } as usize;
        &self.data[self.start..self.start + t]
    }

    pub fn release(&mut self) {
        let data = std::mem::replace(&mut self.data, Box::new([0u8; SIZE]));
        pool::release(data);
        self.start = 0;
        self.end = 0;
    }
}

impl Write for Buffer {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let avail = self.available();
        if avail == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "buffer is full"));
        }
        let n = data.len().min(avail);
        self.data[self.end..self.end + n].copy_from_slice(&data[..n]);
        self.end += n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for Buffer {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        if self.is_empty() {
            return Ok(0);
        }
        let n = data.len().min(self.len());
        data[..n].copy_from_slice(&self.data[self.start..self.start + n]);
        self.start += n;
        if self.start == self.end {
            self.clear();
        }
        Ok(n)
    }
}

impl io::Read for &Buffer {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        if self.is_empty() {
            return Ok(0);
        }
        let n = data.len().min(self.len());
        data[..n].copy_from_slice(&self.data[self.start..self.start + n]);
        Ok(n)
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        self.slice()
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Buffer {
    fn clone(&self) -> Self {
        let mut b = Buffer::new();
        let n = self.len();
        b.data[..n].copy_from_slice(self.slice());
        b.end = n;
        b
    }
}
