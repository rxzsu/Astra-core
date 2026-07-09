use std::io::{self, Read};

use crate::buffer::{Buffer, SIZE};
use crate::io::{read_one_buffer, Reader};
use crate::multi_buffer::MultiBuffer;

pub struct SingleReader {
    inner: Box<dyn Read>,
}

impl SingleReader {
    pub fn new(r: impl Read + 'static) -> Self {
        SingleReader {
            inner: Box::new(r),
        }
    }
}

impl Reader for SingleReader {
    fn read_multi_buffer(&mut self) -> io::Result<MultiBuffer> {
        match read_one_buffer(&mut *self.inner)? {
            None => Ok(MultiBuffer::new()),
            Some(buf) => Ok(MultiBuffer::with_buffer(buf)),
        }
    }
}

// ─── ReadVReader (scatter/gather) ───────────────────────────────────────────

/// Adaptive scatter/gather reader using platform vectors.
/// Reads into up to 8 buffers in a single syscall.
/// Go equivalent: `buf.ReadVReader`
pub struct ReadVReader {
    inner: Box<dyn Read>,
    alloc_level: u32, // 1..8
}

impl ReadVReader {
    pub fn new(r: impl Read + 'static) -> Self {
        ReadVReader { inner: Box::new(r), alloc_level: 1 }
    }

    fn adjust(&mut self, n_bufs: u32) {
        if n_bufs >= self.alloc_level {
            self.alloc_level = (self.alloc_level * 2).min(8);
        } else {
            self.alloc_level = n_bufs.max(1);
        }
    }

    fn read_multi_native(&mut self, bufs: &mut [Buffer]) -> io::Result<usize> {
        // On first call with level == 1, try a single read
        if self.alloc_level == 1 {
            match read_one_buffer(&mut *self.inner)? {
                Some(buf) => {
                    bufs[0] = buf;
                    let n = bufs[0].len();
                    if n >= SIZE {
                        self.adjust(1);
                    }
                    return Ok(n);
                }
                None => return Ok(0),
            }
        }

        // Multi-buffer read using platform iovec
        let n = platform_readv(&mut *self.inner, bufs)?;
        if n > 0 {
            let consumed = {
                let mut remaining = n;
                let mut count = 0;
                for b in bufs.iter_mut() {
                    if remaining == 0 {
                        b.set_end(0);
                    } else {
                        let chunk = remaining.min(SIZE);
                        b.set_end(chunk);
                        remaining -= chunk;
                        count += 1;
                    }
                }
                count as u32
            };
            self.adjust(consumed);
        }
        Ok(n)
    }
}

impl Reader for ReadVReader {
    fn read_multi_buffer(&mut self) -> io::Result<MultiBuffer> {
        let mut bufs: Vec<Buffer> = (0..self.alloc_level).map(|_| Buffer::new()).collect();
        let n = self.read_multi_native(&mut bufs)?;
        if n == 0 {
            return Ok(MultiBuffer::new());
        }
        let mut mb = MultiBuffer::new();
        for b in bufs.into_iter() {
            if b.is_empty() {
                break;
            }
            mb.push_back(b);
        }
        Ok(mb)
    }
}

#[cfg(any(unix, windows))]
fn platform_readv(reader: &mut dyn Read, bufs: &mut [Buffer]) -> io::Result<usize> {
    let mut total = 0;
    for i in 0..bufs.len() {
        let len = {
            let slice = bufs[i].writable_mut();
            match reader.read(slice) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        };
        bufs[i].set_end(len);
        total += len;
        if len < bufs[i].writable_mut().len() {
            break;
        }
    }
    Ok(total)
}

#[cfg(not(any(unix, windows)))]
fn platform_readv(reader: &mut dyn Read, bufs: &mut [Buffer]) -> io::Result<usize> {
    let mut total = 0;
    for i in 0..bufs.len() {
        let len = {
            let slice = bufs[i].writable_mut();
            match reader.read(slice) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        };
        bufs[i].set_end(len);
        total += len;
        if len < bufs[i].writable_mut().len() { break; }
    }
    Ok(total)
}

pub struct PacketReader {
    inner: Box<dyn Read>,
}

impl PacketReader {
    pub fn new(r: impl Read + 'static) -> Self {
        PacketReader {
            inner: Box::new(r),
        }
    }

    fn read_one_udp(&mut self) -> io::Result<Option<MultiBuffer>> {
        read_one_buffer(&mut *self.inner).map(|opt| opt.map(MultiBuffer::with_buffer))
    }
}

impl Reader for PacketReader {
    fn read_multi_buffer(&mut self) -> io::Result<MultiBuffer> {
        let mut retries = 0;
        loop {
            match self.read_one_udp()? {
                Some(mb) if mb.is_empty() => {
                    retries += 1;
                    if retries > 64 {
                        return Ok(mb);
                    }
                    continue;
                }
                result => return result.ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof)),
            }
        }
    }
}

pub struct BufferedReader {
    reader: Box<dyn Reader>,
    buf: MultiBuffer,
}

impl BufferedReader {
    pub fn new(reader: impl Reader + 'static) -> Self {
        BufferedReader {
            reader: Box::new(reader),
            buf: MultiBuffer::new(),
        }
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buf.len()
    }

    pub fn read_at_most(&mut self, size: usize) -> io::Result<MultiBuffer> {
        if self.buf.len() >= size {
            return Ok(self.buf.cut_front(size));
        }
        let _needed = size - self.buf.len();
        let mut more = self.reader.read_multi_buffer()?;
        if !more.is_empty() {
            self.buf.append(&mut more);
        }
        let mut result = std::mem::replace(&mut self.buf, MultiBuffer::new());
        Ok(result.cut_front(size))
    }
}

impl Reader for BufferedReader {
    fn read_multi_buffer(&mut self) -> io::Result<MultiBuffer> {
        if !self.buf.is_empty() {
            return Ok(std::mem::replace(&mut self.buf, MultiBuffer::new()));
        }
        self.reader.read_multi_buffer()
    }
}

impl Read for BufferedReader {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        let n = self.buf.read_into(data);
        if n > 0 {
            return Ok(n);
        }
        let mb = self.reader.read_multi_buffer()?;
        if mb.is_empty() {
            return Ok(0);
        }
        self.buf = mb;
        Ok(self.buf.read_into(data))
    }
}
