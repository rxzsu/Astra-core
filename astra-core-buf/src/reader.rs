use std::io::{self, Read};

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
