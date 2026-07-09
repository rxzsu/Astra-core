use std::io::{self, Write};

use crate::buffer::Buffer;
use crate::io::Writer;
use crate::multi_buffer::MultiBuffer;

pub struct SequentialWriter {
    inner: Box<dyn Write>,
}

impl SequentialWriter {
    pub fn new(w: impl Write + 'static) -> Self {
        SequentialWriter { inner: Box::new(w) }
    }
}

impl Writer for SequentialWriter {
    fn write_multi_buffer(&mut self, mb: MultiBuffer) -> io::Result<()> {
        for buf in mb {
            let data = buf.slice();
            if !data.is_empty() {
                self.inner.write_all(data)?;
            }
        }
        Ok(())
    }
}

pub struct BufferedWriter {
    writer: Box<dyn Writer>,
    buffer: Buffer,
    buffered: bool,
}

impl BufferedWriter {
    pub fn new(writer: impl Writer + 'static) -> Self {
        BufferedWriter {
            writer: Box::new(writer),
            buffer: Buffer::new(),
            buffered: true,
        }
    }

    pub fn flush(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            let buf = std::mem::take(&mut self.buffer);
            self.writer
                .write_multi_buffer(MultiBuffer::with_buffer(buf))?;
        }
        Ok(())
    }
}

impl Writer for BufferedWriter {
    fn write_multi_buffer(&mut self, mb: MultiBuffer) -> io::Result<()> {
        if !self.buffered {
            return self.writer.write_multi_buffer(mb);
        }
        for buf in mb {
            let data = buf.slice().to_vec();
            let _ = self.buffer.write(&data);
            if self.buffer.available() < buf.len() {
                self.flush()?;
            }
        }
        Ok(())
    }
}

impl Write for BufferedWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buffer.write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush()
    }
}

impl Drop for BufferedWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

pub struct DiscardWriter;

impl Writer for DiscardWriter {
    fn write_multi_buffer(&mut self, _mb: MultiBuffer) -> io::Result<()> {
        Ok(())
    }
}

pub static DISCARD: DiscardWriter = DiscardWriter;
