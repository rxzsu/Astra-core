use std::io::{self, Read, Write};

use astra_core_buf::{Buffer, MultiBuffer, Writer as BufWriter};

use crate::cipher::StreamCipher;

pub struct CryptionReader {
    stream: Box<dyn StreamCipher>,
    reader: Box<dyn Read>,
}

impl CryptionReader {
    pub fn new(stream: Box<dyn StreamCipher>, reader: Box<dyn Read>) -> Self {
        CryptionReader { stream, reader }
    }
}

impl Read for CryptionReader {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        let n = self.reader.read(data)?;
        if n > 0 {
            let buf = data[..n].to_vec();
            self.stream.xor_key_stream(&mut data[..n], &buf);
        }
        Ok(n)
    }
}

pub struct CryptionWriter {
    stream: Box<dyn StreamCipher>,
    buf_writer: Box<dyn BufWriter>,
}

impl CryptionWriter {
    pub fn new(stream: Box<dyn StreamCipher>, writer: Box<dyn BufWriter + 'static>) -> Self {
        CryptionWriter {
            stream,
            buf_writer: writer,
        }
    }
}

impl Write for CryptionWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut encrypted = vec![0u8; data.len()];
        self.stream.xor_key_stream(&mut encrypted, data);
        let mut mb = MultiBuffer::new();
        mb.push_back(Buffer::from_slice(&encrypted));
        self.buf_writer.write_multi_buffer(mb)?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl BufWriter for CryptionWriter {
    fn write_multi_buffer(&mut self, mb: MultiBuffer) -> io::Result<()> {
        let mut encrypted = MultiBuffer::new();
        for buf in mb {
            let data = buf.slice();
            let mut enc = data.to_vec();
            self.stream.xor_key_stream(&mut enc, data);
            encrypted.push_back(Buffer::from_slice(&enc));
        }
        self.buf_writer.write_multi_buffer(encrypted)
    }
}
