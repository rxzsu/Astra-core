use std::cell::RefCell;
use std::io::{self, Read};

use astra_core_buf::{Buffer, BufferedReader, MultiBuffer, Reader as BufReader, Writer as BufWriter};

use crate::auth::Authenticator;

pub trait ChunkSizeDecoder: Send {
    fn size_bytes(&self) -> i32;
    fn decode(&self, b: &[u8]) -> io::Result<u16>;
}

pub trait ChunkSizeEncoder: Send {
    fn size_bytes(&self) -> i32;
    fn encode<'a>(&self, size: u16, b: &'a mut [u8]) -> &'a [u8];
}

pub trait PaddingLengthGenerator: Send {
    fn max_padding_len(&self) -> u16;
    fn next_padding_len(&mut self) -> u16;
}

pub struct PlainChunkSizeParser;

impl ChunkSizeDecoder for PlainChunkSizeParser {
    fn size_bytes(&self) -> i32 {
        2
    }
    fn decode(&self, b: &[u8]) -> io::Result<u16> {
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
}

impl ChunkSizeEncoder for PlainChunkSizeParser {
    fn size_bytes(&self) -> i32 {
        2
    }
    fn encode<'a>(&self, size: u16, b: &'a mut [u8]) -> &'a [u8] {
        let bytes = size.to_be_bytes();
        b[..2].copy_from_slice(&bytes);
        &b[..2]
    }
}

pub struct AeadChunkSizeParser {
    auth: RefCell<Box<dyn Authenticator>>,
}

impl AeadChunkSizeParser {
    pub fn new(auth: Box<dyn Authenticator>) -> Self {
        AeadChunkSizeParser {
            auth: RefCell::new(auth),
        }
    }
}

impl ChunkSizeDecoder for AeadChunkSizeParser {
    fn size_bytes(&self) -> i32 {
        2 + self.auth.borrow().overhead() as i32
    }
    fn decode(&self, b: &[u8]) -> io::Result<u16> {
        let mut auth = self.auth.borrow_mut();
        let mut tmp = Vec::new();
        let decrypted = auth
            .open(&mut tmp, b)
            .map_err(io::Error::other)?;
        let size = u16::from_be_bytes([decrypted[0], decrypted[1]]);
        Ok(size + auth.overhead() as u16)
    }
}

impl ChunkSizeEncoder for AeadChunkSizeParser {
    fn size_bytes(&self) -> i32 {
        2 + self.auth.borrow().overhead() as i32
    }
    fn encode<'a>(&self, size: u16, b: &'a mut [u8]) -> &'a [u8] {
        let raw_size = size - self.auth.borrow().overhead() as u16;
        b[..2].copy_from_slice(&raw_size.to_be_bytes());
        let mut tmp = Vec::new();
        let sealed = self
            .auth
            .borrow_mut()
            .seal(&mut tmp, &b[..2])
            .expect("AEAD seal failed in chunk parser");
        let n = sealed.len().min(b.len());
        b[..n].copy_from_slice(&sealed[..n]);
        &b[..n]
    }
}

pub struct ChunkStreamReader {
    size_decoder: Box<dyn ChunkSizeDecoder>,
    reader: BufferedReader,
    buffer: Vec<u8>,
    leftover_size: i32,
    max_chunk: u32,
    num_chunk: u32,
}

impl ChunkStreamReader {
    pub fn new(
        size_decoder: Box<dyn ChunkSizeDecoder>,
        reader: impl BufReader + 'static,
    ) -> Self {
        ChunkStreamReader::with_chunk_count(size_decoder, reader, 0)
    }

    pub fn with_chunk_count(
        size_decoder: Box<dyn ChunkSizeDecoder>,
        reader: impl BufReader + 'static,
        max_chunk: u32,
    ) -> Self {
        let buffer = vec![0u8; size_decoder.size_bytes() as usize];
        ChunkStreamReader {
            size_decoder,
            reader: BufferedReader::new(reader),
            buffer,
            leftover_size: 0,
            max_chunk,
            num_chunk: 0,
        }
    }

    fn read_size(&mut self) -> io::Result<u16> {
        self.reader.read_exact(&mut self.buffer)?;
        self.size_decoder.decode(&self.buffer)
    }

    pub fn read_multi_buffer(&mut self) -> io::Result<MultiBuffer> {
        let size = if self.leftover_size == 0 {
            self.num_chunk += 1;
            if self.max_chunk > 0 && self.num_chunk > self.max_chunk {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "max chunk count reached"));
            }
            let next_size = self.read_size()?;
            if next_size == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "zero size chunk"));
            }
            next_size as i32
        } else {
            self.leftover_size
        };
        self.leftover_size = size;
        let mb = self.reader.read_at_most(size as usize)?;
        if !mb.is_empty() {
            self.leftover_size -= mb.len() as i32;
            return Ok(mb);
        }
        Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no data"))
    }
}

pub struct ChunkStreamWriter {
    size_encoder: Box<dyn ChunkSizeEncoder>,
    writer: Box<dyn BufWriter>,
}

impl ChunkStreamWriter {
    pub fn new(
        size_encoder: Box<dyn ChunkSizeEncoder>,
        writer: impl BufWriter + 'static,
    ) -> Self {
        ChunkStreamWriter {
            size_encoder,
            writer: Box::new(writer),
        }
    }

    pub fn write_multi_buffer(&mut self, mb: MultiBuffer) -> io::Result<()> {
        const SLICE_SIZE: usize = 8192;
        let mut remaining = mb;
        let mut mb2_write = MultiBuffer::new();

        loop {
            let chunk = remaining.cut_front(SLICE_SIZE);
            if chunk.is_empty() {
                break;
            }
            let mut b = Buffer::new();
            let size_bytes = self.size_encoder.size_bytes() as usize;
            let encoded = b.extend(size_bytes);
            self.size_encoder.encode(chunk.len() as u16, encoded);
            mb2_write.push_back(b);
            for buf in chunk {
                mb2_write.push_back(buf);
            }
        }

        self.writer.write_multi_buffer(mb2_write)
    }
}
