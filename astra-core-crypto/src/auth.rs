use std::cell::RefCell;
use std::io::{self};

use astra_core_buf::{Buffer, BufferedReader, MultiBuffer, Reader as BufReader, SIZE};

use crate::chunk::ChunkSizeDecoder;
use crate::cipher::AeadCipher;
use crate::generator::BytesGenerator;

pub trait Authenticator: Send {
    fn nonce_size(&self) -> usize;
    fn overhead(&self) -> usize;
    fn open(&mut self, dst: &mut Vec<u8>, ciphertext: &[u8]) -> Result<Vec<u8>, String>;
    fn seal(&mut self, dst: &mut Vec<u8>, plaintext: &[u8]) -> Result<Vec<u8>, String>;
}

pub struct AeadAuthenticator {
    cipher: Box<dyn AeadCipher>,
    nonce_gen: RefCell<Box<dyn BytesGenerator>>,
    additional_data_gen: RefCell<Option<Box<dyn BytesGenerator>>>,
}

impl AeadAuthenticator {
    pub fn new(
        cipher: Box<dyn AeadCipher>,
        nonce_gen: Box<dyn BytesGenerator>,
        additional_data_gen: Option<Box<dyn BytesGenerator>>,
    ) -> Self {
        AeadAuthenticator {
            cipher,
            nonce_gen: RefCell::new(nonce_gen),
            additional_data_gen: RefCell::new(additional_data_gen),
        }
    }
}

impl Authenticator for AeadAuthenticator {
    fn nonce_size(&self) -> usize {
        self.cipher.nonce_size()
    }

    fn overhead(&self) -> usize {
        self.cipher.overhead()
    }

    fn open(&mut self, dst: &mut Vec<u8>, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let iv = self.nonce_gen.borrow_mut().generate();
        if iv.len() != self.cipher.nonce_size() {
            return Err(format!(
                "invalid AEAD nonce size: {} (expected {})",
                iv.len(),
                self.cipher.nonce_size()
            ));
        }
        let aad = self
            .additional_data_gen
            .borrow_mut()
            .as_mut()
            .map(|g| g.generate())
            .unwrap_or_default();
        self.cipher
            .open_with_nonce(dst, ciphertext, &iv, &aad)
    }

    fn seal(&mut self, dst: &mut Vec<u8>, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let iv = self.nonce_gen.borrow_mut().generate();
        if iv.len() != self.cipher.nonce_size() {
            return Err(format!(
                "invalid AEAD nonce size: {} (expected {})",
                iv.len(),
                self.cipher.nonce_size()
            ));
        }
        let aad = self
            .additional_data_gen
            .borrow_mut()
            .as_mut()
            .map(|g| g.generate())
            .unwrap_or_default();
        self.cipher
            .seal_with_nonce(dst, plaintext, &iv, &aad)
    }
}

pub struct AuthenticationReader {
    auth: Box<dyn Authenticator>,
    reader: BufferedReader,
    size_parser: Box<dyn ChunkSizeDecoder>,
    size_bytes: Vec<u8>,
    padding: Option<Box<dyn crate::chunk::PaddingLengthGenerator>>,
    cached_size: u16,
    cached_padding: u16,
    has_size: bool,
    done: bool,
}

impl AuthenticationReader {
    pub fn new(
        auth: Box<dyn Authenticator>,
        size_parser: Box<dyn ChunkSizeDecoder>,
        reader: impl BufReader + 'static,
        padding: Option<Box<dyn crate::chunk::PaddingLengthGenerator>>,
    ) -> Self {
        let size_bytes = vec![0u8; size_parser.size_bytes() as usize];
        AuthenticationReader {
            auth,
            reader: BufferedReader::new(reader),
            size_parser,
            size_bytes,
            padding,
            cached_size: 0,
            cached_padding: 0,
            has_size: false,
            done: false,
        }
    }

    fn read_size(&mut self) -> io::Result<(u16, u16)> {
        if self.has_size {
            self.has_size = false;
            return Ok((self.cached_size, self.cached_padding));
        }
        use std::io::Read;
        self.reader.read_exact(&mut self.size_bytes)?;
        let padding = self
            .padding
            .as_mut()
            .map(|p| p.next_padding_len())
            .unwrap_or(0);
        let size = self.size_parser.decode(&self.size_bytes)?;
        Ok((size, padding))
    }
}

impl BufReader for AuthenticationReader {
    fn read_multi_buffer(&mut self) -> io::Result<MultiBuffer> {
        const READ_SIZE: usize = 16;
        let mut mb = MultiBuffer::new();

        match self.read_internal(false, &mut mb) {
            Ok(_) => {}
            Err(e) => {
                mb.release_all();
                return Err(e);
            }
        }

        for _ in 1..READ_SIZE {
            match self.read_internal(true, &mut mb) {
                Ok(_) => {}
                Err(e) if e.to_string() == "waiting for more data" || e.kind() == io::ErrorKind::UnexpectedEof => {
                    break;
                }
                Err(e) => {
                    mb.release_all();
                    return Err(e);
                }
            }
        }

        Ok(mb)
    }
}

impl AuthenticationReader {
    const ERR_SOFT: &'static str = "waiting for more data";

    fn read_buffer(&mut self, size: usize, padding: usize) -> io::Result<Option<Buffer>> {
        let mut b = Buffer::new();
        use std::io::Read;
        let writable = b.writable_mut();
        let mut read = 0;
        while read < size {
            let n = self.reader.read(&mut writable[read..size])?;
            if n == 0 {
                break;
            }
            read += n;
        }
        if read < size {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "not enough data"));
        }
        b.set_end(size);
        let actual_size = size - padding;
        let mut tmp = Vec::new();
        let rb = self
            .auth
            .open(&mut tmp, &b.slice()[..actual_size])
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        b.extend(rb.len());
        let n = rb.len().min(b.writable_mut().len());
        b.writable_mut()[..n].copy_from_slice(&rb[..n]);
        b.set_end(n);
        Ok(Some(b))
    }

    fn read_internal(&mut self, soft: bool, mb: &mut MultiBuffer) -> io::Result<()> {
        if soft && self.reader.buffered_bytes() < self.size_parser.size_bytes() as usize {
            return Err(io::Error::new(io::ErrorKind::Other, Self::ERR_SOFT));
        }

        if self.done {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
        }

        let (size, padding) = self.read_size()?;

        if size as usize == self.auth.overhead() + padding as usize {
            self.done = true;
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
        }

        if soft && (size as usize) > self.reader.buffered_bytes() {
            self.cached_size = size;
            self.cached_padding = padding;
            self.has_size = true;
            return Err(io::Error::new(io::ErrorKind::Other, Self::ERR_SOFT));
        }

        if size <= SIZE as u16 {
            let b = self.read_buffer(size as usize, padding as usize)?;
            if let Some(buf) = b {
                mb.push_back(buf);
            }
            return Ok(());
        }

        let payload_size = size as usize;
        let mut payload = vec![0u8; payload_size];
        use std::io::Read;
        self.reader.read_exact(&mut payload)?;

        let actual_size = size as usize - padding as usize;
        let mut tmp = Vec::new();
        let rb = self
            .auth
            .open(&mut tmp, &payload[..actual_size])
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let buf = Buffer::from_slice(&rb);
        mb.push_back(buf);
        Ok(())
    }
}
