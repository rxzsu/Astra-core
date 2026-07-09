use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use bytes::{BufMut, BytesMut};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use hkdf::Hkdf;
use md5::{Digest, Md5};
use sha1::Sha1;
use tokio::io::{AsyncRead, ReadBuf};

use astra_core_net::{Address, Destination, PortFromBytes};

pub const MAX_CHUNK_SIZE: usize = 0x3FFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherType {
    Aes128Gcm = 0,
    Aes256Gcm = 1,
    Chacha20Poly1305 = 2,
    XChacha20Poly1305 = 3,
    None = 4,
}

impl CipherType {
    pub fn key_size(self) -> usize {
        match self {
            CipherType::Aes128Gcm => 16,
            CipherType::Aes256Gcm => 32,
            CipherType::Chacha20Poly1305 => 32,
            CipherType::XChacha20Poly1305 => 32,
            CipherType::None => 0,
        }
    }

    pub fn iv_size(self) -> usize {
        self.key_size()
    }

    pub fn nonce_size(self) -> usize {
        match self {
            CipherType::Aes128Gcm => 12,
            CipherType::Aes256Gcm => 12,
            CipherType::Chacha20Poly1305 => 12,
            CipherType::XChacha20Poly1305 => 24,
            CipherType::None => 0,
        }
    }

    pub fn tag_size(self) -> usize {
        16
    }

    pub fn is_aead(self) -> bool {
        !matches!(self, CipherType::None)
    }
}

impl From<u8> for CipherType {
    fn from(v: u8) -> Self {
        match v {
            0 => CipherType::Aes128Gcm,
            1 => CipherType::Aes256Gcm,
            2 => CipherType::Chacha20Poly1305,
            3 => CipherType::XChacha20Poly1305,
            _ => CipherType::None,
        }
    }
}

impl From<CipherType> for u8 {
    fn from(t: CipherType) -> u8 {
        t as u8
    }
}

pub fn password_to_key(password: &[u8], key_size: usize) -> Vec<u8> {
    let mut key = Vec::new();
    let mut md5_sum = Md5::digest(password);
    key.extend_from_slice(&md5_sum);
    while key.len() < key_size {
        let mut hasher = Md5::new();
        hasher.update(md5_sum);
        hasher.update(password);
        md5_sum = hasher.finalize();
        key.extend_from_slice(&md5_sum);
    }
    key.truncate(key_size);
    key
}

pub fn hkdf_sha1(secret: &[u8], salt: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha1>::new(Some(salt), secret);
    let mut okm = vec![0u8; out_len];
    hk.expand(b"ss-subkey", &mut okm).unwrap();
    okm
}

pub enum AeadCipher {
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
    XChaCha20Poly1305(XChaCha20Poly1305),
}

impl AeadCipher {
    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            AeadCipher::Aes128Gcm(c) => {
                let n = GenericArray::from_slice(nonce);
                c.encrypt(
                    n,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|e| e.to_string())
            }
            AeadCipher::Aes256Gcm(c) => {
                let n = GenericArray::from_slice(nonce);
                c.encrypt(
                    n,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|e| e.to_string())
            }
            AeadCipher::ChaCha20Poly1305(c) => {
                let n = GenericArray::from_slice(nonce);
                c.encrypt(
                    n,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|e| e.to_string())
            }
            AeadCipher::XChaCha20Poly1305(c) => {
                let n = GenericArray::from_slice(nonce);
                c.encrypt(
                    n,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|e| e.to_string())
            }
        }
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            AeadCipher::Aes128Gcm(c) => {
                let n = GenericArray::from_slice(nonce);
                c.decrypt(
                    n,
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|e| e.to_string())
            }
            AeadCipher::Aes256Gcm(c) => {
                let n = GenericArray::from_slice(nonce);
                c.decrypt(
                    n,
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|e| e.to_string())
            }
            AeadCipher::ChaCha20Poly1305(c) => {
                let n = GenericArray::from_slice(nonce);
                c.decrypt(
                    n,
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|e| e.to_string())
            }
            AeadCipher::XChaCha20Poly1305(c) => {
                let n = GenericArray::from_slice(nonce);
                c.decrypt(
                    n,
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|e| e.to_string())
            }
        }
    }
}

pub fn create_aead(cipher_type: CipherType, key: &[u8]) -> Result<AeadCipher, String> {
    match cipher_type {
        CipherType::Aes128Gcm => Ok(AeadCipher::Aes128Gcm(
            Aes128Gcm::new_from_slice(key).map_err(|e| e.to_string())?,
        )),
        CipherType::Aes256Gcm => Ok(AeadCipher::Aes256Gcm(
            Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?,
        )),
        CipherType::Chacha20Poly1305 => Ok(AeadCipher::ChaCha20Poly1305(
            ChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?,
        )),
        CipherType::XChacha20Poly1305 => Ok(AeadCipher::XChaCha20Poly1305(
            XChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?,
        )),
        CipherType::None => Err("no aead for none cipher".into()),
    }
}

pub fn create_authenticator(
    cipher_type: CipherType,
    key: &[u8],
    iv: &[u8],
) -> (AeadCipher, Vec<u8>) {
    let subkey = hkdf_sha1(key, iv, cipher_type.key_size());
    let cipher = create_aead(cipher_type, &subkey).expect("create aead");
    let nonce_seed = vec![0u8; cipher_type.nonce_size()];
    (cipher, nonce_seed)
}

pub fn aead_chunk_encrypt(
    cipher: &AeadCipher,
    nonce: &[u8],
    plaintext: &[u8],
    size_bytes: &[u8],
) -> Vec<u8> {
    cipher
        .encrypt(nonce, plaintext, size_bytes)
        .expect("encrypt chunk")
}

pub fn aead_chunk_decrypt(
    cipher: &AeadCipher,
    nonce: &[u8],
    ciphertext: &[u8],
    size_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    cipher.decrypt(nonce, ciphertext, size_bytes)
}

fn next_nonce(nonce: &mut [u8]) {
    for b in nonce.iter_mut().rev() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
}

pub fn write_address(buf: &mut BytesMut, addr: &Address) {
    match addr {
        Address::Ipv4(octets) => {
            buf.put_u8(0x01);
            buf.put_slice(octets);
        }
        Address::Ipv6(octets) => {
            buf.put_u8(0x04);
            buf.put_slice(octets);
        }
        Address::Domain(domain) => {
            buf.put_u8(0x03);
            let len = domain.len();
            assert!(len <= 255, "domain too long");
            buf.put_u8(len as u8);
            buf.put_slice(domain.as_bytes());
        }
    }
}

pub fn read_address(data: &[u8]) -> Result<(Destination, usize), String> {
    if data.is_empty() {
        return Err("empty address data".into());
    }
    let atype = data[0];
    let mut offset = 1;

    let address = match atype {
        0x01 => {
            if data.len() < offset + 4 {
                return Err("short ipv4 address".into());
            }
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&data[offset..offset + 4]);
            offset += 4;
            Address::Ipv4(octets)
        }
        0x04 => {
            if data.len() < offset + 16 {
                return Err("short ipv6 address".into());
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[offset..offset + 16]);
            offset += 16;
            Address::Ipv6(octets)
        }
        0x03 => {
            if data.len() < offset + 1 {
                return Err("short domain length".into());
            }
            let dlen = data[offset] as usize;
            offset += 1;
            if data.len() < offset + dlen {
                return Err("short domain data".into());
            }
            let domain =
                std::str::from_utf8(&data[offset..offset + dlen]).map_err(|_| "invalid domain")?;
            offset += dlen;
            Address::Domain(domain.to_owned())
        }
        _ => return Err(format!("unknown address type: {}", atype)),
    };

    if data.len() < offset + 2 {
        return Err("short port".into());
    }
    let port = PortFromBytes(&data[offset..offset + 2]);
    offset += 2;

    Ok((
        Destination {
            address,
            port,
            network: astra_core_net::Network::Tcp,
        },
        offset,
    ))
}

pub trait Cipher {
    fn key_size(&self) -> usize;
    fn iv_size(&self) -> usize;
    fn is_aead(&self) -> bool;
    fn encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8>;
    fn decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String>;
}

impl Cipher for CipherType {
    fn key_size(&self) -> usize {
        (*self).key_size()
    }

    fn iv_size(&self) -> usize {
        (*self).iv_size()
    }

    fn is_aead(&self) -> bool {
        (*self).is_aead()
    }

    fn encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let subkey = hkdf_sha1(key, iv, self.key_size());
        let cipher = create_aead(*self, &subkey).expect("create aead");
        let nonce = vec![0u8; self.nonce_size()];
        cipher.encrypt(&nonce, plaintext, b"").expect("encrypt")
    }

    fn decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let subkey = hkdf_sha1(key, iv, self.key_size());
        let cipher = create_aead(*self, &subkey)?;
        let nonce = vec![0u8; self.nonce_size()];
        cipher.decrypt(&nonce, ciphertext, b"")
    }
}

pub struct SessionCipher {
    pub cipher_type: CipherType,
    pub cipher: AeadCipher,
    pub nonce: Vec<u8>,
}

impl SessionCipher {
    pub fn new(cipher_type: CipherType, key: &[u8], iv: &[u8]) -> Self {
        let (cipher, nonce_seed) = create_authenticator(cipher_type, key, iv);
        SessionCipher {
            cipher_type,
            cipher,
            nonce: nonce_seed,
        }
    }

    pub fn encrypt_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        const TAG_SIZE: usize = 16;
        let total_len = self.nonce.len() + plaintext.len() + TAG_SIZE;
        let size_bytes = (total_len as u16).to_be_bytes();
        let ct = self.cipher.encrypt(&self.nonce, plaintext, &size_bytes)?;
        let mut out = Vec::with_capacity(2 + total_len);
        out.extend_from_slice(&size_bytes);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&ct);
        next_nonce(&mut self.nonce);
        Ok(out)
    }

    pub fn decrypt_chunk(
        &mut self,
        ciphertext: &[u8],
        size_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        let pt = self.cipher.decrypt(&self.nonce, ciphertext, size_bytes)?;
        next_nonce(&mut self.nonce);
        Ok(pt)
    }

    pub fn encrypt_first_chunk(&mut self, addr: &Address, port: u16) -> Result<Vec<u8>, String> {
        let mut addr_buf = BytesMut::new();
        write_address(&mut addr_buf, addr);
        addr_buf.put_u16(port);
        self.encrypt_chunk(&addr_buf)
    }

    pub fn decrypt_first_chunk(
        &mut self,
        data: &[u8],
        size_bytes: &[u8],
    ) -> Result<Destination, String> {
        let pt = self.decrypt_chunk(data, size_bytes)?;
        let (dest, _) = read_address(&pt)?;
        Ok(dest)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadStage {
    Size,
    Payload { total_len: usize, read: usize },
}

pub struct DecryptingReader<R> {
    inner: R,
    cipher_type: CipherType,
    cipher: AeadCipher,
    nonce: Vec<u8>,
    output: VecDeque<u8>,
    stage: ReadStage,
    size_buf: [u8; 2],
    size_pos: usize,
    payload_buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin + Send> AsyncRead for DecryptingReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        loop {
            if !this.output.is_empty() {
                let n = dst.remaining().min(this.output.len());
                for b in this.output.drain(..n) {
                    dst.put_slice(&[b]);
                }
                return Poll::Ready(Ok(()));
            }

            match this.stage {
                ReadStage::Size => {
                    let mut buf = ReadBuf::new(&mut this.size_buf[this.size_pos..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            this.size_pos += buf.filled().len();
                            if this.size_pos < 2 {
                                continue;
                            }
                            this.size_pos = 0;
                            let total_len = u16::from_be_bytes(this.size_buf) as usize;
                            if total_len == 0 {
                                return Poll::Ready(Ok(()));
                            }
                            this.payload_buf = vec![0u8; total_len];
                            this.stage = ReadStage::Payload { total_len, read: 0 };
                        }
                    }
                }
                ReadStage::Payload { total_len, read } => {
                    let mut buf = ReadBuf::new(&mut this.payload_buf[read..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let new_read = read + buf.filled().len();
                            if new_read < total_len {
                                this.stage = ReadStage::Payload {
                                    total_len,
                                    read: new_read,
                                };
                                continue;
                            }
                            let nonce_size = this.cipher_type.nonce_size();
                            let ct = &this.payload_buf[nonce_size..];
                            match this.cipher.decrypt(
                                &this.payload_buf[..nonce_size],
                                ct,
                                &this.size_buf,
                            ) {
                                Ok(pt) => {
                                    this.output.extend(pt);
                                    next_nonce(&mut this.nonce);
                                    this.stage = ReadStage::Size;
                                }
                                Err(e) => {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        e,
                                    )));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

pub async fn read_tcp_session<R: AsyncRead + Unpin + Send + 'static>(
    reader: R,
    cipher_type: CipherType,
    key: &[u8],
    iv: &[u8],
) -> Result<(Destination, Box<dyn AsyncRead + Unpin + Send>), String> {
    use tokio::io::AsyncReadExt;

    let mut reader = reader;
    let (cipher, mut nonce) = create_authenticator(cipher_type, key, iv);

    let mut size_buf = [0u8; 2];
    reader
        .read_exact(&mut size_buf)
        .await
        .map_err(|e| format!("read chunk size: {}", e))?;

    let total_len = u16::from_be_bytes(size_buf) as usize;
    let nonce_size = cipher_type.nonce_size();

    let mut chunk = vec![0u8; total_len];
    reader
        .read_exact(&mut chunk)
        .await
        .map_err(|e| format!("read chunk: {}", e))?;

    let n = &chunk[..nonce_size];
    let ct = &chunk[nonce_size..];

    let plaintext = cipher
        .decrypt(n, ct, &size_buf)
        .map_err(|e| format!("decrypt first chunk: {}", e))?;

    let (dest, _) = read_address(&plaintext)?;

    next_nonce(&mut nonce);

    let decrypting_reader = DecryptingReader {
        inner: reader,
        cipher_type,
        cipher,
        nonce,
        output: VecDeque::new(),
        stage: ReadStage::Size,
        size_buf: [0u8; 2],
        size_pos: 0,
        payload_buf: Vec::new(),
    };

    Ok((dest, Box::new(decrypting_reader)))
}
