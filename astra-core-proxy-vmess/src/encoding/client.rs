use astra_core_crypto::aes::{AesCfbStream, AesGcmCipher};
use astra_core_crypto::cipher::{AeadCipher, StreamCipher};
use astra_core_crypto::sha256::Sha256;
use astra_core_proto::{RequestCommand, RequestHeader, SecurityType};

use crate::aead::encrypt::SealVMessAEADHeader;
use crate::aead::kdf::{KDF, KDF16};
use crate::aead::consts::*;
use crate::encoding::auth::Authenticate;

/// Client session for encoding VMess requests and decoding responses.
/// Mirrors go's `proxy/vmess/encoding.ClientSession`.
pub struct ClientSession {
    pub request_body_key: [u8; 16],
    pub request_body_iv: [u8; 16],
    pub response_body_key: [u8; 16],
    pub response_body_iv: [u8; 16],
    pub response_header: u8,
}

impl Default for ClientSession {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientSession {
    pub fn new() -> Self {
        let req_key = rand_16_bytes();
        let req_iv = rand_16_bytes();
        let resp_hdr = rand_1_byte();
        let resp_key = Sha256::hash(&req_key)[..16].try_into().unwrap();
        let resp_iv = Sha256::hash(&req_iv)[..16].try_into().unwrap();
        ClientSession {
            request_body_key: req_key,
            request_body_iv: req_iv,
            response_body_key: resp_key,
            response_body_iv: resp_iv,
            response_header: resp_hdr,
        }
    }

    /// Encode the VMess request header (AEAD-sealed).
    pub fn EncodeRequestHeader(&self, header: &RequestHeader, cmd_key: &[u8; 16]) -> Vec<u8> {
        // Build plaintext buffer
        let mut buf = Vec::with_capacity(38 + 32);
        buf.push(header.version);
        buf.extend_from_slice(&self.request_body_iv);
        buf.extend_from_slice(&self.request_body_key);
        buf.push(self.response_header);
        buf.push(header.option);
        let pad_len = rand_1_byte() & 0x0f;
        let security_byte = (pad_len << 4) | header.security.as_byte();
        buf.push(security_byte);
        buf.push(0x00); // reserved
        buf.push(header.command.as_byte());

        // Address + Port for non-Mux commands
        match header.command {
            RequestCommand::Tcp | RequestCommand::Udp => {
                buf.extend_from_slice(&header.port.value().to_be_bytes());
                encode_address(&header.address, &mut buf);
            }
            _ => {}
        }

        // Padding (random 0-15 bytes)
        for _ in 0..pad_len {
            buf.push(rand_1_byte());
        }

        // FNV-1a checksum
        let hash = Authenticate(&buf);
        buf.extend_from_slice(&hash.to_be_bytes());

        // AEAD seal
        SealVMessAEADHeader(cmd_key, &buf)
    }

    /// Create an encrypted body writer for the request.
    pub fn EncodeRequestBody(&self, request: &RequestHeader) -> EncryptionWriter {
        body_encrypt_writer(request.security, &self.request_body_key, &self.request_body_iv)
    }

    /// Decode the VMess response header.
    pub fn DecodeResponseHeader(&self, data: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>), String> {
        // Derive response body key/IV for payload decryption
        let resp_key = Sha256::hash(&self.request_body_key);
        let resp_iv = Sha256::hash(&self.request_body_iv);
        let rk: [u8; 16] = resp_key[..16].try_into().unwrap();
        let riv: [u8; 16] = resp_iv[..16].try_into().unwrap();

        // Length AEAD key/IV
        let len_key: [u8; 16] = KDF16(&rk, &[KDF_SALT_AEAD_RESP_HEADER_LEN_KEY]);
        let len_iv = &KDF(&riv, &[KDF_SALT_AEAD_RESP_HEADER_LEN_IV]);

        if data.len() < 18 {
            return Err("truncated response header".to_string());
        }
        let len_ct = &data[..18];
        let len_plain = aes_gcm_open(&len_key, &len_iv[..12], len_ct, &[])?;
        let payload_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;

        // Payload AEAD key/IV
        let payload_key: [u8; 16] = KDF16(&rk, &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY]);
        let payload_iv = &KDF(&riv, &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV]);

        if data.len() < 18 + payload_len + 16 {
            return Err("truncated response payload".to_string());
        }
        let payload_ct = &data[18..18 + payload_len + 16];
        let payload = aes_gcm_open(&payload_key, &payload_iv[..12], payload_ct, &[])?;

        Ok((payload, None))
    }

    /// Create a decrypted body reader for the response.
    pub fn DecodeResponseBody(&self) -> EncryptionReader {
        let rk: [u8; 16] = Sha256::hash(&self.request_body_key)[..16].try_into().unwrap();
        let riv: [u8; 16] = Sha256::hash(&self.request_body_iv)[..16].try_into().unwrap();
        EncryptionReader::new_aes_cfb(&rk, &riv)
    }
}

pub struct EncryptionWriter {
    pub buf: Vec<u8>,
}

impl EncryptionWriter {
    pub fn write(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
}

pub struct EncryptionReader {
    key: [u8; 16],
    iv: [u8; 16],
    buffer: Vec<u8>,
    offset: usize,
}

impl EncryptionReader {
    pub fn new_aes_cfb(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        EncryptionReader {
            key: *key,
            iv: *iv,
            buffer: Vec::new(),
            offset: 0,
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn read_decrypted(&mut self, out: &mut [u8]) -> Result<usize, String> {
        let avail = self.buffer.len() - self.offset;
        let to_read = out.len().min(avail);
        if to_read == 0 {
            return Ok(0);
        }

        let mut cfb = AesCfbStream::new_decrypt(&self.key, &self.iv);
        let chunk = &self.buffer[self.offset..self.offset + to_read];
        let mut tmp = chunk.to_vec();
        let src = tmp.clone();
        cfb.xor_key_stream(&mut tmp, &src);
        out[..to_read].copy_from_slice(&tmp);
        self.offset += to_read;
        Ok(to_read)
    }
}

// ── Helpers ────────────────────────────────────────────────────────

fn body_encrypt_writer(
    _security: SecurityType,
    _key: &[u8; 16],
    _iv: &[u8; 16],
) -> EncryptionWriter {
    EncryptionWriter { buf: Vec::new() }
}

fn encode_address(addr: &astra_core_net::Address, buf: &mut Vec<u8>) {
    match addr {
        astra_core_net::Address::Ipv4(o) => { buf.push(1); buf.extend_from_slice(o); }
        astra_core_net::Address::Domain(d) => { buf.push(2); buf.push(d.len() as u8); buf.extend_from_slice(d.as_bytes()); }
        astra_core_net::Address::Ipv6(o) => { buf.push(3); buf.extend_from_slice(o); }
    }
}

#[allow(dead_code)]
fn aes_gcm_seal(key: &[u8; 16], iv: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = AesGcmCipher::new(key);
    cipher
        .seal_with_nonce(&mut vec![], plaintext, iv, aad)
        .unwrap_or_else(|_| plaintext.to_vec())
}

fn aes_gcm_open(key: &[u8; 16], iv: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = AesGcmCipher::new(key);
    cipher.open_with_nonce(&mut vec![], ciphertext, iv, aad)
}

fn rand_16_bytes() -> [u8; 16] {
    let mut out = [0u8; 16];
    for b in out.iter_mut() {
        *b = rand_1_byte();
    }
    out
}

fn rand_1_byte() -> u8 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (seed ^ (seed >> 32)) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra_core_net::Port;

    #[test]
    fn test_client_session_new() {
        let cs = ClientSession::new();
        assert_eq!(cs.request_body_key.len(), 16);
        assert_eq!(cs.request_body_iv.len(), 16);
        assert_eq!(cs.response_body_key.len(), 16);
        assert_eq!(cs.response_body_iv.len(), 16);
    }

    #[test]
    fn test_encode_decode_request_header() {
        let cs = ClientSession::new();
        let cmd_key = [0x42u8; 16];
        let header = RequestHeader {
            version: 1,
            command: RequestCommand::Tcp,
            option: 0x01,
            security: SecurityType::Aes128Gcm,
            port: Port(443),
            address: astra_core_net::Address::Ipv4([10, 0, 0, 1]),
            user: None,
        };

        let encoded = cs.EncodeRequestHeader(&header, &cmd_key);
        assert!(encoded.len() > 42);
    }

    #[test]
    fn test_encryption_reader_writer() {
        let mut writer = EncryptionWriter { buf: Vec::new() };
        writer.write(b"hello");
        assert_eq!(writer.buf, b"hello");
    }
}
