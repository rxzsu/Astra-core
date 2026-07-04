use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::cipher::{KeyIvInit, StreamCipher as CipherStream};
use aes::Aes128;
use aes_gcm::aead::{AeadInPlace, Nonce};

use crate::cipher::{AeadCipher, StreamCipher};

pub struct AesCipher {
    cipher: Aes128,
}

impl AesCipher {
    pub fn new(key: &[u8]) -> Self {
        assert!(key.len() == 16 || key.len() == 24 || key.len() == 32);
        AesCipher {
            cipher: Aes128::new_from_slice(&key[..16]).expect("AES-128 key"),
        }
    }

    pub fn encrypt(&self, block: &mut [u8; 16]) {
        self.cipher.encrypt_block(block.into());
    }

    pub fn decrypt(&self, block: &mut [u8; 16]) {
        self.cipher.decrypt_block(block.into());
    }
}

enum CfbMode {
    Encrypt,
    Decrypt,
}

pub struct AesCfbStream {
    cipher: Aes128,
    shift: [u8; 16],
    mode: CfbMode,
    offset: usize,
}

impl AesCfbStream {
    pub fn new_encrypt(key: &[u8], iv: &[u8; 16]) -> Self {
        AesCfbStream {
            cipher: Aes128::new_from_slice(&key[..16]).expect("AES-128 key"),
            shift: *iv,
            mode: CfbMode::Encrypt,
            offset: 0,
        }
    }

    pub fn new_decrypt(key: &[u8], iv: &[u8; 16]) -> Self {
        AesCfbStream {
            cipher: Aes128::new_from_slice(&key[..16]).expect("AES-128 key"),
            shift: *iv,
            mode: CfbMode::Decrypt,
            offset: 0,
        }
    }
}

impl StreamCipher for AesCfbStream {
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        let mut i = 0;
        while i < src.len() {
            if self.offset == 16 {
                self.offset = 0;
            }
            if self.offset == 0 {
                self.cipher.encrypt_block((&mut self.shift).into());
            }
            let n = (16 - self.offset).min(src.len() - i);
            for j in 0..n {
                dst[i + j] = src[i + j] ^ self.shift[self.offset + j];
            }
            match self.mode {
                CfbMode::Encrypt => {
                    for j in 0..n {
                        self.shift[self.offset + j] = dst[i + j];
                    }
                }
                CfbMode::Decrypt => {
                    for j in 0..n {
                        self.shift[self.offset + j] = src[i + j];
                    }
                }
            }
            self.offset += n;
            i += n;
        }
    }
}

pub struct AesCtrStream {
    cipher: ctr::Ctr128BE<Aes128>,
}

impl AesCtrStream {
    pub fn new(key: &[u8], nonce: &[u8; 16]) -> Self {
        AesCtrStream {
            cipher: ctr::Ctr128BE::<Aes128>::new_from_slices(key, nonce)
                .expect("AES-CTR key/iv"),
        }
    }
}

impl StreamCipher for AesCtrStream {
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        dst.copy_from_slice(src);
        self.cipher.apply_keystream(dst);
    }
}

pub struct AesGcmCipher {
    cipher: aes_gcm::Aes128Gcm,
}

impl AesGcmCipher {
    pub fn new(key: &[u8]) -> Self {
        AesGcmCipher {
            cipher: aes_gcm::Aes128Gcm::new_from_slice(&key[..16])
                .expect("AES-128-GCM key"),
        }
    }
}

impl AeadCipher for AesGcmCipher {
    fn nonce_size(&self) -> usize {
        12
    }

    fn overhead(&self) -> usize {
        16
    }

    fn open_with_nonce(
        &self,
        _dst: &mut Vec<u8>,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        if nonce.len() != 12 {
            return Err("GCM nonce must be 12 bytes".to_string());
        }
        let nonce = Nonce::<aes_gcm::Aes128Gcm>::from_slice(nonce);
        let mut buf = ciphertext.to_vec();
        self.cipher
            .decrypt_in_place(nonce, aad, &mut buf)
            .map_err(|e| format!("GCM decrypt: {}", e))?;
        Ok(buf)
    }

    fn seal_with_nonce(
        &self,
        _dst: &mut Vec<u8>,
        plaintext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        if nonce.len() != 12 {
            return Err("GCM nonce must be 12 bytes".to_string());
        }
        let nonce = Nonce::<aes_gcm::Aes128Gcm>::from_slice(nonce);
        let mut buf = plaintext.to_vec();
        self.cipher
            .encrypt_in_place(nonce, aad, &mut buf)
            .map_err(|e| format!("GCM encrypt: {}", e))?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_128_encrypt_decrypt() {
        let key = [0x00u8; 16];
        let cipher = AesCipher::new(&key);
        let mut block = [0x00u8; 16];
        cipher.encrypt(&mut block);
        assert_ne!(block, [0u8; 16]);
        let mut dec = block;
        cipher.decrypt(&mut dec);
        assert_eq!(dec, [0u8; 16]);
    }

    #[test]
    fn test_aes_cfb_roundtrip() {
        let key = [0x00u8; 16];
        let iv = [0x00u8; 16];
        let plaintext = b"Hello, AES-CFB!";
        let mut enc = AesCfbStream::new_encrypt(&key, &iv);
        let mut ct = vec![0u8; plaintext.len()];
        enc.xor_key_stream(&mut ct, plaintext);
        assert_ne!(&ct, plaintext);
        let mut dec = AesCfbStream::new_decrypt(&key, &iv);
        let mut pt2 = vec![0u8; plaintext.len()];
        dec.xor_key_stream(&mut pt2, &ct);
        assert_eq!(&pt2, plaintext);
    }

    #[test]
    fn test_aes_ctr_roundtrip() {
        let key = [0x00u8; 16];
        let nonce = [0x00u8; 16];
        let plaintext = b"Hello, AES-CTR!";
        let mut enc = AesCtrStream::new(&key, &nonce);
        let mut ct = vec![0u8; plaintext.len()];
        enc.xor_key_stream(&mut ct, plaintext);
        assert_ne!(&ct, plaintext);
        let mut dec = AesCtrStream::new(&key, &nonce);
        let mut pt2 = vec![0u8; plaintext.len()];
        dec.xor_key_stream(&mut pt2, &ct);
        assert_eq!(&pt2, plaintext);
    }
}
