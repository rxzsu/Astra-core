use chacha20::cipher::{KeyIvInit, StreamCipher as ChaChaStream};

use crate::cipher::StreamCipher;

enum ChaChaInner {
    Ietf(chacha20::ChaCha20),
    Legacy(chacha20::ChaCha20Legacy),
}

pub struct ChaCha20Stream {
    inner: ChaChaInner,
}

impl ChaCha20Stream {
    pub fn new(key: &[u8; 32], nonce: &[u8]) -> Self {
        let inner = match nonce.len() {
            8 => ChaChaInner::Legacy(
                chacha20::ChaCha20Legacy::new_from_slices(key, &nonce[..8])
                    .expect("ChaCha20 key/8-nonce"),
            ),
            12 => ChaChaInner::Ietf(
                chacha20::ChaCha20::new_from_slices(key, &nonce[..12])
                    .expect("ChaCha20 key/12-nonce"),
            ),
            _ => panic!("ChaCha20 nonce must be 8 or 12 bytes"),
        };
        ChaCha20Stream { inner }
    }
}

impl StreamCipher for ChaCha20Stream {
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        dst.copy_from_slice(src);
        match &mut self.inner {
            ChaChaInner::Ietf(c) => c.apply_keystream(dst),
            ChaChaInner::Legacy(c) => c.apply_keystream(dst),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_xor() {
        let key = [0x00u8; 32];
        let nonce = [0x00u8; 8];
        let mut stream = ChaCha20Stream::new(&key, &nonce);
        let mut dst = vec![0u8; 64];
        let src = vec![0u8; 64];
        stream.xor_key_stream(&mut dst, &src);
        assert_ne!(dst, src);
    }

    #[test]
    fn test_chacha20_ietf_nonce() {
        let key = [0x00u8; 32];
        let nonce = [0x00u8; 12];
        let mut stream = ChaCha20Stream::new(&key, &nonce);
        let mut dst = vec![0u8; 64];
        let src = vec![0u8; 64];
        stream.xor_key_stream(&mut dst, &src);
        assert_ne!(dst, src);
    }
}
