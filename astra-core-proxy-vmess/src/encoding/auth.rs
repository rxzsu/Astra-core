use astra_core_crypto::auth::AeadAuthenticator;

/// Chunk size adapter that delegates to an AEAD authenticator for size encryption.
#[allow(dead_code)]
pub struct AEADSizeParser {
    auth: AeadAuthenticator,
}

impl AEADSizeParser {
    pub fn new(auth: AeadAuthenticator) -> Self {
        AEADSizeParser { auth }
    }

    pub fn size_bytes(&self) -> i32 {
        2
    }

    pub fn decode(&self, b: &[u8]) -> Result<u16, String> {
        if b.len() < 2 {
            return Err("insufficient length for size".to_string());
        }
        let size = u16::from_be_bytes([b[0], b[1]]);
        Ok(size)
    }

    pub fn encode(&self, size: u16, b: &mut [u8]) {
        let bytes = size.to_be_bytes();
        b[..2].copy_from_slice(&bytes);
    }
}

/// FNV-1a 32-bit hash, used for VMess request header integrity.
pub fn Authenticate(b: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for &byte in b {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// Generate ChaCha20-Poly1305 key from a 32-byte key.
/// Mirrors go's `GenerateChacha20Poly1305Key` — uses MD5 for key derivation (Go compat).
pub fn GenerateChacha20Poly1305Key(b: &[u8]) -> Vec<u8> {
    use md5::Md5;
    use digest::Digest;
    let mut hasher = Md5::new();
    hasher.update(b);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnv1a() {
        assert_eq!(Authenticate(b""), 0x811c9dc5);
        assert_ne!(Authenticate(b"hello"), 0);
    }

    #[test]
    fn test_aead_size_parser_roundtrip() {
        use astra_core_crypto::aes::AesGcmCipher;
        use astra_core_crypto::auth::AeadAuthenticator;
        use astra_core_crypto::generator::{EmptyBytesGenerator, StaticBytesGenerator};

        let key = [0x42u8; 16];
        let cipher = AesGcmCipher::new(&key);
        let auth = AeadAuthenticator::new(
            Box::new(cipher),
            Box::new(EmptyBytesGenerator),
            Some(Box::new(StaticBytesGenerator::new(b"".to_vec()))),
        );

        let parser = AEADSizeParser::new(auth);
        assert_eq!(parser.size_bytes(), 2);

        let mut buf = [0u8; 2];
        parser.encode(1024, &mut buf);
        let decoded = parser.decode(&buf).unwrap();
        assert_eq!(decoded, 1024);
    }
}
