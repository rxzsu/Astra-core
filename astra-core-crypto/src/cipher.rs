pub trait StreamCipher: Send {
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]);
}

pub trait AeadCipher: Send {
    fn nonce_size(&self) -> usize;
    fn overhead(&self) -> usize;
    fn open_with_nonce(
        &self,
        dst: &mut Vec<u8>,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, String>;
    fn seal_with_nonce(
        &self,
        dst: &mut Vec<u8>,
        plaintext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, String>;
}

pub struct NoopStreamCipher;

impl StreamCipher for NoopStreamCipher {
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) {
        dst.copy_from_slice(src);
    }
}

pub struct NoopAeadCipher;

impl AeadCipher for NoopAeadCipher {
    fn nonce_size(&self) -> usize {
        0
    }
    fn overhead(&self) -> usize {
        0
    }
    fn open_with_nonce(
        &self,
        _dst: &mut Vec<u8>,
        ciphertext: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        Ok(ciphertext.to_vec())
    }
    fn seal_with_nonce(
        &self,
        _dst: &mut Vec<u8>,
        plaintext: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        Ok(plaintext.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop_stream() {
        let mut cipher = NoopStreamCipher;
        let mut dst = [0u8; 5];
        cipher.xor_key_stream(&mut dst, b"hello");
        assert_eq!(&dst, b"hello");
    }

    #[test]
    fn test_noop_aead() {
        let cipher = NoopAeadCipher;
        let result = cipher
            .open_with_nonce(&mut vec![], b"data", b"nonce", b"aad")
            .unwrap();
        assert_eq!(result, b"data");
    }
}
