use astra_core_crypto::sha256::hmac_sha256;

use crate::aead::consts::KDF_SALT_VMESS_AEAD_KDF;

/// VMess AEAD KDF: chain of HMAC-SHA256 operations.
/// Mirrors go's `proxy/vmess/aead.KDF`.
pub fn KDF(key: &[u8], path: &[&[u8]]) -> Vec<u8> {
    // Base: HMAC-SHA256(key, "VMess AEAD KDF")
    let mut result = hmac_sha256(key, KDF_SALT_VMESS_AEAD_KDF);

    // For each path segment: HMAC-SHA256(result, segment)
    for segment in path {
        result = hmac_sha256(&result, segment);
    }

    // HMAC-SHA256(result, key) — final mix with original key
    hmac_sha256(&result, key).to_vec()
}

/// KDF16: like KDF but returns only first 16 bytes.
pub fn KDF16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let full = KDF(key, path);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_empty_path() {
        let key = b"test-key";
        let result = KDF(key, &[]);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_kdf16() {
        let key = b"test-key";
        let result = KDF16(key, &[b"segment1"]);
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn test_kdf_deterministic() {
        let key = b"test-key";
        let a = KDF(key, &[b"path1", b"path2"]);
        let b = KDF(key, &[b"path1", b"path2"]);
        assert_eq!(a, b);
    }

    #[test]
    fn test_kdf_different_key_different_result() {
        let a = KDF(b"key1", &[b"path"]);
        let b = KDF(b"key2", &[b"path"]);
        assert_ne!(a, b);
    }
}
