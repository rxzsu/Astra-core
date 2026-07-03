use astra_core_crypto::aes::AesGcmCipher;
use astra_core_crypto::cipher::AeadCipher;

use crate::aead::authid::CreateAuthID;
use crate::aead::consts::*;
use crate::aead::kdf::{KDF, KDF16};

/// AEAD-seal a VMess request header.
/// Mirrors go's `proxy/vmess/aead.SealVMessAEADHeader`.
///
/// Output format:
///   [0:16]   = generatedAuthID
///   [16:34]  = AEAD-encrypted length (18 bytes)
///   [34:42]  = connectionNonce (8 bytes)
///   [42:]    = AEAD-encrypted payload
pub fn SealVMessAEADHeader(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let auth_id = CreateAuthID(key, timestamp);
    let conn_nonce = rand_8_bytes();

    // Length AEAD
    let len_key = KDF16(key, &[KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY, &auth_id, &conn_nonce]);
    let len_iv = KDF(key, &[KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV, &auth_id, &conn_nonce]);
    let len_plain = (data.len() as u16).to_be_bytes();
    let len_cipher = aes_gcm_seal(&len_key, &len_iv[..12], &len_plain, &auth_id);

    // Payload AEAD
    let payload_key = KDF16(key, &[KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_KEY, &auth_id, &conn_nonce]);
    let payload_iv = KDF(key, &[KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_IV, &auth_id, &conn_nonce]);
    let payload_cipher = aes_gcm_seal(&payload_key, &payload_iv[..12], data, &auth_id);

    let mut out = Vec::with_capacity(16 + 18 + 8 + payload_cipher.len());
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&len_cipher);
    out.extend_from_slice(&conn_nonce);
    out.extend_from_slice(&payload_cipher);
    out
}

/// AEAD-open a VMess request header.
/// Returns (decrypted_payload, should_drain, bytes_read).
pub fn OpenVMessAEADHeader(
    key: &[u8; 16],
    auth_id: &[u8; 16],
    data: &[u8],
) -> Result<(Vec<u8>, bool, usize), String> {
    let mut offset = 0usize;

    // Read length ciphertext (18 bytes)
    if data.len() < 18 {
        return Err("truncated length header".to_string());
    }
    let len_ct = &data[offset..offset + 18];
    offset += 18;

    // Read connection nonce (8 bytes)
    if data.len() < offset + 8 {
        return Err("truncated connection nonce".to_string());
    }
    let conn_nonce = &data[offset..offset + 8];
    offset += 8;

    // Decrypt length
    let len_key = KDF16(key, &[KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY, auth_id, conn_nonce]);
    let len_iv = KDF(key, &[KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV, auth_id, conn_nonce]);
    let len_plain = aes_gcm_open(&len_key, &len_iv[..12], len_ct, auth_id)?;
    let payload_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;

    // Read payload
    if data.len() < offset + payload_len + 16 {
        return Err("truncated payload".to_string());
    }
    let payload_ct = &data[offset..offset + payload_len + 16];
    let payload_key = KDF16(key, &[KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_KEY, auth_id, conn_nonce]);
    let payload_iv = KDF(key, &[KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_IV, auth_id, conn_nonce]);
    let payload = aes_gcm_open(&payload_key, &payload_iv[..12], payload_ct, auth_id)?;

    let total_read = offset + payload_len + 16;
    Ok((payload, false, total_read))
}

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

fn rand_8_bytes() -> [u8; 8] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut state = seed as u64;
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_open_roundtrip() {
        let key = [0xabu8; 16];
        let data = b"hello vmess";
        let sealed = SealVMessAEADHeader(&key, data);
        assert!(sealed.len() > 42);

        let auth_id = &sealed[..16];
        let mut auth_id_arr = [0u8; 16];
        auth_id_arr.copy_from_slice(auth_id);

        let (opened, _drain, _read) = OpenVMessAEADHeader(&key, &auth_id_arr, &sealed[16..]).unwrap();
        assert_eq!(opened, data);
    }

    #[test]
    fn test_seal_open_wrong_key() {
        let key = [0xabu8; 16];
        let wrong_key = [0x42u8; 16];
        let data = b"test data";
        let sealed = SealVMessAEADHeader(&key, data);
        let auth_id = &sealed[..16];
        let mut auth_id_arr = [0u8; 16];
        auth_id_arr.copy_from_slice(auth_id);

        let result = OpenVMessAEADHeader(&wrong_key, &auth_id_arr, &sealed[16..]);
        assert!(result.is_err());
    }
}
