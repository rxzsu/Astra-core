use astra_core_crypto::aes::AesCipher;

use crate::aead::consts::KDF_SALT_AUTH_ID_ENCRYPTION_KEY;
use crate::aead::kdf::KDF16;

/// VMess Auth ID length (16 bytes).
pub const AUTH_ID_LEN: usize = 16;

/// Create an AuthID from a command key and timestamp.
/// Mirrors go's `proxy/vmess/aead.CreateAuthID`.
pub fn CreateAuthID(cmd_key: &[u8], time: i64) -> [u8; AUTH_ID_LEN] {
    let mut buf = [0u8; AUTH_ID_LEN];
    // First 8 bytes: big-endian timestamp
    buf[..8].copy_from_slice(&time.to_be_bytes());
    // Next 4 bytes: random
    let rand_bytes = simple_rand();
    buf[8..12].copy_from_slice(&rand_bytes);
    // Last 4 bytes: CRC32 of first 12 bytes
    let crc = crc32_ieee(&buf[..12]);
    buf[12..16].copy_from_slice(&crc.to_be_bytes());

    // Encrypt in-place with AES key derived from cmd_key
    let aes_key = KDF16(cmd_key, &[KDF_SALT_AUTH_ID_ENCRYPTION_KEY]);
    let cipher = AesCipher::new(&aes_key);
    cipher.encrypt(&mut buf);
    buf
}

/// Decode an AuthID, returning (timestamp, rand, crc, plaintext).
pub fn DecodeAuthID(
    cmd_key: &[u8],
    auth_id: &[u8; AUTH_ID_LEN],
) -> Result<(i64, u32, u32, [u8; AUTH_ID_LEN]), String> {
    let aes_key = KDF16(cmd_key, &[KDF_SALT_AUTH_ID_ENCRYPTION_KEY]);
    let cipher = AesCipher::new(&aes_key);
    let mut plaintext = *auth_id;
    cipher.decrypt(&mut plaintext);

    let time = i64::from_be_bytes([
        plaintext[0],
        plaintext[1],
        plaintext[2],
        plaintext[3],
        plaintext[4],
        plaintext[5],
        plaintext[6],
        plaintext[7],
    ]);
    let rand_val = u32::from_be_bytes([plaintext[8], plaintext[9], plaintext[10], plaintext[11]]);
    let crc = u32::from_be_bytes([plaintext[12], plaintext[13], plaintext[14], plaintext[15]]);

    // Verify CRC32
    let expected_crc = crc32_ieee(&plaintext[..12]);
    if crc != expected_crc {
        return Err("AuthID CRC mismatch".to_string());
    }

    Ok((time, rand_val, crc, plaintext))
}

/// Derive a 16-byte AES key from a command key.
/// Mirrors go's `proxy/vmess/aead.NewCipherFromKey`.
pub fn NewCipherFromKey(cmd_key: &[u8]) -> AesCipher {
    let aes_key = KDF16(cmd_key, &[KDF_SALT_AUTH_ID_ENCRYPTION_KEY]);
    AesCipher::new(&aes_key)
}

// ── CRC32/IEEE (table-based) ──────────────────────────────────────

static CRC32_TABLE: [u32; 256] = make_crc32_table();

const fn make_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xedb88320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc = CRC32_TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

fn simple_rand() -> [u8; 4] {
    rand::random::<u32>().to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_ieee() {
        // Known CRC32 values
        assert_eq!(crc32_ieee(b""), 0);
        assert_eq!(crc32_ieee(b"hello world"), 0x0d4a1185);
    }

    #[test]
    fn test_create_auth_id() {
        let cmd_key = [0xabu8; 16];
        let time = 1234567890i64;
        let auth_id = CreateAuthID(&cmd_key, time);
        assert_eq!(auth_id.len(), AUTH_ID_LEN);

        let (decoded_time, _rand, _crc, _plain) = DecodeAuthID(&cmd_key, &auth_id).unwrap();
        assert_eq!(decoded_time, time);
    }

    #[test]
    fn test_auth_id_invalid_crc() {
        let cmd_key = [0xabu8; 16];
        let time = 1234567890i64;
        let mut auth_id = CreateAuthID(&cmd_key, time);
        // Corrupt one byte
        auth_id[0] ^= 0xff;
        assert!(DecodeAuthID(&cmd_key, &auth_id).is_err());
    }

    #[test]
    fn test_new_cipher_from_key() {
        let cmd_key = [0xabu8; 16];
        let cipher = NewCipherFromKey(&cmd_key);
        let plaintext = [0x42u8; 16];
        let mut buf = plaintext;
        cipher.encrypt(&mut buf);
        cipher.decrypt(&mut buf);
        assert_eq!(plaintext, buf);
    }
}
