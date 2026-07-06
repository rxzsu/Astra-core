use aes_gcm::{
    aead::{Aead, KeyInit as AeadKeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

pub type HmacSha512 = Hmac<sha2::Sha512>;

pub const REALITY_INFO: &[u8] = b"REALITY";
pub const SESSION_ID_SIZE: usize = 16;

pub fn generate_ephemeral_key() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(&mut rand::rng());
    let public = PublicKey::from(&secret);
    (secret, public)
}

pub fn ecdh_shared_secret(secret: EphemeralSecret, peer_public: &[u8; 32]) -> SharedSecret {
    let peer_pub = PublicKey::from(*peer_public);
    secret.diffie_hellman(&peer_pub)
}

pub fn hkdf_derive(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(REALITY_INFO, &mut okm)
        .expect("HKDF expand 32 bytes");
    okm
}

pub fn aes256gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("aes key: {}", e))?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|e| format!("aes encrypt: {}", e))
}

pub fn aes256gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("aes key: {}", e))?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|e| format!("aes decrypt: {}", e))
}

pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key)
        .expect("HMAC-SHA512 key size is valid");
    mac.update(data);
    let result = mac.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result.into_bytes());
    out
}

pub fn parse_public_key(hex_key: &str) -> Result<[u8; 32], String> {
    let decoded = hex::decode(hex_key).map_err(|e| format!("hex decode: {}", e))?;
    if decoded.len() != 32 {
        return Err(format!("public key must be 32 bytes, got {}", decoded.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&decoded);
    Ok(arr)
}

pub fn parse_short_id(hex_id: &str) -> Result<[u8; 8], String> {
    let decoded = hex::decode(hex_id).map_err(|e| format!("hex decode short_id: {}", e))?;
    if decoded.len() > 8 {
        return Err(format!("short_id too long: {} bytes", decoded.len()));
    }
    let mut arr = [0u8; 8];
    arr[..decoded.len()].copy_from_slice(&decoded);
    Ok(arr)
}

pub fn build_session_id(
    short_id: &[u8; 8],
    timestamp: u32,
) -> Vec<u8> {
    let mut sid = vec![0u8; SESSION_ID_SIZE];
    sid[0] = 1;
    sid[1] = 0;
    sid[2] = 0;
    sid[3] = 0;
    sid[4..8].copy_from_slice(&timestamp.to_be_bytes());
    sid[8..16].copy_from_slice(short_id);
    sid
}

pub fn parse_session_id(sid: &[u8]) -> Result<([u8; 8], u32), String> {
    if sid.len() < 16 {
        return Err(format!("session_id too short: {} bytes", sid.len()));
    }
    let mut short_id = [0u8; 8];
    short_id.copy_from_slice(&sid[8..16]);
    let mut ts_bytes = [0u8; 4];
    ts_bytes.copy_from_slice(&sid[4..8]);
    let timestamp = u32::from_be_bytes(ts_bytes);
    Ok((short_id, timestamp))
}
