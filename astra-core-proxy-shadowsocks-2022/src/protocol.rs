use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CipherType {
    Aes128Gcm,
    Aes256Gcm,
    XChaCha20Poly1305,
}

impl CipherType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "2022-blake3-aes-128-gcm" => Some(CipherType::Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Some(CipherType::Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Some(CipherType::XChaCha20Poly1305),
            _ => None,
        }
    }
    pub fn key_size(&self) -> usize {
        match self {
            CipherType::Aes128Gcm => 16,
            _ => 32,
        }
    }
    pub fn nonce_size(&self) -> usize {
        match self {
            CipherType::XChaCha20Poly1305 => 24,
            _ => 12,
        }
    }
    pub fn salt_size(&self) -> usize {
        match self {
            CipherType::Aes128Gcm => 16,
            _ => 32,
        }
    }
}

const TAG: usize = 16;
const MAX_PKT: usize = 16383;

// ─── Key derivation ────────────────────────────────────────────────────────

pub fn derive_master_key(psk: &[u8], key_size: usize) -> Vec<u8> {
    Sha256::digest(psk)[..key_size].to_vec()
}

pub fn derive_session_key(psk: &[u8], salt: &[u8], key_size: usize) -> Vec<u8> {
    let mut ctx = psk.to_vec();
    ctx.extend_from_slice(salt);
    let derived = blake3::derive_key("shadowsocks 2022 session subkey", &ctx);
    derived[..key_size].to_vec()
}

pub fn current_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─── AEAD encrypt / decrypt ───────────────────────────────────────────────

fn aead_encrypt(c: CipherType, key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    match c {
        CipherType::Aes128Gcm => {
            let cipher = Aes128Gcm::new_from_slice(key).map_err(|e| format!("key: {}", e))?;
            let n = aes_gcm::Nonce::from_slice(nonce);
            cipher
                .encrypt(n, data)
                .map_err(|e| format!("aes encrypt: {}", e))
        }
        CipherType::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("key: {}", e))?;
            let n = aes_gcm::Nonce::from_slice(nonce);
            cipher
                .encrypt(n, data)
                .map_err(|e| format!("aes encrypt: {}", e))
        }
        CipherType::XChaCha20Poly1305 => {
            let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| format!("key: {}", e))?;
            let n = chacha20poly1305::XNonce::from_slice(nonce);
            cipher
                .encrypt(n, data)
                .map_err(|e| format!("xchacha encrypt: {}", e))
        }
    }
}

fn aead_decrypt(c: CipherType, key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    match c {
        CipherType::Aes128Gcm => {
            let cipher = Aes128Gcm::new_from_slice(key).map_err(|e| format!("key: {}", e))?;
            let n = aes_gcm::Nonce::from_slice(nonce);
            cipher
                .decrypt(n, data)
                .map_err(|e| format!("aes decrypt: {}", e))
        }
        CipherType::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("key: {}", e))?;
            let n = aes_gcm::Nonce::from_slice(nonce);
            cipher
                .decrypt(n, data)
                .map_err(|e| format!("aes decrypt: {}", e))
        }
        CipherType::XChaCha20Poly1305 => {
            let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| format!("key: {}", e))?;
            let n = chacha20poly1305::XNonce::from_slice(nonce);
            cipher
                .decrypt(n, data)
                .map_err(|e| format!("xchacha decrypt: {}", e))
        }
    }
}

fn inc_nonce(n: &mut [u8]) {
    for b in n.iter_mut().rev() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
}

// ─── TCP AEAD chunked (Go: shadowaead TCP) ─────────────────────────────────

pub async fn write_chunk<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    data: &[u8],
    c: CipherType,
    key: &[u8],
    nonce: &mut [u8],
) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;
    let len_pt = [(data.len() as u16).to_be_bytes()];
    let len_ct = aead_encrypt(c, key, nonce, &len_pt[0])?;
    inc_nonce(nonce);
    let payload_ct = aead_encrypt(c, key, nonce, data)?;
    inc_nonce(nonce);
    w.write_all(&len_ct).await.map_err(|e| e.to_string())?;
    w.write_all(&payload_ct).await.map_err(|e| e.to_string())?;
    Ok(())
}

pub async fn read_chunk<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
    c: CipherType,
    key: &[u8],
    nonce: &mut [u8],
) -> Result<Option<Vec<u8>>, String> {
    use tokio::io::AsyncReadExt;
    let mut len_enc = vec![0u8; 2 + TAG];
    if r.read_exact(&mut len_enc).await.is_err() {
        return Ok(None);
    }

    let len_pt = aead_decrypt(c, key, nonce, &len_enc)?;
    inc_nonce(nonce);

    let payload_len = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;
    if payload_len == 0 || payload_len > MAX_PKT {
        return Err("bad len".into());
    }

    let mut payload_enc = vec![0u8; payload_len + TAG];
    r.read_exact(&mut payload_enc)
        .await
        .map_err(|e| e.to_string())?;

    let payload = aead_decrypt(c, key, nonce, &payload_enc)?;
    inc_nonce(nonce);

    Ok(Some(payload))
}

// ─── UDP encrypt / decrypt (Go: shadowaead_2022 UDP) ──────────────────────

pub fn encrypt_udp(
    c: CipherType,
    key: &[u8],
    session_id: &[u8],
    pkt_id: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, String> {
    match c {
        CipherType::XChaCha20Poly1305 => {
            let mut nonce = [0u8; 24];
            for b in &mut nonce {
                *b = rand::random();
            }
            let ct = aead_encrypt(c, key, &nonce, data)?;
            let mut out = nonce.to_vec();
            out.extend_from_slice(&ct);
            Ok(out)
        }
        _ => {
            let ecb_key = &key[..key.len().min(16)];
            let mut header = [0u8; 16];
            header[..8].copy_from_slice(&session_id[..session_id.len().min(8)]);
            header[8..16].copy_from_slice(&pkt_id[..pkt_id.len().min(8)]);

            // Derive session key from PLAIN session_id, then encrypt header
            let sk = derive_session_key(key, &header[..8], c.key_size());
            aes_ecb_encrypt(&mut header, ecb_key);

            let ct = aead_encrypt(c, &sk, &[0u8; 12], data)?;
            let mut out = header.to_vec();
            out.extend_from_slice(&ct);
            Ok(out)
        }
    }
}

pub fn decrypt_udp(c: CipherType, key: &[u8], data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    match c {
        CipherType::XChaCha20Poly1305 => {
            if data.len() < 24 + TAG {
                return Err("short".into());
            }
            let pt = aead_decrypt(c, key, &data[..24], &data[24..])?;
            Ok((vec![], pt))
        }
        _ => {
            if data.len() < 16 + TAG {
                return Err("short".into());
            }
            let mut header = [0u8; 16];
            header.copy_from_slice(&data[..16]);
            let ecb_key = &key[..key.len().min(16)];
            aes_ecb_decrypt(&mut header, ecb_key);
            let session_id = header[..8].to_vec();
            let pkt_id = header[8..16].to_vec();
            let sk = derive_session_key(key, &session_id, c.key_size());
            let pt = aead_decrypt(c, &sk, &[0u8; 12], &data[16..])?;
            Ok((pkt_id, pt))
        }
    }
}

fn aes_ecb_encrypt(block: &mut [u8; 16], key: &[u8]) {
    use aes::cipher::BlockEncryptMut;
    if let Ok(mut c) = aes::Aes128::new_from_slice(key) {
        c.encrypt_block_mut(block.into());
    }
}

fn aes_ecb_decrypt(block: &mut [u8; 16], key: &[u8]) {
    use aes::cipher::BlockDecryptMut;
    if let Ok(mut c) = aes::Aes128::new_from_slice(key) {
        c.decrypt_block_mut(block.into());
    }
}

// ─── Target encoding ──────────────────────────────────────────────────────

pub fn encode_target(addr: &astra_core_net::Address, port: u16) -> Vec<u8> {
    let mut out = Vec::new();
    match addr {
        astra_core_net::Address::Ipv4(ip) => {
            out.push(1);
            out.extend_from_slice(ip);
        }
        astra_core_net::Address::Domain(d) => {
            out.push(2);
            out.push(d.len() as u8);
            out.extend_from_slice(d.as_bytes());
        }
        astra_core_net::Address::Ipv6(ip) => {
            out.push(3);
            out.extend_from_slice(ip);
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    out
}

pub fn decode_target(data: &[u8]) -> Result<(astra_core_net::Address, u16), String> {
    if data.is_empty() {
        return Err("empty".into());
    }
    match data[0] {
        1 => {
            if data.len() < 7 {
                return Err("short ipv4".into());
            }
            Ok((
                astra_core_net::Address::Ipv4([data[1], data[2], data[3], data[4]]),
                u16::from_be_bytes([data[5], data[6]]),
            ))
        }
        2 => {
            if data.len() < 2 {
                return Err("short domain".into());
            }
            let dlen = data[1] as usize;
            if data.len() < 2 + dlen + 2 {
                return Err("short domain".into());
            }
            let domain = String::from_utf8(data[2..2 + dlen].to_vec())
                .map_err(|_| "bad domain".to_string())?;
            Ok((
                astra_core_net::Address::Domain(domain),
                u16::from_be_bytes([data[2 + dlen], data[3 + dlen]]),
            ))
        }
        3 => {
            if data.len() < 18 {
                return Err("short ipv6".into());
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&data[1..17]);
            Ok((
                astra_core_net::Address::Ipv6(ip),
                u16::from_be_bytes([data[17], data[18]]),
            ))
        }
        _ => Err(format!("bad atyp: {}", data[0])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra_core_net::Address;

    #[test]
    fn test_derive() {
        assert_eq!(derive_master_key(b"t", 32).len(), 32);
        assert_eq!(derive_session_key(&[0; 16], &[1; 16], 16).len(), 16);
    }

    #[test]
    fn test_target_roundtrip() {
        let enc = encode_target(&Address::Domain("x.com".into()), 80);
        let (a, p) = decode_target(&enc).unwrap();
        assert_eq!(a.as_domain(), Some("x.com"));
        assert_eq!(p, 80);
    }

    #[tokio::test]
    async fn test_tcp_chunk_roundtrip() {
        use tokio::io::duplex;
        let key = derive_master_key(b"test-psk-aes128", 16);
        let (mut tx, mut rx) = duplex(4096);
        let mut wn = [0u8; 12];
        let mut rn = [0u8; 12];

        write_chunk(
            &mut tx,
            b"hello ss2022!",
            CipherType::Aes128Gcm,
            &key,
            &mut wn,
        )
        .await
        .unwrap();
        let res = read_chunk(&mut rx, CipherType::Aes128Gcm, &key, &mut rn)
            .await
            .unwrap();
        assert_eq!(res, Some(b"hello ss2022!".to_vec()));
    }

    #[tokio::test]
    async fn test_tcp_chunk_roundtrip_xchacha() {
        use tokio::io::duplex;
        let key = derive_master_key(b"test-psk-xchacha", 32);
        let (mut tx, mut rx) = duplex(4096);
        let mut wn = [0u8; 24];
        let mut rn = [0u8; 24];

        write_chunk(
            &mut tx,
            b"xchacha test",
            CipherType::XChaCha20Poly1305,
            &key,
            &mut wn,
        )
        .await
        .unwrap();
        let res = read_chunk(&mut rx, CipherType::XChaCha20Poly1305, &key, &mut rn)
            .await
            .unwrap();
        assert_eq!(res, Some(b"xchacha test".to_vec()));
    }

    #[test]
    fn test_udp_encrypt_decrypt() {
        let key = derive_master_key(b"test-udp-aes128", 16);
        let sid = [1u8; 8];
        let pid = [2u8; 8];
        let data = b"hello udp!";

        let enc = encrypt_udp(CipherType::Aes128Gcm, &key, &sid, &pid, data).unwrap();
        let (dec_pid, dec_data) = decrypt_udp(CipherType::Aes128Gcm, &key, &enc).unwrap();
        assert_eq!(dec_data, data);
        assert_eq!(dec_pid, pid);
    }
}
