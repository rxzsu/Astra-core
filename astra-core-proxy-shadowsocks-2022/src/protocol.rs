use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Digest, Sha256};

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
        match self { CipherType::Aes128Gcm => 16, _ => 32 }
    }
}

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
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub fn encode_target(addr: &astra_core_net::Address, port: u16) -> Vec<u8> {
    let mut out = Vec::new();
    match addr {
        astra_core_net::Address::Ipv4(ip) => { out.push(1); out.extend_from_slice(ip); }
        astra_core_net::Address::Domain(d) => { out.push(2); out.push(d.len() as u8); out.extend_from_slice(d.as_bytes()); }
        astra_core_net::Address::Ipv6(ip) => { out.push(3); out.extend_from_slice(ip); }
    }
    out.extend_from_slice(&port.to_be_bytes());
    out
}

pub fn decode_target(data: &[u8]) -> Result<(astra_core_net::Address, u16), String> {
    if data.is_empty() { return Err("empty".into()); }
    match data[0] {
        1 => {
            if data.len() < 7 { return Err("short ipv4".into()); }
            Ok((astra_core_net::Address::Ipv4([data[1], data[2], data[3], data[4]]), u16::from_be_bytes([data[5], data[6]])))
        }
        2 => {
            if data.len() < 2 { return Err("short domain".into()); }
            let dlen = data[1] as usize;
            if data.len() < 2 + dlen + 2 { return Err("short domain".into()); }
            let domain = String::from_utf8(data[2..2+dlen].to_vec()).map_err(|_| "bad domain".to_string())?;
            Ok((astra_core_net::Address::Domain(domain), u16::from_be_bytes([data[2+dlen], data[3+dlen]])))
        }
        3 => {
            if data.len() < 18 { return Err("short ipv6".into()); }
            let mut ip = [0u8; 16]; ip.copy_from_slice(&data[1..17]);
            Ok((astra_core_net::Address::Ipv6(ip), u16::from_be_bytes([data[17], data[18]])))
        }
        _ => Err(format!("bad atyp: {}", data[0])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra_core_net::Address;

    #[test]
    fn test_master_key() {
        assert_eq!(derive_master_key(b"test", 32).len(), 32);
    }

    #[test]
    fn test_session_key() {
        assert_eq!(derive_session_key(&[0u8; 16], &[1u8; 16], 32).len(), 32);
    }

    #[test]
    fn test_target_roundtrip() {
        let enc = encode_target(&Address::Domain("example.com".into()), 443);
        let (addr, port) = decode_target(&enc).unwrap();
        assert_eq!(addr.as_domain(), Some("example.com"));
        assert_eq!(port, 443);
    }
}
