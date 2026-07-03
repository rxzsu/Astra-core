use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use astra_core_crypto::aes::AesGcmCipher;
use astra_core_crypto::cipher::AeadCipher;
use astra_core_crypto::sha256::Sha256;
use astra_core_proto::{RequestCommand, RequestHeader, SecurityType};

use crate::aead::encrypt::OpenVMessAEADHeader;
use crate::aead::kdf::{KDF, KDF16};


use crate::aead::consts::*;
use crate::encoding::auth::Authenticate;

/// Session ID for replay-attack prevention.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct SessionID {
    pub user: [u8; 16],
    pub key: [u8; 16],
    pub nonce: [u8; 16],
}

/// Session history for replay-attack prevention (3-minute expiry).
/// Mirrors go's `proxy/vmess/encoding.SessionHistory`.
pub struct SessionHistory {
    cache: HashMap<SessionID, u64>, // session -> expiry timestamp (seconds)
}

impl Default for SessionHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionHistory {
    pub fn new() -> Self {
        SessionHistory {
            cache: HashMap::new(),
        }
    }

    /// Returns false if session already exists (replay detected).
    pub fn add_if_not_exists(&mut self, session: SessionID) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Clean expired entries
        self.cache.retain(|_, expiry| *expiry > now);

        if self.cache.contains_key(&session) {
            return false; // replay
        }

        self.cache.insert(session, now + 180); // 3 minute expiry
        true
    }
}

/// Server session for decoding VMess requests and encoding responses.
/// Mirrors go's `proxy/vmess/encoding.ServerSession`.
pub struct ServerSession {
    pub request_body_key: [u8; 16],
    pub request_body_iv: [u8; 16],
    pub response_body_key: [u8; 16],
    pub response_body_iv: [u8; 16],
    pub response_header: u8,
    session_history: SessionHistory,
}

impl ServerSession {
    pub fn new(session_history: SessionHistory) -> Self {
        ServerSession {
            request_body_key: [0u8; 16],
            request_body_iv: [0u8; 16],
            response_body_key: [0u8; 16],
            response_body_iv: [0u8; 16],
            response_header: 0,
            session_history,
        }
    }

    /// Decode a VMess request header from raw bytes.
    /// Returns (RequestHeader, cmd_key_used) on success.
    pub fn DecodeRequestHeader(
        &mut self,
        auth_id: &[u8; 16],
        data: &[u8],
        cmd_key: &[u8; 16],
    ) -> Result<RequestHeader, String> {
        let (plaintext, _should_drain, _bytes_read) = OpenVMessAEADHeader(cmd_key, auth_id, data)?;

        if plaintext.len() < 38 {
            return Err("request header too short".to_string());
        }

        let version = plaintext[0];
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&plaintext[1..17]);
        let mut key = [0u8; 16];
        key.copy_from_slice(&plaintext[17..33]);
        let response_hdr = plaintext[33];
        let option = plaintext[34];
        let security_byte = plaintext[35] & 0x0f;
        let _padding_len = (plaintext[35] >> 4) as usize;
        let _reserved = plaintext[36];
        let cmd_byte = plaintext[37];

        self.request_body_iv = iv;
        self.request_body_key = key;
        self.response_header = response_hdr;

        // Derive response keys
        let resp_key = Sha256::hash(&self.request_body_key);
        let resp_iv = Sha256::hash(&self.request_body_iv);
        self.response_body_key = resp_key[..16].try_into().unwrap();
        self.response_body_iv = resp_iv[..16].try_into().unwrap();

        let command = RequestCommand::from_byte(cmd_byte)
            .ok_or_else(|| format!("unknown VMess command: {}", cmd_byte))?;

        let mut offset = 38usize;
        let (address, port) = match command {
            RequestCommand::Tcp | RequestCommand::Udp => {
                if plaintext.len() < offset + 2 {
                    return Err("truncated port".to_string());
                }
                let port_val = u16::from_be_bytes([plaintext[offset], plaintext[offset + 1]]);
                offset += 2;
                let (addr, consumed) = decode_address(&plaintext[offset..])?;
                offset += consumed;
                (addr, astra_core_net::Port::from(port_val))
            }
            _ => (astra_core_net::Address::Ipv4([0; 4]), astra_core_net::Port::from(0)),
        };

        // Padding
        offset += _padding_len;

        // FNV-1a checksum (last 4 bytes)
        if plaintext.len() < offset + 4 {
            return Err("truncated checksum".to_string());
        }
        let expected_hash = u32::from_be_bytes([
            plaintext[offset],
            plaintext[offset + 1],
            plaintext[offset + 2],
            plaintext[offset + 3],
        ]);
        let actual_hash = Authenticate(&plaintext[..offset]);
        if expected_hash != actual_hash {
            return Err("FNV checksum mismatch".to_string());
        }

        // Replay check
        let session = SessionID {
            user: *cmd_key,
            key: self.request_body_key,
            nonce: self.request_body_iv,
        };
        if !self.session_history.add_if_not_exists(session) {
            return Err("replay attack detected".to_string());
        }

        let security = SecurityType::from_byte(security_byte);

        Ok(RequestHeader {
            version,
            command,
            option,
            security,
            port,
            address,
            user: None,
        })
    }

    /// Encode the VMess response header (AEAD-encrypted).
    pub fn EncodeResponseHeader(&self, option_byte: u8, cmd_data: Option<&[u8]>) -> Vec<u8> {
        let rk = self.response_body_key;
        let riv = self.response_body_iv;

        // Build plaintext
        let mut plaintext = Vec::new();
        plaintext.push(self.response_header);
        plaintext.push(option_byte);
        if let Some(cmd) = cmd_data {
            plaintext.extend_from_slice(cmd);
        } else {
            plaintext.push(0x00); // cmdID = 0 (no command)
            plaintext.push(0x00); // length = 0
        }

        // Length AEAD
        let len_key: [u8; 16] = KDF16(&rk, &[KDF_SALT_AEAD_RESP_HEADER_LEN_KEY]);
        let len_iv = &KDF(&riv, &[KDF_SALT_AEAD_RESP_HEADER_LEN_IV]);
        let len_plain = (plaintext.len() as u16).to_be_bytes();
        let len_ct = aes_gcm_seal(&len_key, &len_iv[..12], &len_plain, &[]);

        // Payload AEAD
        let payload_key: [u8; 16] = KDF16(&rk, &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY]);
        let payload_iv = &KDF(&riv, &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV]);
        let payload_ct = aes_gcm_seal(&payload_key, &payload_iv[..12], &plaintext, &[]);

        let mut out = Vec::with_capacity(len_ct.len() + payload_ct.len());
        out.extend_from_slice(&len_ct);
        out.extend_from_slice(&payload_ct);
        out
    }
}

// ── Helpers ────────────────────────────────────────────────────────

fn decode_address(data: &[u8]) -> Result<(astra_core_net::Address, usize), String> {
    if data.is_empty() {
        return Err("truncated address".to_string());
    }
    let addr_type = data[0];
    match addr_type {
        1 => {
            if data.len() < 5 { return Err("truncated IPv4".to_string()); }
            let mut o = [0u8; 4];
            o.copy_from_slice(&data[1..5]);
            Ok((astra_core_net::Address::Ipv4(o), 5))
        }
        2 => {
            if data.len() < 2 { return Err("truncated domain len".to_string()); }
            let dlen = data[1] as usize;
            if data.len() < 2 + dlen { return Err("truncated domain".to_string()); }
            let domain = String::from_utf8_lossy(&data[2..2 + dlen]).to_string();
            Ok((astra_core_net::Address::Domain(domain), 2 + dlen))
        }
        3 => {
            if data.len() < 17 { return Err("truncated IPv6".to_string()); }
            let mut o = [0u8; 16];
            o.copy_from_slice(&data[1..17]);
            Ok((astra_core_net::Address::Ipv6(o), 17))
        }
        _ => Err(format!("unknown address type: {}", addr_type)),
    }
}

fn aes_gcm_seal(key: &[u8; 16], iv: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = AesGcmCipher::new(key);
    cipher
        .seal_with_nonce(&mut vec![], plaintext, iv, aad)
        .unwrap_or_else(|_| plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::client::ClientSession;

    #[test]
    fn test_session_history() {
        let mut sh = SessionHistory::new();
        let sid = SessionID {
            user: [0u8; 16],
            key: [1u8; 16],
            nonce: [2u8; 16],
        };
        assert!(sh.add_if_not_exists(sid.clone()));
        // Duplicate
        assert!(!sh.add_if_not_exists(sid));
    }

    #[test]
    fn test_decode_request_header() {
        let client = ClientSession::new();
        let cmd_key = [0x42u8; 16];
        let header = RequestHeader {
            version: 1,
            command: RequestCommand::Tcp,
            option: 0x01,
            security: SecurityType::Aes128Gcm,
            port: astra_core_net::Port(443),
            address: astra_core_net::Address::Ipv4([10, 0, 0, 1]),
            user: None,
        };

        let encoded = client.EncodeRequestHeader(&header, &cmd_key);
        let auth_id = &encoded[..16];
        let mut auth_id_arr = [0u8; 16];
        auth_id_arr.copy_from_slice(auth_id);

        let mut server = ServerSession::new(SessionHistory::new());
        let decoded = server.DecodeRequestHeader(&auth_id_arr, &encoded[16..], &cmd_key).unwrap();
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.command, RequestCommand::Tcp);
        assert_eq!(decoded.port.value(), 443);
    }

    #[test]
    fn test_encode_response_header() {
        let sh = SessionHistory::new();

        // First set request keys via a header decode (minimal)
        let mut server = ServerSession::new(sh);

        // Manually set keys (normally set during DecodeRequestHeader)
        let req_key = [0x01u8; 16];
        let req_iv = [0x02u8; 16];
        server.request_body_key = req_key;
        server.request_body_iv = req_iv;
        server.response_header = 0xab;

        let resp_key = Sha256::hash(&req_key);
        let resp_iv = Sha256::hash(&req_iv);
        server.response_body_key = resp_key[..16].try_into().unwrap();
        server.response_body_iv = resp_iv[..16].try_into().unwrap();

        let encoded = server.EncodeResponseHeader(0, None);
        assert!(encoded.len() > 18);
    }
}
