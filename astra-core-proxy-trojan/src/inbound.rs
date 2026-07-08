use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use astra_core_transport::new_link_stream;

use astra_core_net::Network;
use astra_core_proxy::{async_trait, Conn, Dispatcher, InboundHandler, ProxyResult};
use astra_core_session::{Content, Inbound, Outbound, Session};

use crate::config::{Fallback, ServerConfig};
use crate::protocol;

const MAX_CHUNK_SIZE: usize = 0x3FFF;
const FALLBACK_BUF_SIZE: usize = 2048;

pub struct Handler {
    config: ServerConfig,
}

impl Handler {
    pub fn new(config: ServerConfig) -> Self {
        Handler { config }
    }

    fn find_user(&self, key: &[u8; 56]) -> Option<usize> {
        self.config.users.iter().position(|u| &u.key == key)
    }

    fn match_fallback(&self, sni: &str, alpn: &str, path: &str) -> Option<Fallback> {
        for fb in &self.config.fallbacks {
            let name_match = fb.name.is_empty() || fb.name == sni;
            let alpn_match = fb.alpn.is_empty() || fb.alpn == alpn;
            let path_match = fb.path.is_empty() || path.contains(&fb.path);
            if name_match && alpn_match && path_match {
                return Some(fb.clone());
            }
        }
        None
    }

    async fn fallback_connect(fb: &Fallback) -> Result<TcpStream, String> {
        let dest = if fb.dest.contains(':') {
            fb.dest.clone()
        } else {
            format!("{}:443", fb.dest)
        };
        TcpStream::connect(&dest)
            .await
            .map_err(|e| format!("fallback connect {}: {}", dest, e))
        // TODO: add PROXY protocol v1/v2 support when fb.xver > 0
    }

    /// Check if the first bytes look like a Trojan protocol.
    /// Trojan header starts with a 56-byte hex-encoded SHA224 hash,
    /// followed by \r\n, then command byte, address type, etc.
    /// If the first bytes don't look right, it's probably not Trojan.
    fn looks_like_trojan(data: &[u8]) -> bool {
        if data.len() < 58 {
            return false; // Need at least 56 (key) + 2 (\r\n) = 58 bytes
        }
        // In Go: the first 56 bytes should be lowercase hex
        data[..56].iter().all(|&b| b.is_ascii_hexdigit() || b.is_ascii_lowercase())
            && data[56] == b'\r'
            && data[57] == b'\n'
    }
}

#[async_trait]
impl InboundHandler for Handler {
    async fn process(
        &self,
        _session: Session,
        mut conn: Conn,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> ProxyResult<()> {
        // Read enough bytes to determine if it's Trojan protocol
        let mut peek_buf = vec![0u8; FALLBACK_BUF_SIZE];
        let n = conn
            .read(&mut peek_buf)
            .await
            .map_err(|e| format!("trojan inbound: read: {}", e))?;

        if n == 0 {
            return Ok(());
        }

        // Check fallback
        let has_fallbacks = !self.config.fallbacks.is_empty();

        // If it doesn't look like Trojan and we have fallbacks
        if has_fallbacks && !Self::looks_like_trojan(&peek_buf[..n]) {
            // Extract SNI from TLS ClientHello if possible
            let sni = extract_sni_from_client_hello(&peek_buf[..n]);
            let alpn = String::new(); // Would need ALPN from TLS handshake
            let path = extract_http_path(&peek_buf[..n]);

            if let Some(fb) = self.match_fallback(&sni, &alpn, &path) {
                // Fallback: connect to fallback destination and relay
                let mut fallback_stream = Self::fallback_connect(&fb)
                    .await
                    .map_err(|e| format!("fallback failed: {}", e))?;

                // Send the peeked data to fallback
                fallback_stream
                    .write_all(&peek_buf[..n])
                    .await
                    .map_err(|e| format!("fallback write: {}", e))?;

                // Relay remaining data bidirectionally
                let (mut fb_r, mut fb_w) = tokio::io::split(&mut fallback_stream);
                let (mut conn_r, mut conn_w) = tokio::io::split(&mut conn);

                let to_fb = tokio::io::copy(&mut conn_r, &mut fb_w);
                let to_conn = tokio::io::copy(&mut fb_r, &mut conn_w);

                tokio::select! {
                    r = to_fb => r.map_err(|e| format!("fallback copy: {}", e)).map(|_| ())?,
                    r = to_conn => r.map_err(|e| format!("fallback copy: {}", e)).map(|_| ())?,
                }
                return Ok(());
            }
        }

        // Process as normal Trojan protocol
        // Reconstruct the reader with the peeked data
        let mut all_data = peek_buf;
        all_data.truncate(n);
        // The first n bytes are the peeked data; the header reader needs
        // at least 58 bytes (56 key + 2 CRLF). If we have enough, parse header.
        if all_data.len() < 58 {
            return Err("trojan inbound: header too short".into());
        }

        let (header, header_size) = protocol::read_header_from_slice(&all_data)?;
        let _user_idx = self
            .find_user(&header.key)
            .ok_or_else(|| "trojan inbound: unknown user".to_string())?;

        let remaining = n - header_size;

        let target = header.destination;
        let out_session = Session {
            inbound: Some(Inbound {
                source: target.clone(),
                local: None,
                gateway: None,
                tag: String::new(),
            }),
            outbound: Some(Outbound {
                target: target.clone(),
                original_target: target.clone(),
                route_target: None,
                tag: String::new(),
            }),
            content: Some(Content {
                protocol: Some("trojan".into()),
                ..Default::default()
            }),
        };

        if target.network != Network::Tcp {
            return Err("trojan inbound: non-TCP not supported yet".into());
        }

        let link = dispatcher.dispatch(out_session, target).await?;
        let mut link_stream = new_link_stream(link);

        // Send remaining data after header to link
        if remaining > 0 {
            use tokio::io::AsyncWriteExt;
            link_stream
                .write_all(&all_data[header_size..])
                .await
                .map_err(|e| format!("trojan: write remaining: {}", e))?;
        }

        let (mut link_r, mut link_w) = tokio::io::split(&mut link_stream);
        let (mut conn_r, mut conn_w) = tokio::io::split(&mut conn);

        let to_client = tokio::io::copy(&mut link_r, &mut conn_w);
        let to_link = tokio::io::copy(&mut conn_r, &mut link_w);

        tokio::select! {
            r = to_client => r.map_err(|e| format!("trojan copy: {}", e)).map(|_| ())?,
            r = to_link => r.map_err(|e| format!("trojan copy: {}", e)).map(|_| ())?,
        }

        Ok(())
    }
}

/// Extract SNI from a raw TLS ClientHello.
/// TLS ClientHello starts with 0x16 (Handshake), then version, then length,
/// then 0x01 (ClientHello), then 3 bytes length, then version, then random (32),
/// then session ID, then cipher suites, then compression, then extensions.
/// SNI extension has type 0x0000.
fn extract_sni_from_client_hello(data: &[u8]) -> String {
    if data.len() < 50 || data[0] != 0x16 {
        return String::new();
    }
    // Skip record header (5 bytes) + handshake header (4 bytes) + version (2) + random (32)
    let mut pos = 43; // 5 + 4 + 2 + 32
    if pos >= data.len() { return String::new(); }

    // Session ID length
    let sid_len = data[pos] as usize;
    pos += 1 + sid_len;
    if pos + 1 >= data.len() { return String::new(); }

    // Cipher suites length
    let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos >= data.len() { return String::new(); }

    // Compression methods length
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;
    if pos + 1 >= data.len() { return String::new(); }

    // Extensions length
    let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    if ext_end > data.len() { return String::new(); }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if ext_type == 0x0000 && pos + 2 <= ext_end {
            // SNI extension
            let _sni_list_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if pos + 3 <= ext_end {
                let _sni_type = data[pos]; // 0x00 for host_name
                let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
                pos += 3;
                if pos + name_len <= data.len()
                    && let Ok(name) = std::str::from_utf8(&data[pos..pos + name_len]) {
                        return name.to_string();
                    }
            }
        }
        pos += ext_data_len;
    }
    String::new()
}

/// Extract HTTP Host/Authority from raw HTTP request.
fn extract_http_path(data: &[u8]) -> String {
    let s = std::str::from_utf8(data).unwrap_or("");
    for line in s.lines() {
        if line.to_lowercase().starts_with("host:") {
            return line[5..].trim().to_string();
        }
        if line.to_lowercase().starts_with(":authority:") {
            return line[11..].trim().to_string();
        }
    }
    // Extract path from GET/POST line
    if let Some(line) = s.lines().next()
        && (line.starts_with("GET ") || line.starts_with("POST ")) && line.len() > 5 {
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                return parts[1].to_string();
            }
        }
    String::new()
}
