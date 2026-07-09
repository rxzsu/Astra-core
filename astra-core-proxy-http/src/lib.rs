pub mod outbound;

use base64::Engine;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use astra_core_net::{Destination, Network, ParseAddress, Port};
use astra_core_proxy::{async_trait, Conn, Dispatcher, InboundHandler, ProxyResult};
use astra_core_session::{Outbound, Session};
use astra_core_transport::new_link_stream;

#[derive(Debug, Clone, Default)]
pub struct HttpConfig {
    pub accounts: HashMap<String, String>,
    pub allow_transparent: bool,
    pub user_level: u32,
}

impl HttpConfig {
    pub fn has_account(&self, username: &str, password: &str) -> bool {
        self.accounts.get(username).is_some_and(|p| p == password)
    }
}

#[derive(Clone)]
pub struct Handler {
    pub config: HttpConfig,
}

impl Handler {
    pub fn new() -> Self {
        Handler {
            config: HttpConfig::default(),
        }
    }

    pub fn with_config(config: HttpConfig) -> Self {
        Handler { config }
    }
}

fn parse_basic_auth(header: &str) -> Option<(String, String)> {
    let prefix = "Basic ";
    if !header.starts_with(prefix) {
        return None;
    }
    let encoded = &header[prefix.len()..];
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let colon = decoded_str.find(':')?;
    let username = decoded_str[..colon].to_string();
    let password = decoded_str[colon + 1..].to_string();
    Some((username, password))
}

#[async_trait]
impl InboundHandler for Handler {
    async fn process(
        &self,
        session: Session,
        conn: Conn,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> ProxyResult<()> {
        let mut reader = BufReader::new(conn);
        let mut first_line = String::new();
        reader
            .read_line(&mut first_line)
            .await
            .map_err(|e| format!("http read request line: {}", e))?;

        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err("invalid HTTP request line".into());
        }

        let method = parts[0];
        let uri = parts[1];

        // Read headers
        let mut headers = Vec::new();
        loop {
            let mut header_line = String::new();
            reader
                .read_line(&mut header_line)
                .await
                .map_err(|e| format!("http read header: {}", e))?;
            if header_line == "\r\n" || header_line == "\n" || header_line.is_empty() {
                break;
            }
            headers.push(
                header_line
                    .trim_end_matches("\r\n")
                    .trim_end_matches('\n')
                    .to_string(),
            );
        }

        // Auth check
        if !self.config.accounts.is_empty() {
            let auth_header = headers
                .iter()
                .find(|h| h.to_lowercase().starts_with("proxy-authorization:"))
                .cloned();

            let authed = match auth_header {
                Some(h) => {
                    let value = h.split_once(':').map(|x| x.1).unwrap_or("").trim();
                    parse_basic_auth(value).is_some_and(|(u, p)| self.config.has_account(&u, &p))
                }
                None => false,
            };

            if !authed {
                let mut conn = reader.into_inner();
                let resp = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n";
                conn.write_all(resp)
                    .await
                    .map_err(|e| format!("http write 407: {}", e))?;
                return Err("auth required".into());
            }
        }

        if method.to_uppercase() != "CONNECT" {
            let mut conn = reader.into_inner();
            conn.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                .await
                .map_err(|e| format!("http write 405: {}", e))?;
            return Err(format!("unsupported method: {}", method));
        }

        // Parse host:port
        let uri_parts: Vec<&str> = uri.split(':').collect();
        if uri_parts.len() != 2 {
            let mut conn = reader.into_inner();
            conn.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                .await
                .map_err(|e| format!("http write 400: {}", e))?;
            return Err(format!("invalid CONNECT URI: {}", uri));
        }

        let host = uri_parts[0];
        let port_num: u16 = uri_parts[1]
            .parse()
            .map_err(|_| format!("invalid port: {}", uri_parts[1]))?;

        let address = ParseAddress(host);
        let dest = Destination {
            address,
            port: Port(port_num),
            network: Network::Tcp,
        };

        let mut conn = reader.into_inner();

        conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|e| format!("http reply 200: {}", e))?;

        let mut outbound_session = session.clone();
        outbound_session.outbound = Some(Outbound {
            target: dest.clone(),
            original_target: dest.clone(),
            route_target: None,
            tag: String::new(),
        });

        let link = dispatcher.dispatch(outbound_session, dest).await?;
        let mut link_stream = new_link_stream(link);

        tokio::io::copy_bidirectional(&mut conn, &mut link_stream)
            .await
            .map_err(|e| format!("http relay: {}", e))?;

        Ok(())
    }
}

impl Default for Handler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_auth_valid() {
        let creds = base64::engine::general_purpose::STANDARD.encode("user:pass");
        let header = format!("Basic {}", creds);
        let result = parse_basic_auth(&header);
        assert_eq!(result, Some(("user".into(), "pass".into())));
    }

    #[test]
    fn test_parse_basic_auth_no_prefix() {
        assert_eq!(parse_basic_auth("Bearer token"), None);
        assert_eq!(parse_basic_auth(""), None);
    }

    #[test]
    fn test_parse_basic_auth_invalid_base64() {
        assert_eq!(parse_basic_auth("Basic !!!invalid!!!"), None);
    }

    #[test]
    fn test_parse_basic_auth_no_colon() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("justuser");
        assert_eq!(parse_basic_auth(&format!("Basic {}", encoded)), None);
    }

    #[test]
    fn test_parse_basic_auth_empty_password() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:");
        let result = parse_basic_auth(&format!("Basic {}", encoded));
        assert_eq!(result, Some(("user".into(), "".into())));
    }

    #[test]
    fn test_http_config_has_account() {
        let mut cfg = HttpConfig::default();
        cfg.accounts.insert("alice".into(), "secret".into());
        assert!(cfg.has_account("alice", "secret"));
        assert!(!cfg.has_account("alice", "wrong"));
        assert!(!cfg.has_account("bob", "secret"));
    }

    #[test]
    fn test_http_config_no_accounts() {
        let cfg = HttpConfig::default();
        assert!(!cfg.has_account("any", "any"));
    }
}
