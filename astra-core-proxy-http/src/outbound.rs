use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use astra_core_net::{Address, Destination, Network, Port};
use astra_core_proxy::{async_trait, AsyncConn, Dialer, OutboundHandler, ProxyResult};
use astra_core_session::Session;
use astra_core_transport::Link;

#[derive(Debug, Clone)]
pub struct HttpOutboundConfig {
    pub server_address: Address,
    pub server_port: Port,
    pub username: String,
    pub password: String,
}

pub struct Handler {
    config: HttpOutboundConfig,
}

impl Handler {
    pub fn new(config: HttpOutboundConfig) -> Self {
        Handler { config }
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    async fn process(
        &self,
        session: Session,
        link: &mut Link,
        dialer: &dyn Dialer,
    ) -> ProxyResult<()> {
        let target = session
            .outbound
            .as_ref()
            .ok_or_else(|| "no target".to_string())?
            .target
            .clone();

        if target.network == Network::Udp {
            return Err("UDP not supported by HTTP outbound".into());
        }

        let server_dest = Destination {
            address: self.config.server_address.clone(),
            port: self.config.server_port,
            network: Network::Tcp,
        };

        let mut remote: Box<dyn AsyncConn> = dialer.dial(session, server_dest).await?;
        // Don't split yet - do handshake first on the full conn
        let target_str = format!("{}:{}", target.address, target.port.value());

        let mut req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
            target_str, target_str
        );
        if !self.config.username.is_empty() {
            let auth = format!("{}:{}", self.config.username, self.config.password);
            let encoded = base64::engine::general_purpose::STANDARD.encode(auth);
            req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }
        req.push_str("Proxy-Connection: Keep-Alive\r\n\r\n");

        remote
            .write_all(req.as_bytes())
            .await
            .map_err(|e| format!("http connect write: {}", e))?;

        // Read response line + headers manually
        let mut buf = [0u8; 4096];
        let mut pos = 0;
        loop {
            let n = remote
                .read(&mut buf[pos..])
                .await
                .map_err(|e| format!("http read response: {}", e))?;
            if n == 0 {
                return Err("connection closed during handshake".into());
            }
            pos += n;

            let data = &buf[..pos];
            if let Some(hdr_end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                let status_line = std::str::from_utf8(
                    &data[..data[..hdr_end]
                        .iter()
                        .position(|&b| b == b'\r')
                        .unwrap_or(hdr_end)],
                )
                .map_err(|_| "invalid status line".to_string())?;
                if !status_line.contains("200") {
                    return Err("proxy rejected CONNECT request".into());
                }
                let remaining = pos - (hdr_end + 4);
                if remaining > 0 {
                    buf.copy_within(hdr_end + 4..pos, 0);
                }
                pos = remaining;
                break;
            }
        }

        // Now split for relay
        let (mut remote_r, mut remote_w) = tokio::io::split(&mut *remote);

        // Write any buffered remaining data to link writer
        if pos > 0 {
            link.writer
                .write_all(&buf[..pos])
                .await
                .map_err(|e| format!("write buffered data: {}", e))?;
        }

        let to_remote = tokio::io::copy(&mut link.reader, &mut remote_w);
        let to_local = tokio::io::copy(&mut remote_r, &mut link.writer);

        tokio::select! {
            r = to_remote => r.map(|_| ()),
            r = to_local => r.map(|_| ()),
        }
        .map_err(|e| format!("http outbound copy: {}", e))?;

        Ok(())
    }
}
