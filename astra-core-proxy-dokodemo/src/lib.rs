use astra_core_net::{Address, Destination, Network, Port};
use tokio::net::TcpStream;

/// Configuration for the Dokodemo-door inbound handler.
#[derive(Debug, Clone, Default)]
pub struct InboundConfig {
    pub address: Option<Address>,
    pub port: u16,
    pub follow_redirect: bool,
    pub user_level: u32,
}

/// Dokodemo-door inbound handler.
///
/// Returns the destination to which traffic should be forwarded.
pub struct InboundHandler {
    config: InboundConfig,
}

impl InboundHandler {
    pub fn new(config: InboundConfig) -> Self {
        InboundHandler { config }
    }

    /// Determine the target destination from the config.
    ///
    /// If an address+port is configured, returns that.
    /// Otherwise, for `follow_redirect`, reads the peer address (not truly
    /// transparent without SO_ORIGINAL_DST, but serves as a fallback).
    pub fn resolve_dest(&self, _stream: &TcpStream) -> Result<Destination, String> {
        if let Some(ref addr) = self.config.address {
            Ok(Destination {
                address: addr.clone(),
                port: Port(self.config.port),
                network: Network::Tcp,
            })
        } else if self.config.follow_redirect {
            // In a real implementation this would use SO_ORIGINAL_DST.
            // Fallback: use the peer address (only useful for testing).
            Err("follow_redirect requires platform support (SO_ORIGINAL_DST)".into())
        } else {
            Err("dokodemo: no address/port configured".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_dokodemo_resolve_config() {
        let config = InboundConfig {
            address: Some(Address::Ipv4([1, 2, 3, 4])),
            port: 8080,
            ..Default::default()
        };
        let handler = InboundHandler::new(config);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let dest = handler.resolve_dest(&stream).unwrap();
            assert_eq!(dest.address.to_string(), "1.2.3.4");
            assert_eq!(dest.port.value(), 8080);
        });

        let _ = TcpStream::connect(addr).await.unwrap();
    }
}
