use std::sync::Arc;

use astra_core_net::Destination;
use astra_core_routing::Router;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Configuration for the Freedom outbound handler.
#[derive(Clone, Default)]
pub struct OutboundConfig {
    pub domain_strategy: String,
    pub redirect: Option<Destination>,
    pub router: Option<Arc<Router>>,
}

impl std::fmt::Debug for OutboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundConfig")
            .field("domain_strategy", &self.domain_strategy)
            .field("redirect", &self.redirect)
            .field("router", &self.router.as_ref().map(|_| "Some(Router)"))
            .finish()
    }
}

/// Freedom outbound handler — connects directly to the target and pipes data.
pub struct OutboundHandler {
    config: OutboundConfig,
}

impl OutboundHandler {
    pub fn new(config: OutboundConfig) -> Self {
        OutboundHandler { config }
    }

    pub fn route_target(&self, hint: &Destination) -> Destination {
        self.config
            .router
            .as_ref()
            .and_then(|r| r.route(&hint.address, hint.port.value()))
            .unwrap_or_else(|| hint.clone())
    }

    /// Connect to `dest` and pipe data bidirectionally with `stream`.
    pub async fn process_async<S>(
        &self,
        dest: &Destination,
        mut stream: S,
    ) -> Result<(), String>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let target = self.route_target(dest);
        let addr = format!("{}:{}", target.address, target.port.value());

        let mut remote = TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("freedom dial {}: {}", addr, e))?;

        tokio::io::copy_bidirectional(&mut stream, &mut remote)
            .await
            .map_err(|e| format!("freedom copy: {}", e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra_core_net::{Address, Port, TcpDestination};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_freedom_echo() {
        // Start an echo server as the target
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                stream.write_all(&buf[..n]).await.unwrap();
            }
        });

        // Start a listener for the "client" side
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();

        let dest = TcpDestination(Address::Ipv4([127, 0, 0, 1]), Port(echo_addr.port()));
        let handler = OutboundHandler::new(OutboundConfig::default());

        // Accept the client connection in the background
        let client_handle = tokio::spawn(async move {
            let (stream, _) = client_listener.accept().await.unwrap();
            handler.process_async(&dest, stream).await.unwrap();
        });

        // Connect as a client
        let mut client = TcpStream::connect(client_addr).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut buf = vec![0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        // Shutdown the write half so copy_bidirectional can unblock
        let _ = client.shutdown().await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), client_handle).await;
    }
}
