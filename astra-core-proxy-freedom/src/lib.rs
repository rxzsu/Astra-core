use astra_core_net::Destination;
use astra_core_proxy::{async_trait, Dialer, OutboundHandler, ProxyResult};
use astra_core_session::Session;
use astra_core_transport::Link;

/// Configuration for the Freedom outbound handler.
#[derive(Clone, Default)]
pub struct OutboundConfig {
    pub domain_strategy: String,
    pub redirect: Option<Destination>,
}

impl std::fmt::Debug for OutboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundConfig")
            .field("domain_strategy", &self.domain_strategy)
            .field("redirect", &self.redirect)
            .finish()
    }
}

pub struct Handler {
    config: OutboundConfig,
}

impl Handler {
    pub fn new(config: OutboundConfig) -> Self {
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
        let hint = session
            .outbound
            .as_ref()
            .map(|o| &o.target)
            .ok_or_else(|| "no target destination".to_string())?;

        let target = self.config.redirect.clone().unwrap_or_else(|| hint.clone());
        let mut remote = dialer.dial(session, target).await?;

        let (mut remote_reader, mut remote_writer) = tokio::io::split(&mut remote);

        let to_remote = tokio::io::copy(&mut link.reader, &mut remote_writer);
        let to_client = tokio::io::copy(&mut remote_reader, &mut link.writer);

        tokio::select! {
            r = to_remote => r.map(|_| ()),
            r = to_client => r.map(|_| ()),
        }
        .map_err(|e| format!("freedom copy: {}", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra_core_net::{Address, Port, TcpDestination};
    use astra_core_proxy::{AsyncConn, Dialer};
    use astra_core_session::Outbound;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct TestDialer;

    #[async_trait]
    impl Dialer for TestDialer {
        async fn dial(
            &self,
            _session: Session,
            dest: Destination,
        ) -> ProxyResult<Box<dyn AsyncConn>> {
            let addr = format!("{}:{}", dest.address, dest.port.value());
            let stream = tokio::net::TcpStream::connect(&addr)
                .await
                .map_err(|e| format!("dial {}: {}", addr, e))?;
            Ok(Box::new(stream))
        }
    }

    #[tokio::test]
    async fn test_freedom_echo() {
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

        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();

        let dest = TcpDestination(Address::Ipv4([127, 0, 0, 1]), Port(echo_addr.port()));
        let handler = Handler::new(OutboundConfig::default());

        let client_handle = tokio::spawn(async move {
            let (conn, _) = client_listener.accept().await.unwrap();
            // Create link pair and pipe conn with inbound_link
            let (mut inbound_link, mut outbound_link) = astra_core_transport::new_link_pair();

            // Pipe: conn ↔ inbound_link (simulating what a dispatcher does)
            let pipe_handle = tokio::spawn(async move {
                let (mut conn_reader, mut conn_writer) = tokio::io::split(conn);
                let to_outbound = tokio::io::copy(&mut conn_reader, &mut inbound_link.writer);
                let to_inbound = tokio::io::copy(&mut inbound_link.reader, &mut conn_writer);
                tokio::select! {
                    r = to_outbound => r.map(|_| ()),
                    r = to_inbound => r.map(|_| ()),
                }
            });

            let session = Session {
                inbound: None,
                outbound: Some(Outbound {
                    target: dest.clone(),
                    original_target: dest.clone(),
                    route_target: None,
                    tag: String::new(),
                }),
                content: None,
            };
            let dialer = TestDialer;
            handler.process(session, &mut outbound_link, &dialer).await.unwrap();
            let _ = pipe_handle.await;
        });

        let mut client = tokio::net::TcpStream::connect(client_addr).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut buf = vec![0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        let _ = client.shutdown().await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), client_handle).await;
    }
}
