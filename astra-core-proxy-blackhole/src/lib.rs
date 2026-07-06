use astra_core_proxy::{async_trait, Dialer, OutboundHandler, ProxyResult, UdpLink};
use astra_core_session::Session;
use astra_core_transport::Link;

/// Blackhole outbound — discards all traffic silently.
pub struct Handler;

impl Handler {
    pub fn new() -> Self {
        Handler
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    async fn process(
        &self,
        _session: Session,
        link: &mut Link,
        _dialer: &dyn Dialer,
    ) -> ProxyResult<()> {
        // Read and discard all data from the client
        let mut buf = [0u8; 16384];
        loop {
            match tokio::io::AsyncReadExt::read(&mut link.reader, &mut buf).await {
                Ok(0) | Err(_) => break,
                _ => {}
            }
        }
        Ok(())
    }

    async fn process_udp(&self, _session: Session, link: &mut UdpLink) -> ProxyResult<()> {
        // Discard all UDP packets
        while link.recv().await.is_some() {}
        Ok(())
    }
}
