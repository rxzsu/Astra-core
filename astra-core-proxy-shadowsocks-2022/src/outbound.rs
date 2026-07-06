use astra_core_net::Destination;
use astra_core_proxy::{async_trait, Dialer, OutboundHandler, ProxyResult, UdpLink};
use astra_core_session::Session;
use astra_core_transport::Link;

use crate::protocol::CipherType;

pub struct Handler {
    pub server_address: astra_core_net::Address,
    pub server_port: astra_core_net::Port,
    pub cipher: CipherType,
    pub key: Vec<u8>,
}

impl Handler {
    pub fn new(
        server_address: astra_core_net::Address,
        server_port: astra_core_net::Port,
        cipher: CipherType,
        key: Vec<u8>,
    ) -> Self {
        Handler { server_address, server_port, cipher, key }
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
        let dest = Destination {
            address: self.server_address.clone(),
            port: self.server_port,
            network: astra_core_net::Network::Tcp,
        };
        let mut remote = dialer.dial(session, dest).await?;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut rr, mut rw) = tokio::io::split(&mut *remote);

        let to_remote = async {
            let mut buf = [0u8; 16384];
            loop {
                match link.reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if rw.write_all(&buf[..n]).await.is_err() { break; }
                    }
                }
            }
            Ok::<_, String>(())
        };

        let to_client = async {
            let mut buf = [0u8; 16384];
            loop {
                match rr.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if link.writer.write_all(&buf[..n]).await.is_err() { break; }
                    }
                }
            }
            Ok::<_, String>(())
        };

        tokio::select! {
            r = to_remote => r?,
            r = to_client => r?,
        }
        Ok(())
    }

    async fn process_udp(&self, _s: Session, _l: &mut UdpLink) -> ProxyResult<()> {
        Err("ss2022 udp not implemented".into())
    }
}
