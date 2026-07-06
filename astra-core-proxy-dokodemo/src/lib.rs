use std::sync::Arc;

use astra_core_net::{Address, Destination, Network, Port};
use astra_core_proxy::{async_trait, Conn, Dispatcher, InboundHandler, ProxyResult};
use astra_core_session::Session;
use astra_core_transport::new_link_stream;

#[derive(Debug, Clone, Default)]
pub struct InboundConfig {
    pub address: Option<Address>,
    pub port: u16,
    pub follow_redirect: bool,
    pub user_level: u32,
}

pub struct Handler {
    config: InboundConfig,
}

impl Handler {
    pub fn new(config: InboundConfig) -> Self {
        Handler { config }
    }

    fn resolve_dest(&self) -> Result<Destination, String> {
        if let Some(ref addr) = self.config.address {
            Ok(Destination {
                address: addr.clone(),
                port: Port(self.config.port),
                network: Network::Tcp,
            })
        } else if self.config.follow_redirect {
            Err("follow_redirect requires platform support (SO_ORIGINAL_DST)".into())
        } else {
            Err("dokodemo: no address/port configured".into())
        }
    }
}

#[async_trait]
impl InboundHandler for Handler {
    async fn process(
        &self,
        session: Session,
        conn: Conn,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> ProxyResult<()> {
        let dest = self.resolve_dest()?;
        let link = dispatcher.dispatch(session, dest).await?;
        let mut link_stream = new_link_stream(link);
        let mut conn = conn;

        tokio::io::copy_bidirectional(&mut *conn, &mut link_stream)
            .await
            .map_err(|e| format!("dokodemo copy: {}", e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dokodemo_resolve_config() {
        let config = InboundConfig {
            address: Some(Address::Ipv4([1, 2, 3, 4])),
            port: 8080,
            ..Default::default()
        };
        let handler = Handler::new(config);
        let dest = handler.resolve_dest().unwrap();
        assert_eq!(dest.address.to_string(), "1.2.3.4");
        assert_eq!(dest.port.value(), 8080);
    }
}
