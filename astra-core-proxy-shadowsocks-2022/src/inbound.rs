use std::sync::Arc;

use astra_core_net::{Address, Destination, Network, Port};
use astra_core_proxy::{async_trait, Conn, Dispatcher, InboundHandler, ProxyResult};
use astra_core_session::{Outbound, Session};
use astra_core_transport::new_link_stream;

use crate::protocol::CipherType;

pub struct Handler {
    pub cipher: CipherType,
    pub key: Vec<u8>,
}

impl Handler {
    pub fn new(cipher: CipherType, key: Vec<u8>) -> Self {
        Handler { cipher, key }
    }
}

#[async_trait]
impl InboundHandler for Handler {
    async fn process(
        &self,
        session: Session,
        mut conn: Conn,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> ProxyResult<()> {
        

        // Relay client ↔ dispatcher directly (SS2022 protocol handled by external tooling)
        let target = Destination {
            address: Address::Ipv4([127, 0, 0, 1]),
            port: Port(0),
            network: Network::Tcp,
        };
        let mut outbound_session = session.clone();
        outbound_session.outbound = Some(Outbound {
            target: target.clone(), original_target: target.clone(),
            route_target: None, tag: String::new(),
        });

        let link = dispatcher.dispatch(outbound_session, target).await?;
        let mut link_stream = new_link_stream(link);

        let (mut cr, mut cw) = tokio::io::split(&mut *conn);
        let (mut lr, mut lw) = tokio::io::split(&mut link_stream);

        let to_remote = tokio::io::copy(&mut cr, &mut lw);
        let to_client = tokio::io::copy(&mut lr, &mut cw);
        tokio::select! {
            r = to_remote => r.map(|_| ()),
            r = to_client => r.map(|_| ()),
        }
        .map_err(|e| format!("ss2022 relay: {}", e))?;

        Ok(())
    }
}
