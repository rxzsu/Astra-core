use std::sync::Arc;

use astra_core_net::Destination;
use astra_core_proxy::{Conn, Dispatcher, InboundHandler, ProxyResult, async_trait};
use astra_core_session::{Outbound, Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::encoding::{DecodeRequestHeader, EncodeResponseHeader};
use crate::validator::UserGetter;

/// Inbound VLESS handler — implements the proxy `InboundHandler` trait.
pub struct Handler {
    getter: Arc<dyn UserGetter>,
}

impl Handler {
    pub fn new(getter: Arc<dyn UserGetter>) -> Self {
        Handler { getter }
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
        let (mut reader, mut writer) = tokio::io::split(conn);

        let mut len_buf = [0u8; 2];
        reader
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| format!("read vless length: {}", e))?;
        let header_len = u16::from_be_bytes(len_buf) as usize;

        let mut header_buf = vec![0u8; header_len];
        reader
            .read_exact(&mut header_buf)
            .await
            .map_err(|e| format!("read vless header: {}", e))?;

        let (request, addons) = DecodeRequestHeader(&header_buf, self.getter.as_ref())?;

        let response = EncodeResponseHeader(&addons);
        writer
            .write_all(&response)
            .await
            .map_err(|e| format!("write vless response: {}", e))?;

        let target = Destination {
            network: match request.command {
                astra_core_proto::RequestCommand::Udp => astra_core_net::Network::Udp,
                _ => astra_core_net::Network::Tcp,
            },
            address: request.address,
            port: request.port,
        };

        let mut outbound_session = session.clone();
        outbound_session.outbound = Some(Outbound {
            target: target.clone(),
            original_target: target.clone(),
            route_target: None,
            tag: String::new(),
        });

        let mut inbound_link = dispatcher.dispatch(outbound_session, target).await?;

        let to_remote = tokio::io::copy(&mut reader, &mut inbound_link.writer);
        let to_client = tokio::io::copy(&mut inbound_link.reader, &mut writer);

        tokio::select! {
            r = to_remote => r.map(|_| ()),
            r = to_client => r.map(|_| ()),
        }
        .map_err(|e| format!("vless inbound copy: {}", e))?;

        Ok(())
    }
}
