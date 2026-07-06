use std::sync::Arc;

use astra_core_net::Destination;
use astra_core_proto::{RequestCommand, MemoryUser};
use astra_core_proxy::{async_trait, Conn, Dispatcher, InboundHandler, ProxyResult};
use astra_core_session::{Outbound, Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::aead::authid::DecodeAuthID;
use crate::aead::encrypt::OpenVMessAEADHeader;
use crate::encoding::server::{ServerSession, SessionHistory};

/// Inbound VMess handler configuration.
pub struct InboundConfig {
    pub users: Vec<MemoryUser>,
}

/// Inbound VMess handler — implements the proxy `InboundHandler` trait.
pub struct Handler {
    users: Vec<MemoryUser>,
}

impl Handler {
    pub fn new(config: InboundConfig) -> Self {
        Handler {
            users: config.users,
        }
    }

    fn find_user(&self, auth_id: &[u8; 16]) -> Option<[u8; 16]> {
        for user in &self.users {
            if let Some(acc) = user.account.as_ref() {
                if let Some(macc) = acc.as_any().downcast_ref::<crate::account::MemoryAccount>() {
                    let cmd_key = *macc.id.cmd_key();
                    if DecodeAuthID(&cmd_key, auth_id).is_ok() {
                        return Some(cmd_key);
                    }
                }
            }
        }
        None
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

        let mut auth_id = [0u8; 16];
        reader.read_exact(&mut auth_id).await
            .map_err(|e| format!("read auth id: {}", e))?;

        let cmd_key = self.find_user(&auth_id)
            .ok_or_else(|| "no matching user for auth id".to_string())?;

        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = reader.read(&mut tmp).await
                .map_err(|e| format!("read header data: {}", e))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            // Try to parse — OpenVMessAEADHeader will validate the full structure
            if let Ok((_, _, _)) = OpenVMessAEADHeader(&cmd_key, &auth_id, &buf) {
                break;
            }
            if buf.len() > 65536 {
                return Err("header too large".to_string());
            }
        }

        let mut server = ServerSession::new(SessionHistory::new());
        let request = server.DecodeRequestHeader(&auth_id, &buf, &cmd_key)
            .map_err(|e| format!("decode request: {}", e))?;

        let response_header = server.EncodeResponseHeader(0, None);
        writer.write_all(&response_header).await
            .map_err(|e| format!("write response: {}", e))?;

        let target = Destination {
            network: match request.command {
                RequestCommand::Udp => astra_core_net::Network::Udp,
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
        .map_err(|e| format!("vmess inbound copy: {}", e))?;

        Ok(())
    }
}

