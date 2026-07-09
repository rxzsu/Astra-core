use astra_core_net::{Address, Destination, Port};
use astra_core_proto::{MemoryUser, RequestCommand, RequestHeader, SecurityType};
use astra_core_proxy::Dialer;
use astra_core_proxy::{OutboundHandler as OutboundHandlerTrait, ProxyResult, async_trait};
use astra_core_session::Session;
use astra_core_transport::Link;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::encoding::client::ClientSession;

/// Outbound VMess handler configuration.
pub struct OutboundConfig {
    pub user: MemoryUser,
    pub address: Address,
    pub port: Port,
}

/// Outbound VMess handler.
/// Mirrors go's `proxy/vmess/outbound.Handler`.
pub struct OutboundHandler {
    pub config: OutboundConfig,
}

impl OutboundHandler {
    pub fn new(config: OutboundConfig) -> Self {
        OutboundHandler { config }
    }

    /// Build a request header for the outbound connection.
    pub fn build_request(&self, cmd_key: &[u8; 16], target: &Destination) -> Vec<u8> {
        let client = ClientSession::new();

        let command = match target.network {
            astra_core_net::Network::Udp => RequestCommand::Udp,
            _ => RequestCommand::Tcp,
        };

        let request = RequestHeader {
            version: 1,
            command,
            option: 0x01 | 0x04, // ChunkStream + ChunkMasking
            security: SecurityType::Aes128Gcm,
            port: target.port,
            address: target.address.clone(),
            user: Some(self.config.user.clone()),
        };

        client.EncodeRequestHeader(&request, cmd_key)
    }

    /// Handle a response command (stub — currently no-op).
    pub fn handle_command(&self, _dest: &Destination, _cmd: Option<Vec<u8>>) {
        // no-op
    }
}

/// VMess outbound handler that implements the `OutboundHandler` trait.
pub struct Handler {
    server: Destination,
    config: OutboundConfig,
}

impl Handler {
    pub fn new(server: Destination, config: OutboundConfig) -> Self {
        Handler { server, config }
    }
}

#[async_trait]
impl OutboundHandlerTrait for Handler {
    async fn process(
        &self,
        session: Session,
        link: &mut Link,
        dialer: &dyn Dialer,
    ) -> ProxyResult<()> {
        let target = session
            .outbound
            .as_ref()
            .map(|o| o.target.clone())
            .ok_or_else(|| "no target destination".to_string())?;

        let mut remote = dialer.dial(session, self.server.clone()).await?;
        let (mut remote_reader, mut remote_writer) = tokio::io::split(&mut *remote);

        let cmd_key = self
            .config
            .user
            .account
            .as_ref()
            .and_then(|a| a.as_any().downcast_ref::<crate::account::MemoryAccount>())
            .map(|acc| *acc.id.cmd_key())
            .unwrap_or([0u8; 16]);

        let client = ClientSession::new();
        let inner = OutboundHandler::new(OutboundConfig {
            user: self.config.user.clone(),
            address: self.config.address.clone(),
            port: self.config.port,
        });
        let request_bytes = inner.build_request(&cmd_key, &target);
        remote_writer
            .write_all(&request_bytes)
            .await
            .map_err(|e| format!("write vmess header: {}", e))?;

        let mut resp_buf = vec![0u8; 1024];
        let n = remote_reader
            .read(&mut resp_buf)
            .await
            .map_err(|e| format!("read vmess response: {}", e))?;
        resp_buf.truncate(n);
        client.DecodeResponseHeader(&resp_buf)?;

        let to_remote = tokio::io::copy(&mut link.reader, &mut remote_writer);
        let to_client = tokio::io::copy(&mut remote_reader, &mut link.writer);

        tokio::select! {
            r = to_remote => r.map(|_| ()),
            r = to_client => r.map(|_| ()),
        }
        .map_err(|e| format!("vmess copy: {}", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra_core_net::destination::TcpDestination;

    #[test]
    fn test_outbound_build_request() {
        let user = MemoryUser::new(0, "test@test.com".into(), None);
        let config = OutboundConfig {
            user,
            address: Address::Ipv4([192, 168, 1, 1]),
            port: Port(443),
        };
        let handler = OutboundHandler::new(config);
        let cmd_key = [0x42u8; 16];
        let dest = TcpDestination(Address::Ipv4([10, 0, 0, 1]), Port(80));
        let encoded = handler.build_request(&cmd_key, &dest);
        assert!(encoded.len() > 42);
    }
}
