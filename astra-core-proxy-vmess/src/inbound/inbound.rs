use crate::encoding::server::{ServerSession, SessionHistory};
use astra_core_proto::{MemoryUser, RequestHeader};

/// Inbound VMess handler configuration.
pub struct InboundConfig {
    pub users: Vec<MemoryUser>,
}

/// Inbound VMess handler.
/// Mirrors go's `proxy/vmess/inbound.Handler`.
pub struct InboundHandler {
    pub session_history: SessionHistory,
    pub users: Vec<MemoryUser>,
}

impl InboundHandler {
    pub fn new(config: InboundConfig) -> Self {
        InboundHandler {
            session_history: SessionHistory::new(),
            users: config.users,
        }
    }

    /// Process an incoming VMess connection.
    /// Returns the decoded request header and the data flow direction.
    pub fn process(
        &mut self,
        auth_id: &[u8; 16],
        encrypted_header: &[u8],
        cmd_key: &[u8; 16],
    ) -> Result<ProcessResult, String> {
        let mut server = ServerSession::new(SessionHistory::new());
        let request = server.DecodeRequestHeader(auth_id, encrypted_header, cmd_key)?;

        Ok(ProcessResult {
            request,
            response_header: server.EncodeResponseHeader(0, None),
        })
    }

    pub fn network(&self) -> Vec<astra_core_net::Network> {
        vec![astra_core_net::Network::Tcp]
    }
}

pub struct ProcessResult {
    pub request: RequestHeader,
    pub response_header: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::client::ClientSession;
    use astra_core_proto::{RequestCommand, SecurityType};
    use astra_core_net::Port;

    #[test]
    fn test_inbound_process() {
        let client = ClientSession::new();
        let cmd_key = [0x42u8; 16];
        let header = RequestHeader {
            version: 1,
            command: RequestCommand::Tcp,
            option: 0x01,
            security: SecurityType::Aes128Gcm,
            port: Port(443),
            address: astra_core_net::Address::Ipv4([10, 0, 0, 1]),
            user: None,
        };

        let encoded = client.EncodeRequestHeader(&header, &cmd_key);
        let auth_id = &encoded[..16];
        let mut auth_id_arr = [0u8; 16];
        auth_id_arr.copy_from_slice(auth_id);

        let mut handler = InboundHandler::new(InboundConfig { users: vec![] });
        let result = handler.process(&auth_id_arr, &encoded[16..], &cmd_key).unwrap();
        assert_eq!(result.request.command, RequestCommand::Tcp);
        assert!(result.response_header.len() > 18);
    }
}
