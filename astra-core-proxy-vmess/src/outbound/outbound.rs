use std::sync::Arc;

use astra_core_proto::{MemoryUser, RequestCommand, RequestHeader, SecurityType};
use astra_core_net::{Address, Destination, Port};
use astra_core_routing::Router;

use crate::encoding::client::ClientSession;

/// Outbound VMess handler configuration.
pub struct OutboundConfig {
    pub user: MemoryUser,
    pub address: Address,
    pub port: Port,
    pub router: Option<Arc<Router>>,
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

    /// Resolve the target destination using the router, falling back to the given hint.
    pub fn route_target(&self, hint: &Destination) -> Destination {
        self.config
            .router
            .as_ref()
            .and_then(|r| r.route(&hint.address, hint.port.value()))
            .unwrap_or_else(|| hint.clone())
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

#[cfg(test)]
mod tests {
    use super::*;
    use astra_core_net::destination::TcpDestination;
    use astra_core_routing::{RouteFilter, RouteRule, RouterConfig};
    use std::sync::Arc;

    #[test]
    fn test_outbound_build_request() {
        let user = MemoryUser::new(0, "test@test.com".into(), None);
        let config = OutboundConfig {
            user,
            address: Address::Ipv4([192, 168, 1, 1]),
            port: Port(443),
            router: None,
        };
        let handler = OutboundHandler::new(config);
        let cmd_key = [0x42u8; 16];
        let dest = TcpDestination(Address::Ipv4([10, 0, 0, 1]), Port(80));
        let encoded = handler.build_request(&cmd_key, &dest);
        assert!(encoded.len() > 42);
    }

    #[test]
    fn test_route_target_with_router() {
        let user = MemoryUser::new(0, "test@test.com".into(), None);
        let router = Router::new(
            RouterConfig {
                rules: vec![RouteRule {
                    filter: RouteFilter::Domain("example.com".into()),
                    target: TcpDestination(Address::Ipv4([1, 2, 3, 4]), Port(8080)),
                }],
            },
            None,
        );
        let config = OutboundConfig {
            user,
            address: Address::Ipv4([192, 168, 1, 1]),
            port: Port(443),
            router: Some(Arc::new(router)),
        };
        let handler = OutboundHandler::new(config);

        let hint = TcpDestination(
            Address::Domain("example.com".into()),
            Port(80),
        );
        let routed = handler.route_target(&hint);
        assert_eq!(routed.address, Address::Ipv4([1, 2, 3, 4]));
        assert_eq!(routed.port, Port(8080));
    }

    #[test]
    fn test_route_target_fallback() {
        let user = MemoryUser::new(0, "test@test.com".into(), None);
        let config = OutboundConfig {
            user,
            address: Address::Ipv4([192, 168, 1, 1]),
            port: Port(443),
            router: None,
        };
        let handler = OutboundHandler::new(config);

        let hint = TcpDestination(Address::Ipv4([10, 0, 0, 1]), Port(80));
        let routed = handler.route_target(&hint);
        assert_eq!(routed, hint);
    }
}
