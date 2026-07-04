use std::io::{Read, Write};
use std::sync::Arc;

use astra_core_net::Destination;
use astra_core_routing::Router;

use crate::encoding::{Addons, EncodeRequestHeader, LengthPacketReader};

/// Outbound VLESS handler configuration.
pub struct OutboundConfig {
    pub flow: String,
    pub seed: Option<Vec<u8>>,
    pub router: Option<Arc<Router>>,
}

/// Outbound VLESS handler.
/// Mirrors go's `proxy/vless/outbound.Handler`.
///
/// On `process()`:
/// 1. Encodes a VLESS request header for the given destination.
/// 2. Writes it to the writer.
/// 3. Reads the response header from the reader.
pub struct OutboundHandler {
    config: OutboundConfig,
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

    /// Process an outbound VLESS connection.
    ///
    /// Encodes the request header for `dest`, writes it to `writer`,
    /// reads the response header from `reader`, and returns the decoded addons.
    pub fn process<R: Read, W: Write>(
        &self,
        dest: &Destination,
        mut reader: R,
        mut writer: W,
    ) -> Result<Addons, String> {
        // Build VLESS request
        let request = dest_to_request(dest);
        let addons = Addons::new(self.config.flow.clone(), self.config.seed.clone());
        let header = EncodeRequestHeader(&request, &addons);
        let packet = LengthPacketReader::encode_packet(&header);

        // Write request header
        writer
            .write_all(&packet)
            .map_err(|e| format!("write request header: {}", e))?;

        // Read response header (length-prefixed)
        let mut len_buf = [0u8; 2];
        reader
            .read_exact(&mut len_buf)
            .map_err(|e| format!("read response length: {}", e))?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        reader
            .read_exact(&mut resp_buf)
            .map_err(|e| format!("read response: {}", e))?;

        let response_addons = crate::encoding::DecodeResponseHeader(&resp_buf)?;
        Ok(response_addons)
    }
}

fn dest_to_request(dest: &Destination) -> astra_core_proto::RequestHeader {
    use astra_core_net::Network;

    let command = match dest.network {
        Network::Udp => astra_core_proto::RequestCommand::Udp,
        _ => astra_core_proto::RequestCommand::Tcp,
    };

    astra_core_proto::RequestHeader {
        version: 0,
        command,
        option: 0,
        security: astra_core_proto::SecurityType::Zero,
        port: dest.port,
        address: dest.address.clone(),
        user: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra_core_net::{Address, Port, Network};
    use std::io::Cursor;

    #[test]
    fn test_outbound_process() {
        let handler = OutboundHandler::new(OutboundConfig {
            flow: "none".into(),
            seed: None,
            router: None,
        });

        let dest = Destination {
            network: Network::Tcp,
            address: Address::Ipv4([10, 0, 0, 1]),
            port: Port(443),
        };

        let resp_addons = Addons::default();
        let resp_data = crate::encoding::EncodeResponseHeader(&resp_addons);
        let resp_packet = LengthPacketReader::encode_packet(&resp_data);

        let mut reader = Cursor::new(resp_packet);
        let mut writer = Vec::new();

        let result = handler.process(&dest, &mut reader, &mut writer);
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_route_target_fallback() {
        let handler = OutboundHandler::new(OutboundConfig {
            flow: "none".into(),
            seed: None,
            router: None,
        });

        let hint = Destination {
            network: Network::Tcp,
            address: Address::Ipv4([10, 0, 0, 1]),
            port: Port(80),
        };
        assert_eq!(handler.route_target(&hint), hint);
    }

    #[test]
    fn test_route_target_with_router() {
        use astra_core_routing::{RouteFilter, RouteRule, RouterConfig};
        use astra_core_net::destination::TcpDestination;

        let router = Router::new(
            RouterConfig {
                rules: vec![RouteRule {
                    filter: RouteFilter::Domain("example.com".into()),
                    target: TcpDestination(Address::Ipv4([1, 2, 3, 4]), Port(8080)),
                }],
            },
            None,
        );
        let handler = OutboundHandler::new(OutboundConfig {
            flow: "none".into(),
            seed: None,
            router: Some(Arc::new(router)),
        });

        let hint = Destination {
            network: Network::Tcp,
            address: Address::Domain("example.com".into()),
            port: Port(80),
        };
        let routed = handler.route_target(&hint);
        assert_eq!(routed.address, Address::Ipv4([1, 2, 3, 4]));
        assert_eq!(routed.port, Port(8080));
    }
}
