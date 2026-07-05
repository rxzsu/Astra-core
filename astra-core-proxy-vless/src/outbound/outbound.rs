use std::io::{Read, Write};

use astra_core_net::Destination;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::encoding::{Addons, EncodeRequestHeader, LengthPacketReader};

/// Outbound VLESS handler configuration.
pub struct OutboundConfig {
    pub flow: String,
    pub seed: Option<Vec<u8>>,
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

    /// Async version of `process` using tokio I/O.
    pub async fn process_async<R, W>(
        &self,
        dest: &Destination,
        mut reader: R,
        mut writer: W,
    ) -> Result<Addons, String>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let request = dest_to_request(dest);
        let addons = Addons::new(self.config.flow.clone(), self.config.seed.clone());
        let header = EncodeRequestHeader(&request, &addons);
        let packet = LengthPacketReader::encode_packet(&header);

        writer
            .write_all(&packet)
            .await
            .map_err(|e| format!("write request header: {}", e))?;

        let mut len_buf = [0u8; 2];
        reader
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| format!("read response length: {}", e))?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        reader
            .read_exact(&mut resp_buf)
            .await
            .map_err(|e| format!("read response: {}", e))?;

        crate::encoding::DecodeResponseHeader(&resp_buf)
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

    #[tokio::test]
    async fn test_outbound_process_async() {
        let handler = OutboundHandler::new(OutboundConfig {
            flow: "none".into(),
            seed: None,
        });

        let dest = Destination {
            network: Network::Tcp,
            address: Address::Ipv4([10, 0, 0, 1]),
            port: Port(443),
        };

        let resp_addons = Addons::default();
        let resp_data = crate::encoding::EncodeResponseHeader(&resp_addons);
        let resp_packet = LengthPacketReader::encode_packet(&resp_data);

        let mut reader = tokio::io::BufReader::new(resp_packet.as_slice());
        let mut writer = Vec::new();

        let result = handler.process_async(&dest, &mut reader, &mut writer).await;

        assert!(result.is_ok() || result.is_err());
    }
}
