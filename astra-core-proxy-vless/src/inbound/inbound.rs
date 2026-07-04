use std::io::{Read, Write};

use astra_core_proto::RequestHeader;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::encoding::{Addons, DecodeRequestHeader, EncodeResponseHeader};
use crate::validator::Validator;

/// Inbound VLESS handler configuration.
pub struct InboundConfig<V: Validator + 'static> {
    pub validator: V,
}

/// Inbound VLESS handler.
/// Mirrors go's `proxy/vless/inbound.Handler`.
///
/// On `process()`:
/// 1. Reads a length-prefixed VLESS request header from the reader.
/// 2. Decodes the header (UUID, command, address, port, addons).
/// 3. Returns the decoded request information and writes a response header.
pub struct InboundHandler<V: Validator> {
    validator: V,
}

impl<V: Validator> InboundHandler<V> {
    pub fn new(config: InboundConfig<V>) -> Self {
        InboundHandler {
            validator: config.validator,
        }
    }

    /// Process an incoming VLESS connection.
    ///
    /// Reads the header from `reader`, validates the user, writes the response header
    /// to `writer`, and returns the decoded request information.
    pub fn process<R: Read, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
    ) -> Result<ProcessResult, String> {
        let mut len_buf = [0u8; 2];
        reader
            .read_exact(&mut len_buf)
            .map_err(|e| format!("read length prefix: {}", e))?;
        let header_len = u16::from_be_bytes(len_buf) as usize;

        let mut header_buf = vec![0u8; header_len];
        reader
            .read_exact(&mut header_buf)
            .map_err(|e| format!("read header: {}", e))?;

        let (request, addons) = DecodeRequestHeader(&header_buf, &self.validator)?;

        let response = EncodeResponseHeader(&addons);
        writer
            .write_all(&response)
            .map_err(|e| format!("write response header: {}", e))?;

        Ok(ProcessResult { request, addons })
    }

    /// Async version of `process` using tokio I/O.
    pub async fn process_async<R, W>(
        &self,
        mut reader: R,
        mut writer: W,
    ) -> Result<ProcessResult, String>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut len_buf = [0u8; 2];
        reader
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| format!("read length prefix: {}", e))?;
        let header_len = u16::from_be_bytes(len_buf) as usize;

        let mut header_buf = vec![0u8; header_len];
        reader
            .read_exact(&mut header_buf)
            .await
            .map_err(|e| format!("read header: {}", e))?;

        let (request, addons) = DecodeRequestHeader(&header_buf, &self.validator)?;

        let response = EncodeResponseHeader(&addons);
        writer
            .write_all(&response)
            .await
            .map_err(|e| format!("write response header: {}", e))?;

        Ok(ProcessResult { request, addons })
    }

    pub fn validator(&self) -> &V {
        &self.validator
    }
}

pub struct ProcessResult {
    pub request: RequestHeader,
    pub addons: Addons,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::MemoryAccount;
    use crate::encoding::{EncodeRequestHeader, LengthPacketReader};
    use astra_core_net::{Address, Port};
    use astra_core_proto::{ID, MemoryUser, RequestCommand, UUID};
    use std::sync::Arc;

    struct TestValidator;

    impl Validator for TestValidator {
        fn get(&self, _id: UUID) -> Option<MemoryUser> {
            let id = ID::new(UUID([0; 16]));
            Some(MemoryUser::new(0, "test@test.com".into(), Some(Arc::new(MemoryAccount::new(id, "none".into())))))
        }
        fn add(&mut self, _u: MemoryUser) -> Result<(), String> { Ok(()) }
        fn del(&mut self, _email: &str) -> bool { false }
        fn get_count(&self) -> usize { 1 }
    }

    #[test]
    fn test_inbound_process_tcp() {
        let handler = InboundHandler::new(InboundConfig { validator: TestValidator });

        let request = RequestHeader {
            version: 0,
            command: RequestCommand::Tcp,
            option: 0,
            security: astra_core_proto::SecurityType::Zero,
            port: Port(443),
            address: Address::Ipv4([10, 0, 0, 1]),
            user: None,
        };
        let addons = Addons::default();
        let header_data = EncodeRequestHeader(&request, &addons);
        let packet = LengthPacketReader::encode_packet(&header_data);

        let mut input = packet.as_slice();
        let mut output = Vec::new();

        let result = handler.process(&mut input, &mut output);
        assert!(result.is_ok());
        let pr = result.unwrap();
        assert_eq!(pr.request.command, RequestCommand::Tcp);
    }

    #[tokio::test]
    async fn test_inbound_process_async() {
        let handler = InboundHandler::new(InboundConfig { validator: TestValidator });

        let request = RequestHeader {
            version: 0,
            command: RequestCommand::Tcp,
            option: 0,
            security: astra_core_proto::SecurityType::Zero,
            port: Port(443),
            address: Address::Ipv4([10, 0, 0, 1]),
            user: None,
        };
        let addons = Addons::default();
        let header_data = EncodeRequestHeader(&request, &addons);
        let packet = LengthPacketReader::encode_packet(&header_data);

        let mut input = packet.as_slice();
        let mut output = Vec::new();

        let result = handler.process_async(&mut input, &mut output).await;
        assert!(result.is_ok());
        let pr = result.unwrap();
        assert_eq!(pr.request.command, RequestCommand::Tcp);
    }
}
