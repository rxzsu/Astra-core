use astra_core_net::{Address, Port};
use astra_core_proto::{RequestCommand, RequestHeader, UUID};

use crate::encoding::addons::Addons;
use crate::validator::UserGetter;

/// VLESS protocol version byte.
pub const VERSION: u8 = 0;

/// Encode the VLESS request header into a buffer.
/// Mirrors go's `proxy/vless/encoding.EncodeRequestHeader`.
///
/// Format:
///   Version (1 byte, 0x00)
///   UUID (16 bytes)
///   Addons Length (1 byte)
///   Addons (L bytes)
///   Command (1 byte)
///   Port (2 bytes, big-endian) — only for TCP/UDP
///   Address Type (1 byte) — only for TCP/UDP
///   Address (N bytes) — only for TCP/UDP
pub fn EncodeRequestHeader(request: &RequestHeader, addons: &Addons) -> Vec<u8> {
    let mut buf = Vec::new();

    // Version
    buf.push(VERSION);

    // UUID — placeholder, in real impl would come from user.account
    buf.extend_from_slice(&[0u8; 16]);

    // Addons
    let addons_data = addons.encode();
    buf.extend_from_slice(&addons_data);

    // Command
    let cmd_byte = match request.command {
        RequestCommand::Tcp => 0x01u8,
        RequestCommand::Udp => 0x02u8,
        RequestCommand::Mux => 0x03u8,
        RequestCommand::Rvs => 0x04u8,
    };
    buf.push(cmd_byte);

    // Address + Port (only for TCP/UDP, not Mux/Rvs)
    match request.command {
        RequestCommand::Tcp | RequestCommand::Udp => {
            // Port (big-endian)
            buf.extend_from_slice(&request.port.value().to_be_bytes());

            // Address type and address
            encode_address(&request.address, &mut buf);
        }
        _ => {}
    }

    buf
}

/// Decode the VLESS request header from a buffer.
/// Mirrors go's `proxy/vless/encoding.DecodeRequestHeader`.
pub fn DecodeRequestHeader(
    data: &[u8],
    _getter: &dyn UserGetter,
) -> Result<(RequestHeader, Addons), String> {
    let mut offset = 0usize;

    // Version
    if data.is_empty() {
        return Err("empty request header".to_string());
    }
    let version = data[offset];
    if version != VERSION {
        return Err(format!("unsupported VLESS version: {}", version));
    }
    offset += 1;

    // UUID (16 bytes)
    if data.len() < offset + 16 {
        return Err("truncated UUID".to_string());
    }
    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(&data[offset..offset + 16]);
    let _uuid = UUID(uuid_bytes);
    offset += 16;

    // Addons Length
    if data.len() <= offset {
        return Err("truncated addons length".to_string());
    }
    let addons_len = data[offset] as usize;
    offset += 1;

    // Addons data
    let addons = if addons_len > 0 {
        if data.len() < offset + addons_len {
            return Err("truncated addons".to_string());
        }
        let decoded = Addons::decode(&data[offset - 1..offset + addons_len])?;
        offset += addons_len;
        decoded
    } else {
        Addons::default()
    };

    // Command
    if data.len() <= offset {
        return Err("truncated command".to_string());
    }
    let command = match data[offset] {
        0x01 => RequestCommand::Tcp,
        0x02 => RequestCommand::Udp,
        0x03 => RequestCommand::Mux,
        0x04 => RequestCommand::Rvs,
        _ => return Err(format!("unknown VLESS command: {}", data[offset])),
    };
    offset += 1;

    // Address + Port (only for TCP/UDP)
    let (address, port) = match command {
        RequestCommand::Tcp | RequestCommand::Udp => {
            if data.len() < offset + 2 {
                return Err("truncated port".to_string());
            }
            let port_val = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            let port = Port::from(port_val);

            let (addr, _consumed) = decode_address(&data[offset..])?;
            (addr, port)
        }
        _ => (Address::Ipv4([0; 4]), Port::from(0)),
    };

    let header = RequestHeader {
        version,
        command,
        option: 0,
        security: astra_core_proto::SecurityType::Zero,
        port,
        address,
        user: None,
    };

    Ok((header, addons))
}

/// Encode the VLESS response header.
/// Format:
///   Version (1 byte, 0x00)
///   Addons Length (1 byte)
///   Addons (L bytes)
pub fn EncodeResponseHeader(addons: &Addons) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(VERSION);
    let addons_data = addons.encode();
    buf.extend_from_slice(&addons_data);
    buf
}

/// Decode the VLESS response header.
pub fn DecodeResponseHeader(data: &[u8]) -> Result<Addons, String> {
    if data.is_empty() {
        return Err("empty response header".to_string());
    }

    let version = data[0];
    if version != VERSION {
        return Err(format!("unsupported VLESS response version: {}", version));
    }

    if data.len() < 2 {
        return Err("truncated addons length in response".to_string());
    }

    Addons::decode(&data[1..])
}

// ── Address encoding helpers ───────────────────────────────────────

fn encode_address(addr: &Address, buf: &mut Vec<u8>) {
    match addr {
        Address::Ipv4(octets) => {
            buf.push(0x01); // AddressTypeIPv4
            buf.extend_from_slice(octets);
        }
        Address::Domain(domain) => {
            buf.push(0x02); // AddressTypeDomain
            let d = domain.as_bytes();
            let len = d.len().min(255) as u8;
            buf.push(len);
            buf.extend_from_slice(&d[..len as usize]);
        }
        Address::Ipv6(octets) => {
            buf.push(0x03); // AddressTypeIPv6
            buf.extend_from_slice(octets);
        }
    }
}

fn decode_address(data: &[u8]) -> Result<(Address, usize), String> {
    if data.is_empty() {
        return Err("truncated address type".to_string());
    }

    let addr_type = data[0];
    let mut consumed = 1usize;

    let addr = match addr_type {
        0x01 => {
            // IPv4
            if data.len() < consumed + 4 {
                return Err("truncated IPv4 address".to_string());
            }
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&data[consumed..consumed + 4]);
            consumed += 4;
            Address::Ipv4(octets)
        }
        0x02 => {
            // Domain
            if data.len() <= consumed {
                return Err("truncated domain length".to_string());
            }
            let domain_len = data[consumed] as usize;
            consumed += 1;
            if data.len() < consumed + domain_len {
                return Err("truncated domain".to_string());
            }
            let domain =
                String::from_utf8_lossy(&data[consumed..consumed + domain_len]).to_string();
            consumed += domain_len;
            Address::Domain(domain)
        }
        0x03 => {
            // IPv6
            if data.len() < consumed + 16 {
                return Err("truncated IPv6 address".to_string());
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[consumed..consumed + 16]);
            consumed += 16;
            Address::Ipv6(octets)
        }
        _ => return Err(format!("unknown address type: {}", addr_type)),
    };

    Ok((addr, consumed))
}

/// Length-prefixed packet reader (2-byte big-endian length prefix).
pub struct LengthPacketReader;

impl LengthPacketReader {
    pub fn read_packet(data: &[u8]) -> Result<(&[u8], &[u8]), String> {
        if data.len() < 2 {
            return Err("truncated length prefix".to_string());
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + len {
            return Err("truncated packet".to_string());
        }
        Ok((&data[2..2 + len], &data[2 + len..]))
    }

    pub fn encode_packet(payload: &[u8]) -> Vec<u8> {
        let len = payload.len().min(u16::MAX as usize);
        let mut buf = Vec::with_capacity(2 + len);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
        buf.extend_from_slice(&payload[..len]);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::Validator;
    use astra_core_proto::MemoryUser;

    #[test]
    fn test_encode_decode_request_header_tcp() {
        let addr = astra_core_net::Address::Ipv4([10, 0, 0, 1]);
        let port = Port::from(80);
        let request = RequestHeader {
            version: 0,
            command: RequestCommand::Tcp,
            option: 0,
            security: astra_core_proto::SecurityType::Zero,
            port,
            address: addr,
            user: None,
        };
        let addons = Addons::default();

        let encoded = EncodeRequestHeader(&request, &addons);
        assert!(encoded.len() > 20);

        let (decoded, decoded_addons) = DecodeRequestHeader(&encoded, &MemoryValidator).unwrap();
        assert_eq!(decoded.version, 0);
        assert_eq!(decoded.command, RequestCommand::Tcp);
        assert_eq!(decoded.port.value(), 80);
        assert_eq!(decoded_addons.flow, "");
    }

    struct MemoryValidator;

    impl Validator for MemoryValidator {
        fn get(&self, _id: UUID) -> Option<MemoryUser> {
            None
        }
        fn add(&mut self, _u: MemoryUser) -> Result<(), String> {
            Ok(())
        }
        fn del(&mut self, _email: &str) -> bool {
            true
        }
        fn get_count(&self) -> usize {
            0
        }
    }

    #[test]
    fn test_encode_response_header() {
        let addons = Addons::new("xtls-rprx-vision".into(), None);
        let encoded = EncodeResponseHeader(&addons);
        let decoded = DecodeResponseHeader(&encoded).unwrap();
        assert_eq!(decoded.flow, "xtls-rprx-vision");
    }

    #[test]
    fn test_length_packet_reader() {
        let payload = b"hello";
        let packet = LengthPacketReader::encode_packet(payload);
        assert_eq!(packet.len(), 2 + 5);

        let (decoded, rest) = LengthPacketReader::read_packet(&packet).unwrap();
        assert_eq!(decoded, b"hello");
        assert!(rest.is_empty());
    }

    #[test]
    fn test_encode_decode_address_ipv4() {
        let addr = Address::Ipv4([192, 168, 1, 1]);
        let mut buf = Vec::new();
        encode_address(&addr, &mut buf);
        let (decoded, consumed) = decode_address(&buf).unwrap();
        assert_eq!(consumed, 5);
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_encode_decode_address_domain() {
        let addr = Address::Domain("example.com".into());
        let mut buf = Vec::new();
        encode_address(&addr, &mut buf);
        let (decoded, consumed) = decode_address(&buf).unwrap();
        assert_eq!(consumed, 13); // 1 + 1 + 11
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_encode_decode_address_ipv6() {
        let addr = Address::Ipv6([
            0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x68,
        ]);
        let mut buf = Vec::new();
        encode_address(&addr, &mut buf);
        let (decoded, consumed) = decode_address(&buf).unwrap();
        assert_eq!(consumed, 17);
        assert_eq!(decoded, addr);
    }
}
