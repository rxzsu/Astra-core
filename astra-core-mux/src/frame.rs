use astra_core_net::destination::{TcpDestination, UdpDestination};
use astra_core_net::{Address, Destination, Network, Port};
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Session status byte in mux frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    New = 0x01,
    Keep = 0x02,
    End = 0x03,
    KeepAlive = 0x04,
}

impl SessionStatus {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(SessionStatus::New),
            0x02 => Some(SessionStatus::Keep),
            0x03 => Some(SessionStatus::End),
            0x04 => Some(SessionStatus::KeepAlive),
            _ => None,
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Option flags in mux frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameOption(u8);

impl FrameOption {
    pub const DATA: u8 = 0x01;
    pub const ERROR: u8 = 0x02;

    pub fn new() -> Self {
        FrameOption(0)
    }

    pub fn set(&mut self, bit: u8) {
        self.0 |= bit;
    }

    pub fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    pub fn as_byte(self) -> u8 {
        self.0
    }

    pub fn from_byte(b: u8) -> Self {
        FrameOption(b)
    }
}

impl Default for FrameOption {
    fn default() -> Self {
        FrameOption::new()
    }
}

/// Target network byte in mux frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetNetwork {
    Tcp = 0x01,
    Udp = 0x02,
}

impl TargetNetwork {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(TargetNetwork::Tcp),
            0x02 => Some(TargetNetwork::Udp),
            _ => None,
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Inbound source/local metadata carried in mux frames.
#[derive(Debug, Clone, Default)]
pub struct MuxInbound {
    pub source: Option<Destination>,
    pub local: Option<Destination>,
}

/// Decoded mux frame metadata.
///
/// Wire format:
/// ```text
/// [2 bytes] total_metadata_len
///   [2 bytes] session_id
///   [1 byte]  status
///   [1 byte]  option
///   [variable: target, inbound, global_id]
/// [2 bytes] data_len (if OptionData)
/// [N bytes] data
/// ```
#[derive(Debug, Clone)]
pub struct FrameMetadata {
    pub session_id: u16,
    pub status: SessionStatus,
    pub option: FrameOption,
    pub target: Option<Destination>,
    pub inbound: Option<MuxInbound>,
    pub global_id: [u8; 8],
}

impl FrameMetadata {
    pub fn new(session_id: u16, status: SessionStatus) -> Self {
        FrameMetadata {
            session_id,
            status,
            option: FrameOption::new(),
            target: None,
            inbound: None,
            global_id: [0u8; 8],
        }
    }

    pub fn has_data(&self) -> bool {
        self.option.has(FrameOption::DATA)
    }

    pub fn has_error(&self) -> bool {
        self.option.has(FrameOption::ERROR)
    }

    /// Encode metadata into `BytesMut`.
    /// Writes: session_id(2) + status(1) + option(1) + target + inbound + global_id.
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.session_id);
        buf.put_u8(self.status.as_byte());
        buf.put_u8(self.option.as_byte());

        if self.status == SessionStatus::New {
            if let Some(ref target) = self.target {
                match target.network {
                    Network::Tcp => buf.put_u8(TargetNetwork::Tcp as u8),
                    Network::Udp => buf.put_u8(TargetNetwork::Udp as u8),
                    _ => buf.put_u8(TargetNetwork::Tcp as u8),
                }
                encode_address_port(target, buf);
            }

            if let Some(ref inbound) = self.inbound {
                if let Some(ref source) = inbound.source
                    && (source.network == Network::Tcp || source.network == Network::Udp)
                {
                    let net_byte = if source.network == Network::Tcp {
                        0u8
                    } else {
                        1u8
                    };
                    buf.put_u8(net_byte);
                    encode_address_port(source, buf);
                }
                if let Some(ref local) = inbound.local
                    && (local.network == Network::Tcp || local.network == Network::Udp)
                {
                    let net_byte = if local.network == Network::Tcp {
                        0u8
                    } else {
                        1u8
                    };
                    buf.put_u8(net_byte);
                    encode_address_port(local, buf);
                }
            } else if target_is_udp(self.target.as_ref()) && self.global_id != [0u8; 8] {
                buf.put_slice(&self.global_id);
            }
        }
    }

    /// Decode metadata from a buffer containing just the metadata bytes.
    pub fn decode(buf: &[u8], read_source_and_local: bool) -> Result<(Self, usize), String> {
        if buf.len() < 4 {
            return Err("insufficient buffer for mux frame metadata".into());
        }

        let session_id = u16::from_be_bytes([buf[0], buf[1]]);
        let status = SessionStatus::from_byte(buf[2])
            .ok_or_else(|| format!("unknown session status: {}", buf[2]))?;
        let option = FrameOption::from_byte(buf[3]);

        let mut meta = FrameMetadata {
            session_id,
            status,
            option,
            target: None,
            inbound: None,
            global_id: [0u8; 8],
        };

        let mut offset = 4usize;

        if status == SessionStatus::New {
            if buf.len() < offset + 1 {
                return Err("truncated: missing target network".into());
            }
            let net_byte = TargetNetwork::from_byte(buf[offset])
                .ok_or_else(|| format!("unknown target network: {}", buf[offset]))?;
            offset += 1;

            let (dest, consumed) = decode_address_port(&buf[offset..], net_byte)?;
            meta.target = Some(dest);
            offset += consumed;

            if read_source_and_local && offset < buf.len() {
                let net_byte = buf[offset];
                if net_byte != 0 {
                    offset += 1;
                    let src_net_byte = if net_byte == 0 {
                        TargetNetwork::Tcp
                    } else {
                        TargetNetwork::Udp
                    };
                    let (src_dest, consumed) = decode_address_port(&buf[offset..], src_net_byte)?;
                    let mut inbound = MuxInbound {
                        source: Some(src_dest),
                        local: None,
                    };
                    offset += consumed;

                    if offset < buf.len() {
                        let net_byte = buf[offset];
                        if net_byte != 0 {
                            offset += 1;
                            let loc_net_byte = if net_byte == 0 {
                                TargetNetwork::Tcp
                            } else {
                                TargetNetwork::Udp
                            };
                            let (loc_dest, consumed) =
                                decode_address_port(&buf[offset..], loc_net_byte)?;
                            inbound.local = Some(loc_dest);
                            offset += consumed;
                        }
                    }
                    meta.inbound = Some(inbound);
                }
            }

            if meta
                .target
                .as_ref()
                .is_some_and(|t| t.network == Network::Udp)
                && meta.option.has(FrameOption::DATA)
                && buf.len() >= offset + 8
            {
                let mut gid = [0u8; 8];
                gid.copy_from_slice(&buf[offset..offset + 8]);
                meta.global_id = gid;
                offset += 8;
            }
        } else if status == SessionStatus::Keep && offset < buf.len() {
            let net_byte = buf[offset];
            if let Some(tn) = TargetNetwork::from_byte(net_byte)
                && tn == TargetNetwork::Udp
            {
                offset += 1;
                let (dest, consumed) = decode_address_port(&buf[offset..], tn)?;
                meta.target = Some(dest);
                offset += consumed;
            }
        }

        Ok((meta, offset))
    }
}

fn target_is_udp(target: Option<&Destination>) -> bool {
    target.is_some_and(|t| t.network == Network::Udp)
}

/// Encode address+port in mux format: port(2) + addr_type(1) + addr_bytes.
fn encode_address_port(target: &Destination, buf: &mut BytesMut) {
    match &target.address {
        Address::Ipv4(o) => {
            buf.put_u16(target.port.value());
            buf.put_u8(1);
            buf.put_slice(o);
        }
        Address::Domain(d) => {
            buf.put_u16(target.port.value());
            buf.put_u8(2);
            let b = d.as_bytes();
            buf.put_u8(b.len().min(255) as u8);
            buf.put_slice(&b[..b.len().min(255)]);
        }
        Address::Ipv6(o) => {
            buf.put_u16(target.port.value());
            buf.put_u8(3);
            buf.put_slice(o);
        }
    }
}

/// Decode address+port from mux format: port(2) + addr_type(1) + addr_bytes.
fn decode_address_port(
    data: &[u8],
    network: TargetNetwork,
) -> Result<(Destination, usize), String> {
    if data.len() < 3 {
        return Err("truncated: need at least port(2) + addr_type(1)".into());
    }
    let port = Port(u16::from_be_bytes([data[0], data[1]]));
    let addr_type = data[2];
    let mut consumed = 3usize;

    let address = match addr_type {
        1 => {
            if data.len() < consumed + 4 {
                return Err("truncated IPv4 address".into());
            }
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&data[consumed..consumed + 4]);
            consumed += 4;
            Address::Ipv4(octets)
        }
        2 => {
            if data.len() < consumed + 1 {
                return Err("truncated domain length".into());
            }
            let domain_len = data[consumed] as usize;
            consumed += 1;
            if data.len() < consumed + domain_len {
                return Err("truncated domain".into());
            }
            let domain =
                String::from_utf8_lossy(&data[consumed..consumed + domain_len]).to_string();
            consumed += domain_len;
            Address::Domain(domain)
        }
        3 => {
            if data.len() < consumed + 16 {
                return Err("truncated IPv6 address".into());
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[consumed..consumed + 16]);
            consumed += 16;
            Address::Ipv6(octets)
        }
        _ => return Err(format!("unknown address type: {}", addr_type)),
    };

    let dest = match network {
        TargetNetwork::Tcp => TcpDestination(address, port),
        TargetNetwork::Udp => UdpDestination(address, port),
    };

    Ok((dest, consumed))
}

/// Encode a complete mux frame (metadata + optional data) into BytesMut.
pub fn encode_frame(meta: &FrameMetadata, data: Option<&[u8]>) -> BytesMut {
    let mut meta_buf = BytesMut::new();
    meta.encode(&mut meta_buf);

    let total_meta_len = meta_buf.len() as u16;

    let mut frame = BytesMut::new();
    frame.put_u16(total_meta_len);
    frame.put_slice(&meta_buf);

    if let Some(data) = data {
        frame.put_u16(data.len() as u16);
        frame.put_slice(data);
    }

    frame
}

/// Read a complete mux frame from an async reader.
pub async fn read_frame<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(FrameMetadata, Option<Vec<u8>>), String> {
    let mut len_buf = [0u8; 2];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("read meta len: {}", e))?;
    let meta_len = u16::from_be_bytes(len_buf) as usize;

    let mut meta_buf = vec![0u8; meta_len];
    reader
        .read_exact(&mut meta_buf)
        .await
        .map_err(|e| format!("read meta: {}", e))?;

    let (meta, _consumed) = FrameMetadata::decode(&meta_buf, false)?;

    let data = if meta.has_data() {
        let mut data_len_buf = [0u8; 2];
        reader
            .read_exact(&mut data_len_buf)
            .await
            .map_err(|e| format!("read data len: {}", e))?;
        let data_len = u16::from_be_bytes(data_len_buf) as usize;
        let mut data_buf = vec![0u8; data_len];
        reader
            .read_exact(&mut data_buf)
            .await
            .map_err(|e| format!("read data: {}", e))?;
        Some(data_buf)
    } else {
        None
    };

    Ok((meta, data))
}

pub async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    meta: &FrameMetadata,
    data: Option<&[u8]>,
) -> Result<(), String> {
    let frame = encode_frame(meta, data);
    writer
        .write_all(&frame)
        .await
        .map_err(|e| format!("write mux frame: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_metadata_new_tcp_roundtrip() {
        let dest = TcpDestination(Address::Ipv4([10, 0, 0, 1]), Port(443));
        let meta = FrameMetadata {
            session_id: 1,
            status: SessionStatus::New,
            option: FrameOption::new(),
            target: Some(dest),
            inbound: None,
            global_id: [0u8; 8],
        };

        let mut buf = BytesMut::new();
        meta.encode(&mut buf);

        let (decoded, _consumed) = FrameMetadata::decode(&buf, false).unwrap();
        assert_eq!(decoded.session_id, 1);
        assert_eq!(decoded.status, SessionStatus::New);
        assert_eq!(
            decoded.target.as_ref().unwrap().address,
            Address::Ipv4([10, 0, 0, 1])
        );
        assert_eq!(decoded.target.as_ref().unwrap().port, Port(443));
        assert_eq!(decoded.target.as_ref().unwrap().network, Network::Tcp);
    }

    #[test]
    fn test_frame_metadata_new_udp_roundtrip() {
        let dest = UdpDestination(Address::Domain("example.com".into()), Port(53));
        let meta = FrameMetadata {
            session_id: 42,
            status: SessionStatus::New,
            option: FrameOption::new(),
            target: Some(dest),
            inbound: None,
            global_id: [0u8; 8],
        };

        let mut buf = BytesMut::new();
        meta.encode(&mut buf);

        let (decoded, _consumed) = FrameMetadata::decode(&buf, false).unwrap();
        assert_eq!(decoded.session_id, 42);
        assert_eq!(decoded.status, SessionStatus::New);
        assert_eq!(
            decoded.target.as_ref().unwrap().address,
            Address::Domain("example.com".into())
        );
        assert_eq!(decoded.target.as_ref().unwrap().port, Port(53));
        assert_eq!(decoded.target.as_ref().unwrap().network, Network::Udp);
    }

    #[test]
    fn test_frame_metadata_end() {
        let meta = FrameMetadata {
            session_id: 7,
            status: SessionStatus::End,
            option: FrameOption::new(),
            target: None,
            inbound: None,
            global_id: [0u8; 8],
        };

        let mut buf = BytesMut::new();
        meta.encode(&mut buf);

        let (decoded, _consumed) = FrameMetadata::decode(&buf, false).unwrap();
        assert_eq!(decoded.session_id, 7);
        assert_eq!(decoded.status, SessionStatus::End);
        assert!(decoded.target.is_none());
    }

    #[test]
    fn test_frame_metadata_keepalive() {
        let meta = FrameMetadata::new(0, SessionStatus::KeepAlive);
        let mut buf = BytesMut::new();
        meta.encode(&mut buf);
        let (decoded, _consumed) = FrameMetadata::decode(&buf, false).unwrap();
        assert_eq!(decoded.status, SessionStatus::KeepAlive);
    }

    #[test]
    fn test_encode_frame_roundtrip() {
        let dest = TcpDestination(Address::Ipv4([192, 168, 1, 1]), Port(8080));
        let meta = FrameMetadata {
            session_id: 5,
            status: SessionStatus::New,
            option: {
                let mut o = FrameOption::new();
                o.set(FrameOption::DATA);
                o
            },
            target: Some(dest),
            inbound: None,
            global_id: [0u8; 8],
        };
        let data = b"hello mux";

        let frame = encode_frame(&meta, Some(data));

        let meta_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
        assert!(meta_len > 0);

        let (decoded_meta, _) = FrameMetadata::decode(&frame[2..2 + meta_len], false).unwrap();
        assert_eq!(decoded_meta.session_id, 5);
        assert_eq!(decoded_meta.status, SessionStatus::New);
        assert_eq!(
            decoded_meta.target.as_ref().unwrap().address,
            Address::Ipv4([192, 168, 1, 1])
        );

        let data_offset = 2 + meta_len;
        assert!(frame.len() >= data_offset + 2);
        let data_len = u16::from_be_bytes([frame[data_offset], frame[data_offset + 1]]) as usize;
        assert_eq!(data_len, data.len());
        assert_eq!(&frame[data_offset + 2..data_offset + 2 + data_len], data);
    }
}
