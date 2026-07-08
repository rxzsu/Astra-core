/// XUDP protocol-specific UDP extensions.
/// Go equivalent: `common/xudp`
/// Used for Xray-specific UDP proxying behavior.

/// XUDP packet header with additional metadata.
#[derive(Debug, Clone)]
pub struct XudpPacket {
    pub session_id: u16,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub total_fragments: u8,
    pub data: Vec<u8>,
}

impl XudpPacket {
    pub fn new(data: Vec<u8>) -> Self {
        XudpPacket {
            session_id: 0,
            packet_id: 0,
            fragment_id: 0,
            total_fragments: 1,
            data,
        }
    }

    /// Encode the XUDP header into a byte buffer.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(7 + self.data.len());
        buf.extend_from_slice(&self.session_id.to_be_bytes());
        buf.extend_from_slice(&self.packet_id.to_be_bytes());
        buf.push(self.fragment_id);
        buf.push(self.total_fragments);
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Decode an XUDP packet from raw bytes.
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < 6 {
            return Err("xudp packet too short".into());
        }
        let session_id = u16::from_be_bytes([data[0], data[1]]);
        let packet_id = u16::from_be_bytes([data[2], data[3]]);
        let fragment_id = data[4];
        let total_fragments = data[5];
        let payload = data[6..].to_vec();
        Ok(XudpPacket {
            session_id,
            packet_id,
            fragment_id,
            total_fragments,
            data: payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xudp_roundtrip() {
        let pkt = XudpPacket {
            session_id: 1,
            packet_id: 2,
            fragment_id: 0,
            total_fragments: 1,
            data: vec![10, 20, 30],
        };
        let encoded = pkt.encode();
        let decoded = XudpPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.session_id, 1);
        assert_eq!(decoded.packet_id, 2);
        assert_eq!(decoded.data, vec![10, 20, 30]);
    }

    #[test]
    fn test_xudp_short_data() {
        assert!(XudpPacket::decode(&[0; 3]).is_err());
    }
}
