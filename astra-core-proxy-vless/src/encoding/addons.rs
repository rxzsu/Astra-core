/// VLESS Header Addons — protobuf wire format compatible with Go.
///
/// Go uses proto: message Addons { string Flow = 1; bytes Seed = 2; }
/// Wire format (protobuf):
///   Field 1 (Flow, string):  tag=0x0a, varint_len, utf8_bytes
///   Field 2 (Seed, bytes):   tag=0x12, varint_len, raw_bytes
#[derive(Debug, Clone, Default)]
pub struct Addons {
    pub flow: String,
    pub seed: Option<Vec<u8>>,
}

impl Addons {
    pub fn new(flow: String, seed: Option<Vec<u8>>) -> Self {
        Addons { flow, seed }
    }

    /// Encode addons as protobuf bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        if !self.flow.is_empty() {
            let flow_bytes = self.flow.as_bytes();
            buf.push(0x0a);
            encode_varint(&mut buf, flow_bytes.len() as u64);
            buf.extend_from_slice(flow_bytes);
        }
        if let Some(ref seed) = self.seed {
            if !seed.is_empty() {
                buf.push(0x12);
                encode_varint(&mut buf, seed.len() as u64);
                buf.extend_from_slice(seed);
            }
        }
        buf
    }

    /// Decode addons from protobuf bytes.
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut flow = String::new();
        let mut seed: Option<Vec<u8>> = None;
        let mut offset = 0;
        while offset < data.len() {
            let tag = data[offset];
            offset += 1;
            match tag {
                0x0a => {
                    let len = decode_varint(data, &mut offset)?;
                    if offset + len > data.len() {
                        return Err("truncated addons flow".into());
                    }
                    flow = String::from_utf8_lossy(&data[offset..offset + len]).to_string();
                    offset += len;
                }
                0x12 => {
                    let len = decode_varint(data, &mut offset)?;
                    if offset + len > data.len() {
                        return Err("truncated addons seed".into());
                    }
                    seed = Some(data[offset..offset + len].to_vec());
                    offset += len;
                }
                _ => break,
            }
        }
        Ok(Addons { flow, seed })
    }
}

fn encode_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        if value < 0x80 {
            buf.push(value as u8);
            break;
        }
        buf.push((value as u8) | 0x80);
        value >>= 7;
    }
}

fn decode_varint(data: &[u8], offset: &mut usize) -> Result<usize, String> {
    let mut result = 0u64;
    let mut shift = 0;
    loop {
        if *offset >= data.len() {
            return Err("truncated varint".into());
        }
        let byte = data[*offset] as u64;
        *offset += 1;
        result |= (byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err("varint too long".into());
        }
    }
    Ok(result as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addons_empty() {
        let a = Addons::default();
        let encoded = a.encode();
        assert!(encoded.is_empty());
        let decoded = Addons::decode(&encoded).unwrap();
        assert_eq!(decoded.flow, "");
        assert!(decoded.seed.is_none());
    }

    #[test]
    fn test_addons_with_flow() {
        let a = Addons::new("xtls-rprx-vision".into(), None);
        let encoded = a.encode();
        assert!(!encoded.is_empty());
        assert_eq!(encoded[0], 0x0a);
        let decoded = Addons::decode(&encoded).unwrap();
        assert_eq!(decoded.flow, "xtls-rprx-vision");
        assert!(decoded.seed.is_none());
    }

    #[test]
    fn test_addons_roundtrip() {
        let a = Addons::new("xtls-rprx-vision".into(), Some(vec![0xab; 16]));
        let encoded = a.encode();
        let decoded = Addons::decode(&encoded).unwrap();
        assert_eq!(decoded.flow, "xtls-rprx-vision");
        assert_eq!(decoded.seed, Some(vec![0xab; 16]));
    }
}
