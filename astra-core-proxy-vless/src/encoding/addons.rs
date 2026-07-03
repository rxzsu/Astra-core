/// VLESS Header Addons — mirrors go's `proxy/vless/encoding.Addons`.
#[derive(Debug, Clone, Default)]
pub struct Addons {
    pub flow: String,
    pub seed: Option<Vec<u8>>,
}

impl Addons {
    pub fn new(flow: String, seed: Option<Vec<u8>>) -> Self {
        Addons { flow, seed }
    }

    /// Encode addons into a buffer (protobuf-like length-prefixed format).
    pub fn encode(&self) -> Vec<u8> {
        if self.flow.is_empty() && self.seed.is_none() {
            // Length 0
            return vec![0x00];
        }

        let flow_bytes = self.flow.as_bytes();
        let seed_bytes = self.seed.as_deref().unwrap_or(&[]);

        // Simple encoding: length byte + flow_len byte + flow + seed_len byte + seed
        let mut buf = Vec::new();
        buf.push(0x01); // addons length (always 1+ for now)

        // protobuf-like field: flow is field 1, string
        // We use a simple encoding for the Rust port
        let flow_len = flow_bytes.len().min(255) as u8;
        let seed_len = seed_bytes.len().min(255) as u8;

        buf.push(flow_len);
        buf.extend_from_slice(&flow_bytes[..flow_len as usize]);
        buf.push(seed_len);
        buf.extend_from_slice(&seed_bytes[..seed_len as usize]);

        buf
    }

    /// Decode addons from a buffer.
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.is_empty() {
            return Ok(Addons::default());
        }

        let addons_len = data[0] as usize;
        if addons_len == 0 {
            return Ok(Addons::default());
        }

        if data.len() < 1 + addons_len {
            return Err("truncated addons data".to_string());
        }

        let mut offset = 1;
        let flow_len = data[offset] as usize;
        offset += 1;
        let flow = if flow_len > 0 && offset + flow_len <= data.len() {
            String::from_utf8_lossy(&data[offset..offset + flow_len]).to_string()
        } else {
            String::new()
        };
        offset += flow_len;

        let seed = if offset < data.len() {
            let seed_len = data[offset] as usize;
            if seed_len > 0 && offset + 1 + seed_len <= data.len() {
                Some(data[offset + 1..offset + 1 + seed_len].to_vec())
            } else {
                None
            }
        } else {
            None
        };

        Ok(Addons { flow, seed })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addons_empty() {
        let a = Addons::default();
        let encoded = a.encode();
        let decoded = Addons::decode(&encoded).unwrap();
        assert_eq!(decoded.flow, "");
        assert!(decoded.seed.is_none());
    }

    #[test]
    fn test_addons_with_flow() {
        let a = Addons::new("xtls-rprx-vision".into(), None);
        let encoded = a.encode();
        let decoded = Addons::decode(&encoded).unwrap();
        assert_eq!(decoded.flow, "xtls-rprx-vision");
        assert!(decoded.seed.is_none());
    }

    #[test]
    fn test_addons_with_seed() {
        let a = Addons::new("".into(), Some(vec![0x01, 0x02, 0x03]));
        let encoded = a.encode();
        let decoded = Addons::decode(&encoded).unwrap();
        assert!(decoded.flow.is_empty());
        assert_eq!(decoded.seed, Some(vec![0x01, 0x02, 0x03]));
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
