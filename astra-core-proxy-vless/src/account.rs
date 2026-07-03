use astra_core_proto::{Account, ID};

/// VLESS flow constants.
pub const NONE: &str = "none";
pub const XRV: &str = "xtls-rprx-vision";

/// In-memory VLESS account, mirrors go's `proxy/vless.MemoryAccount`.
#[derive(Debug, Clone)]
pub struct MemoryAccount {
    pub id: ID,
    pub flow: String,
}

impl MemoryAccount {
    pub fn new(id: ID, flow: String) -> Self {
        MemoryAccount { id, flow }
    }
}

impl Account for MemoryAccount {
    fn equals(&self, other: &dyn Account) -> bool {
        if let Some(other) = other.as_any().downcast_ref::<MemoryAccount>() {
            self.id.uuid() == other.id.uuid()
        } else {
            false
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// ProcessUUID zeros out bytes [6..8] of the UUID as the lookup key.
/// Mirrors go's `proxy/vless.ProcessUUID`.
pub fn ProcessUUID(id: [u8; 16]) -> [u8; 16] {
    let mut out = id;
    out[6] = 0;
    out[7] = 0;
    out
}

/// Parse a UUID string like "66ad4540-b58c-4ad2-9926-ea63445a9b57".
pub fn parse_uuid(s: &str) -> Result<astra_core_proto::UUID, String> {
    let s = s.trim().replace('-', "");
    let bytes = hex_decode(&s)?;
    if bytes.len() != 16 {
        return Err(format!("invalid UUID length: {}", bytes.len()));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Ok(astra_core_proto::UUID(arr))
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd hex string length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uuid() {
        let u = parse_uuid("66ad4540-b58c-4ad2-9926-ea63445a9b57").unwrap();
        assert_eq!(u.0.len(), 16);
        assert_eq!(format!("{}", u), "66ad4540-b58c-4ad2-9926-ea63445a9b57");
    }

    #[test]
    fn test_process_uuid() {
        let id = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let processed = ProcessUUID(id);
        assert_eq!(processed[6], 0);
        assert_eq!(processed[7], 0);
        assert_eq!(processed[0], 0x00);
        assert_eq!(processed[15], 0x0f);
    }

    #[test]
    fn test_memory_account() {
        let uuid = parse_uuid("66ad4540-b58c-4ad2-9926-ea63445a9b57").unwrap();
        let id = ID::new(uuid);
        let acc = MemoryAccount::new(id, NONE.to_string());
        assert_eq!(acc.flow, NONE);

        let acc2 = MemoryAccount::new(id, XRV.to_string());
        assert!(acc.equals(&acc2)); // equals compares UUID only
    }
}
