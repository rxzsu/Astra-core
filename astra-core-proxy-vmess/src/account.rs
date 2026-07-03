use astra_core_proto::{Account, ID, SecurityType};

/// In-memory VMess account, mirrors go's `proxy/vmess.MemoryAccount`.
#[derive(Debug, Clone)]
pub struct MemoryAccount {
    pub id: ID,
    pub security: SecurityType,
    pub authenticated_length_experiment: bool,
    pub no_termination_signal: bool,
}

impl MemoryAccount {
    pub fn new(
        id: ID,
        security: SecurityType,
        authenticated_length_experiment: bool,
        no_termination_signal: bool,
    ) -> Self {
        MemoryAccount {
            id,
            security,
            authenticated_length_experiment,
            no_termination_signal,
        }
    }
}

impl Account for MemoryAccount {
    fn equals(&self, other: &dyn Account) -> bool {
        if let Some(other) = other.as_any().downcast_ref::<MemoryAccount>() {
            self.id.uuid() == other.id.uuid() && self.security == other.security
        } else {
            false
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Parse tests_enabled string like "AuthenticatedLength|NoTerminationSignal".
pub fn parse_tests_enabled(s: &str) -> (bool, bool) {
    let auth_len = s.contains("AuthenticatedLength");
    let no_term = s.contains("NoTerminationSignal");
    (auth_len, no_term)
}

/// Create a `MemoryAccount` from a protobuf-style Account.
pub fn from_proto_account(
    id_str: &str,
    security: SecurityType,
    tests_enabled: &str,
) -> Result<MemoryAccount, String> {
    let uuid = parse_uuid(id_str)?;
    let id = ID::new(uuid);
    let (auth_len, no_term) = parse_tests_enabled(tests_enabled);
    Ok(MemoryAccount::new(id, security, auth_len, no_term))
}

/// Parse a UUID string like "66ad4540-b58c-4ad2-9926-ea63445a9b57".
pub fn parse_uuid(s: &str) -> Result<astra_core_proto::UUID, String> {
    let s = s.trim();
    let s = s.replace('-', "");
    let bytes = hex::decode(&s)?;
    if bytes.len() != 16 {
        return Err(format!("invalid UUID length: {}", bytes.len()));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Ok(astra_core_proto::UUID(arr))
}

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("odd hex string length".to_string());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uuid() {
        let u = parse_uuid("66ad4540-b58c-4ad2-9926-ea63445a9b57").unwrap();
        assert_eq!(u.0.len(), 16);
        let s = format!("{}", u);
        assert_eq!(s, "66ad4540-b58c-4ad2-9926-ea63445a9b57");
    }

    #[test]
    fn test_parse_tests_enabled() {
        assert_eq!(parse_tests_enabled(""), (false, false));
        assert_eq!(parse_tests_enabled("AuthenticatedLength"), (true, false));
        assert_eq!(parse_tests_enabled("NoTerminationSignal"), (false, true));
        assert_eq!(
            parse_tests_enabled("AuthenticatedLength|NoTerminationSignal"),
            (true, true)
        );
    }

    #[test]
    fn test_memory_account() {
        let uuid = parse_uuid("66ad4540-b58c-4ad2-9926-ea63445a9b57").unwrap();
        let id = ID::new(uuid);
        let acc = MemoryAccount::new(id, SecurityType::Aes128Gcm, true, false);
        assert_eq!(acc.security, SecurityType::Aes128Gcm);
        assert!(acc.authenticated_length_experiment);
        assert!(!acc.no_termination_signal);

        let acc2 = MemoryAccount::new(id, SecurityType::Aes128Gcm, true, false);
        assert!(acc.equals(&acc2));
    }

    #[test]
    fn test_account_not_equals_different_security() {
        let uuid = parse_uuid("66ad4540-b58c-4ad2-9926-ea63445a9b57").unwrap();
        let id = ID::new(uuid);
        let a = MemoryAccount::new(id, SecurityType::Aes128Gcm, false, false);
        let b = MemoryAccount::new(id, SecurityType::ChaCha20Poly1305, false, false);
        assert!(!a.equals(&b)); // different security types → not equal
    }
}
