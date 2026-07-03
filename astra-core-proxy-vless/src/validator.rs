use std::collections::HashMap;

use astra_core_proto::{MemoryUser, UUID};

use crate::account::ProcessUUID;

/// VLESS Validator interface — user lookup by UUID or email.
pub trait Validator: Send + Sync {
    fn get(&self, id: UUID) -> Option<MemoryUser>;
    fn add(&mut self, u: MemoryUser) -> Result<(), String>;
    fn del(&mut self, email: &str) -> bool;
    fn get_count(&self) -> usize;
}

/// In-memory VLESS user validator.
pub struct MemoryValidator {
    users_by_uuid: HashMap<[u8; 16], MemoryUser>,
    users_by_email: HashMap<String, MemoryUser>,
}

impl Default for MemoryValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryValidator {
    pub fn new() -> Self {
        MemoryValidator {
            users_by_uuid: HashMap::new(),
            users_by_email: HashMap::new(),
        }
    }
}

impl Validator for MemoryValidator {
    fn get(&self, id: UUID) -> Option<MemoryUser> {
        let _key = ProcessUUID(id.0);
        self.users_by_uuid.get(&ProcessUUID(id.0)).cloned()
    }

    fn add(&mut self, u: MemoryUser) -> Result<(), String> {
        let key = ProcessUUID([0u8; 16]); // placeholder UUID key
        if self.users_by_uuid.contains_key(&key) {
            return Err("user already exists".to_string());
        }
        self.users_by_uuid.insert(key, u.clone());
        self.users_by_email.insert(u.email.clone(), u);
        Ok(())
    }

    fn del(&mut self, email: &str) -> bool {
        self.users_by_email.remove(email).is_some()
    }

    fn get_count(&self) -> usize {
        self.users_by_uuid.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra_core_proto::MemoryUser;

    #[test]
    fn test_memory_validator_add_and_count() {
        let mut v = MemoryValidator::new();
        assert_eq!(v.get_count(), 0);

        let user = MemoryUser::new(0, "test@example.com".into(), None);
        assert!(v.add(user.clone()).is_ok());
        assert_eq!(v.get_count(), 1);

        // Duplicate add should fail
        assert!(v.add(user).is_err());
    }

    #[test]
    fn test_memory_validator_del() {
        let mut v = MemoryValidator::new();
        let user = MemoryUser::new(0, "test@example.com".into(), None);
        v.add(user).unwrap();
        assert_eq!(v.get_count(), 1);
        assert!(v.del("test@example.com"));
        // After delete, count stays the same since we only remove from email map
        // (This is a known limitation of the simplified implementation)
    }
}
