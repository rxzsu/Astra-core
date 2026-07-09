use std::sync::Arc;

use crate::headers::{Account, MemoryUser};

/// Protobuf-style User. Mirrors go's `protocol.User`.
#[derive(Debug, Clone)]
pub struct User {
    pub level: u32,
    pub email: String,
    pub account: Option<Arc<dyn Account>>,
}

impl User {
    pub fn new(level: u32, email: String, account: Option<Arc<dyn Account>>) -> Self {
        User {
            level,
            email,
            account,
        }
    }

    /// Try to get a typed account reference.
    pub fn get_typed_account<T: Account + 'static>(&self) -> Option<&T> {
        self.account
            .as_ref()
            .and_then(|a| a.as_any().downcast_ref::<T>())
    }

    /// Convert to in-memory (cached) representation.
    pub fn to_memory_user(&self) -> MemoryUser {
        MemoryUser {
            email: self.email.clone(),
            level: self.level,
            account: None,
        }
    }
}

/// Convert a MemoryUser back to a User (protobuf form).
pub fn to_proto_user(mu: &MemoryUser) -> User {
    User {
        level: mu.level,
        email: mu.email.clone(),
        account: None,
    }
}
