use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Generate a unique context ID for tracing/ logging.
/// Go equivalent: `common/ctx.Context()`
pub fn new_id() -> u64 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

/// Context ID wrapper for propagation through the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContextId(u64);

impl ContextId {
    pub fn new() -> Self {
        ContextId(new_id())
    }

    pub fn value(&self) -> u64 {
        self.0
    }
}

impl Default for ContextId {
    fn default() -> Self {
        ContextId::new()
    }
}

impl std::fmt::Display for ContextId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_id_unique() {
        let id1 = ContextId::new();
        let id2 = ContextId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_new_id_increment() {
        let a = new_id();
        let b = new_id();
        assert!(b > a);
    }
}
