//! Domain name handling and routing.

use astra_core_net::Address;

/// Domain filter for routing decisions.
#[derive(Debug, Clone)]
pub struct DomainFilter {
    domain: String,
}

impl DomainFilter {
    pub fn new(domain: String) -> Self {
        DomainFilter { domain }
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }
}

/// Domain type for routing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Domain {
    domain: String,
}

impl Domain {
    pub fn new(domain: String) -> Self {
        Domain { domain }
    }

    pub fn as_str(&self) -> &str {
        &self.domain
    }
}

impl From<&str> for Domain {
    fn from(s: &str) -> Self {
        Domain::new(s.to_string())
    }
}

impl From<String> for Domain {
    fn from(s: String) -> Self {
        Domain::new(s)
    }
}

impl AsRef<str> for Domain {
    fn as_ref(&self) -> &str {
        &self.domain
    }
}