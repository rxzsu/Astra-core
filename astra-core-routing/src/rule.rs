//! Rule-based routing types.

use astra_core_net::{Address, Destination, Port};

/// Rule filter trait for custom routing rules.
pub trait RuleFilter: Send + Sync {
    fn matches(&self, addr: &Address, port: Port) -> bool;
}

/// Routing rule with filter and destination.
#[derive(Debug, Clone)]
pub struct Rule<F: RuleFilter> {
    filter: F,
    dest: Destination,
}

impl<F: RuleFilter> Rule<F> {
    pub fn new(filter: F, dest: Destination) -> Self {
        Rule { filter, dest }
    }

    pub fn matches(&self, addr: &Address, port: Port) -> bool {
        self.filter.matches(addr, port)
    }

    pub fn destination(&self) -> &Destination {
        &self.dest
    }
}

/// Simple address-based rule filter.
#[derive(Debug, Clone)]
pub struct AddrRule {
    target: Address,
}

impl AddrRule {
    pub fn new(target: Address) -> Self {
        AddrRule { target }
    }
}

impl RuleFilter for AddrRule {
    fn matches(&self, addr: &Address, _port: Port) -> bool {
        match addr {
            Address::Ipv4(o) => match &self.target {
                Address::Ipv4(t) => o == t,
                _ => false,
            },
            Address::Ipv6(o) => match &self.target {
                Address::Ipv6(t) => o == t,
                _ => false,
            },
            Address::Domain(d) => match &self.target {
                Address::Domain(t) => d == t,
                _ => false,
            },
        }
    }
}