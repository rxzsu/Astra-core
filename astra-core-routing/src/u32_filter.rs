//! U32-based filter for efficient routing lookups.

use astra_core_net::{Address, Port};
use super::rule::RuleFilter;

/// U32-based filter for IPv4 address matching.
#[derive(Debug, Clone)]
pub struct U32Filter {
    value: u32,
}

impl U32Filter {
    pub fn new(value: u32) -> Self {
        U32Filter { value }
    }

    pub fn from_ipv4(octets: [u8; 4]) -> Self {
        U32Filter {
            value: u32::from_be_bytes(octets),
        }
    }
}

impl RuleFilter for U32Filter {
    fn matches(&self, addr: &Address, _port: Port) -> bool {
        match addr {
            Address::Ipv4(o) => u32::from_be_bytes(*o) == self.value,
            _ => false,
        }
    }
}