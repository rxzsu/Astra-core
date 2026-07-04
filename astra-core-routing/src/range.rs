//! IP range handling for routing.

use astra_core_net::Address;

/// IPv4 address range (start..=end).
#[derive(Debug, Clone)]
pub struct IPv4Range {
    start: [u8; 4],
    end: [u8; 4],
}

impl IPv4Range {
    pub fn new(start: [u8; 4], end: [u8; 4]) -> Self {
        IPv4Range { start, end }
    }

    pub fn contains(&self, addr: &Address) -> bool {
        match addr {
            Address::Ipv4(octets) => {
                u32::from_be_bytes(*octets) >= u32::from_be_bytes(self.start)
                    && u32::from_be_bytes(*octets) <= u32::from_be_bytes(self.end)
            }
            _ => false,
        }
    }
}

/// IPv6 address range.
#[derive(Debug, Clone)]
pub struct IPv6Range {
    start: [u8; 16],
    end: [u8; 16],
}

impl IPv6Range {
    pub fn new(start: [u8; 16], end: [u8; 16]) -> Self {
        IPv6Range { start, end }
    }

    pub fn contains(&self, addr: &Address) -> bool {
        match addr {
            Address::Ipv6(octets) => {
                // Simple byte-by-byte comparison (for full ranges)
                octets >= &self.start && octets <= &self.end
            }
            _ => false,
        }
    }
}

/// Range filter for routing decisions.
#[derive(Debug, Clone)]
pub struct RangeFilter {
    ranges: Vec<IPv4Range>,
}

impl RangeFilter {
    pub fn new() -> Self {
        RangeFilter { ranges: Vec::new() }
    }

    pub fn add_range(&mut self, range: IPv4Range) {
        self.ranges.push(range);
    }

    pub fn matches(&self, addr: &Address) -> bool {
        self.ranges.iter().any(|r| r.contains(addr))
    }
}