//! IP address mask handling for routing.

use astra_core_net::Address;

/// IP mask for routing range matching.
#[derive(Debug, Clone)]
pub struct IpMask {
    network: [u8; 16],
    mask: [u8; 16],
}

impl IpMask {
    pub fn new(network: [u8; 16], mask: [u8; 16]) -> Self {
        IpMask { network, mask }
    }

    pub fn matches(&self, ip: &[u8]) -> bool {
        ip.iter()
            .zip(self.mask.iter())
            .zip(self.network.iter())
            .take(16)
            .all(|((&ip_b, &mask_b), &net_b)| (ip_b & mask_b) == (net_b & mask_b))
    }
}

/// IPv4 subnet mask (e.g., 24 for /24).
#[derive(Debug, Clone)]
pub struct IPv4Mask {
    ip: [u8; 4],
    prefix: u8,
}

impl IPv4Mask {
    pub fn new(ip: [u8; 4], prefix: u8) -> Self {
        IPv4Mask { ip, prefix }
    }

    pub fn contains(&self, addr: &Address) -> bool {
        match addr {
            Address::Ipv4(octets) => {
                let mask = ipv4_mask_bits(self.prefix);
                (octets[0] & mask[0]) == (self.ip[0] & mask[0])
                    && (octets[1] & mask[1]) == (self.ip[1] & mask[1])
                    && (octets[2] & mask[2]) == (self.ip[2] & mask[2])
                    && (octets[3] & mask[3]) == (self.ip[3] & mask[3])
            }
            _ => false,
        }
    }
}

fn ipv4_mask_bits(prefix: u8) -> [u8; 4] {
    let mut mask = [0u8; 4];
    for (i, m) in mask.iter_mut().enumerate() {
        let i8 = i as u8;
        *m = if prefix > 8 * (i8 + 1) {
            255
        } else if prefix < 8 * i8 {
            0
        } else {
            let remaining = prefix - 8 * i8;
            (((1u32 << remaining) - 1) as u8) << (8 - remaining)
        };
    }
    mask
}

#[derive(Debug, Clone)]
pub struct IPv6Mask {
    ip: [u8; 16],
    prefix: u8,
}

impl IPv6Mask {
    pub fn new(ip: [u8; 16], prefix: u8) -> Self {
        IPv6Mask { ip, prefix }
    }

    pub fn contains(&self, addr: &Address) -> bool {
        match addr {
            Address::Ipv6(octets) => {
                let partial = (self.prefix as usize).div_ceil(8);
                let full = (self.prefix as usize) / 8;
                for (i, (&o, &ip)) in octets.iter().zip(self.ip.iter()).enumerate().take(16) {
                    if i < full {
                        continue;
                    }
                    if i == partial && !self.prefix.is_multiple_of(8) {
                        let mask = 0xFFu8 << (self.prefix % 8);
                        if (o & mask) != (ip & mask) {
                            return false;
                        }
                    } else if o != ip {
                        return false;
                    }
                }
                true
            }
            _ => false,
        }
    }
}