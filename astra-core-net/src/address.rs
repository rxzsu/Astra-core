use std::fmt;
use std::net::IpAddr;
use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
    Domain,
}

impl AddressFamily {
    pub fn is_ipv4(self) -> bool {
        matches!(self, AddressFamily::Ipv4)
    }
    pub fn is_ipv6(self) -> bool {
        matches!(self, AddressFamily::Ipv6)
    }
    pub fn is_ip(self) -> bool {
        matches!(self, AddressFamily::Ipv4 | AddressFamily::Ipv6)
    }
    pub fn is_domain(self) -> bool {
        matches!(self, AddressFamily::Domain)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Address {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Domain(String),
}

impl Address {
    pub fn family(&self) -> AddressFamily {
        match self {
            Address::Ipv4(_) => AddressFamily::Ipv4,
            Address::Ipv6(_) => AddressFamily::Ipv6,
            Address::Domain(_) => AddressFamily::Domain,
        }
    }

    pub fn as_ip(&self) -> Option<IpAddr> {
        match self {
            Address::Ipv4(b) => Some(IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
            Address::Ipv6(b) => {
                let arr = b.to_owned();
                Some(IpAddr::V6(std::net::Ipv6Addr::from(arr)))
            }
            Address::Domain(_) => None,
        }
    }

    pub fn as_domain(&self) -> Option<&str> {
        match self {
            Address::Domain(d) => Some(d.as_str()),
            _ => None,
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Ipv4(b) => write!(f, "{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
            Address::Ipv6(b) => {
                let addr = std::net::Ipv6Addr::from(*b);
                write!(f, "[{}]", addr)
            }
            Address::Domain(d) => write!(f, "{}", d),
        }
    }
}

pub fn IpAddress(ip: &[u8]) -> Address {
    match ip.len() {
        4 => {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(ip);
            Address::Ipv4(arr)
        }
        16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(ip);
            if arr[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
                let mut v4 = [0u8; 4];
                v4.copy_from_slice(&arr[12..16]);
                Address::Ipv4(v4)
            } else {
                Address::Ipv6(arr)
            }
        }
        _ => panic!("Invalid IP address length: {}", ip.len()),
    }
}

pub fn DomainAddress(domain: &str) -> Address {
    Address::Domain(domain.to_owned())
}

pub fn ParseAddress(addr: &str) -> Address {
    if let Some(inner) = addr.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
        && let Ok(v6) = inner.parse::<std::net::Ipv6Addr>()
    {
        return Address::Ipv6(v6.octets());
    }
    if let Ok(v4) = addr.parse::<std::net::Ipv4Addr>() {
        return Address::Ipv4(v4.octets());
    }
    if let Ok(v6) = addr.parse::<std::net::Ipv6Addr>() {
        return Address::Ipv6(v6.octets());
    }
    Address::Domain(addr.to_owned())
}

pub fn local_host_ip() -> &'static Address {
    static V: OnceLock<Address> = OnceLock::new();
    V.get_or_init(|| IpAddress(&[127, 0, 0, 1]))
}

pub fn any_ip() -> &'static Address {
    static V: OnceLock<Address> = OnceLock::new();
    V.get_or_init(|| IpAddress(&[0, 0, 0, 0]))
}

pub fn local_host_domain() -> &'static Address {
    static V: OnceLock<Address> = OnceLock::new();
    V.get_or_init(|| DomainAddress("localhost"))
}

pub fn local_host_ipv6() -> &'static Address {
    static V: OnceLock<Address> = OnceLock::new();
    V.get_or_init(|| IpAddress(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
}

pub fn any_ipv6() -> &'static Address {
    static V: OnceLock<Address> = OnceLock::new();
    V.get_or_init(|| IpAddress(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_address() {
        let addr = IpAddress(&[192, 168, 1, 1]);
        assert_eq!(addr.family(), AddressFamily::Ipv4);
        assert_eq!(addr.to_string(), "192.168.1.1");
        assert!(addr.family().is_ipv4());
        assert!(addr.family().is_ip());
        assert!(!addr.family().is_domain());
    }

    #[test]
    fn test_ipv6_address() {
        let addr = IpAddress(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(addr.family(), AddressFamily::Ipv6);
        assert!(addr.family().is_ip());
    }

    #[test]
    fn test_ipv4_mapped_ipv6() {
        let addr = IpAddress(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1]);
        assert_eq!(addr.family(), AddressFamily::Ipv4);
        assert_eq!(addr.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_domain_address() {
        let addr = DomainAddress("example.com");
        assert_eq!(addr.family(), AddressFamily::Domain);
        assert_eq!(addr.to_string(), "example.com");
        assert_eq!(addr.as_domain(), Some("example.com"));
        assert!(addr.as_ip().is_none());
    }

    #[test]
    fn test_parse_ipv4() {
        let addr = ParseAddress("10.0.0.1");
        assert_eq!(addr.family(), AddressFamily::Ipv4);
    }

    #[test]
    fn test_parse_ipv6_brackets() {
        let addr = ParseAddress("[::1]");
        assert_eq!(addr.family(), AddressFamily::Ipv6);
    }

    #[test]
    fn test_parse_domain() {
        let addr = ParseAddress("test.local");
        assert_eq!(addr.family(), AddressFamily::Domain);
    }
}
