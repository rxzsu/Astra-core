use std::fmt;

use crate::address::{Address, ParseAddress};
use crate::network::Network;
use crate::port::Port;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Destination {
    pub address: Address,
    pub port: Port,
    pub network: Network,
}

impl Destination {
    pub fn net_addr(&self) -> String {
        match self.network {
            Network::Unix => self.address.to_string(),
            _ => format!("{}:{}", self.address, self.port),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.network != Network::Unknown
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.network {
            Network::Tcp => write!(f, "tcp:{}:{}", self.address, self.port),
            Network::Udp => write!(f, "udp:{}:{}", self.address, self.port),
            Network::Unix => write!(f, "unix:{}", self.address),
            Network::Unknown => write!(f, "unknown:{}:{}", self.address, self.port),
        }
    }
}

pub fn TcpDestination(address: Address, port: Port) -> Destination {
    Destination {
        address,
        port,
        network: Network::Tcp,
    }
}

pub fn UdpDestination(address: Address, port: Port) -> Destination {
    Destination {
        address,
        port,
        network: Network::Udp,
    }
}

pub fn UnixDestination(address: Address) -> Destination {
    Destination {
        address,
        port: Port(0),
        network: Network::Unix,
    }
}

pub fn ParseDestination(dest: &str) -> Result<Destination, String> {
    if let Some(rest) = dest.strip_prefix("tcp:") {
        let (addr_str, port_str) = split_host_port(rest)?;
        let addr = ParseAddress(addr_str);
        let port = super::port::PortFromString(port_str)?;
        Ok(TcpDestination(addr, port))
    } else if let Some(rest) = dest.strip_prefix("udp:") {
        let (addr_str, port_str) = split_host_port(rest)?;
        let addr = ParseAddress(addr_str);
        let port = super::port::PortFromString(port_str)?;
        Ok(UdpDestination(addr, port))
    } else if let Some(path) = dest.strip_prefix("unix:") {
        let addr = ParseAddress(path);
        Ok(UnixDestination(addr))
    } else {
        let (addr_str, port_str) = split_host_port(dest)?;
        let addr = ParseAddress(addr_str);
        let port = super::port::PortFromString(port_str)?;
        Ok(TcpDestination(addr, port))
    }
}

fn split_host_port(s: &str) -> Result<(&str, &str), String> {
    if s.starts_with('[') {
        let closing = s.find(']').ok_or_else(|| "missing closing bracket".to_string())?;
        let addr = &s[1..closing];
        let rest = &s[closing + 1..];
        if let Some(port_str) = rest.strip_prefix(':') {
            Ok((addr, port_str))
        } else if rest.is_empty() {
            return Err("missing port after IPv6 address".to_string());
        } else {
            return Err(format!("unexpected characters after bracket: {}", rest));
        }
    } else {
        let colon = s.rfind(':').ok_or_else(|| format!("missing port in {}", s))?;
        Ok((&s[..colon], &s[colon + 1..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_destination() {
        let addr = crate::address::IpAddress(&[10, 0, 0, 1]);
        let d = TcpDestination(addr, Port(80));
        assert_eq!(d.network, Network::Tcp);
        assert!(d.is_valid());
        assert_eq!(d.net_addr(), "10.0.0.1:80");
        assert_eq!(d.to_string(), "tcp:10.0.0.1:80");
    }

    #[test]
    fn test_udp_destination() {
        let addr = crate::address::IpAddress(&[8, 8, 8, 8]);
        let d = UdpDestination(addr, Port(53));
        assert_eq!(d.network, Network::Udp);
        assert_eq!(d.to_string(), "udp:8.8.8.8:53");
    }

    #[test]
    fn test_unix_destination() {
        let addr = crate::address::DomainAddress("/var/run/xray.sock");
        let d = UnixDestination(addr);
        assert_eq!(d.network, Network::Unix);
        assert!(d.is_valid());
    }

    #[test]
    fn test_parse_tcp_destination() {
        let d = ParseDestination("tcp:192.168.1.1:8080").unwrap();
        assert_eq!(d.network, Network::Tcp);
        assert_eq!(d.port.value(), 8080);
    }

    #[test]
    fn test_parse_udp_destination() {
        let d = ParseDestination("udp:10.0.0.1:53").unwrap();
        assert_eq!(d.network, Network::Udp);
    }

    #[test]
    fn test_parse_ipv6_destination() {
        let d = ParseDestination("tcp:[::1]:443").unwrap();
        assert_eq!(d.port.value(), 443);
    }

    #[test]
    fn test_parse_unix_destination() {
        let d = ParseDestination("unix:/tmp/test.sock").unwrap();
        assert_eq!(d.network, Network::Unix);
    }

    #[test]
    fn test_parse_plain_hostport() {
        let d = ParseDestination("example.com:80").unwrap();
        assert_eq!(d.network, Network::Tcp);
        assert_eq!(d.port.value(), 80);
    }

    #[test]
    fn test_invalid_missing_port() {
        assert!(ParseDestination("tcp:1.2.3.4").is_err());
    }
}
