use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Port(pub u16);

impl Port {
    pub fn value(self) -> u16 {
        self.0
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u16> for Port {
    fn from(v: u16) -> Self {
        Port(v)
    }
}

pub fn PortFromBytes(port: &[u8]) -> Port {
    assert_eq!(port.len(), 2);
    Port(u16::from_be_bytes([port[0], port[1]]))
}

pub fn PortFromInt(val: u32) -> Result<Port, String> {
    if val == 0 || val > 65535 {
        Err(format!("invalid port: {}", val))
    } else {
        Ok(Port(val as u16))
    }
}

pub fn PortFromString(s: &str) -> Result<Port, String> {
    let val: u32 = s
        .parse()
        .map_err(|_| format!("invalid port string: {}", s))?;
    PortFromInt(val)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PortRange {
    pub from: Port,
    pub to: Port,
}

impl PortRange {
    pub fn contains(&self, port: Port) -> bool {
        port >= self.from && port <= self.to
    }
}

pub fn SinglePortRange(p: Port) -> PortRange {
    PortRange { from: p, to: p }
}

#[derive(Clone, Debug)]
pub struct MemoryPortList {
    ranges: Vec<MemoryPortRange>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MemoryPortRange {
    pub from: Port,
    pub to: Port,
}

impl MemoryPortRange {
    pub fn contains(&self, port: Port) -> bool {
        port >= self.from && port <= self.to
    }
}

impl MemoryPortList {
    pub fn new(ranges: Vec<MemoryPortRange>) -> Self {
        MemoryPortList { ranges }
    }

    pub fn contains(&self, port: Port) -> bool {
        self.ranges.iter().any(|r| r.contains(port))
    }
}

impl From<&PortRange> for MemoryPortRange {
    fn from(pr: &PortRange) -> Self {
        MemoryPortRange {
            from: pr.from,
            to: pr.to,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PortList {
    ranges: Vec<PortRange>,
}

impl PortList {
    pub fn new(ranges: Vec<PortRange>) -> Self {
        PortList { ranges }
    }

    pub fn ports(&self) -> Vec<u32> {
        self.ranges
            .iter()
            .flat_map(|r| (r.from.value()..=r.to.value()).map(|p| p as u32))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_from_int() {
        let p = PortFromInt(80).unwrap();
        assert_eq!(p.value(), 80);
        assert!(PortFromInt(0).is_err());
        assert!(PortFromInt(65536).is_err());
    }

    #[test]
    fn test_port_from_string() {
        let p = PortFromString("443").unwrap();
        assert_eq!(p.value(), 443);
        assert!(PortFromString("abc").is_err());
    }

    #[test]
    fn test_port_from_bytes() {
        let p = PortFromBytes(&[0x00, 0x50]);
        assert_eq!(p.value(), 80);
    }

    #[test]
    fn test_port_range_contains() {
        let r = PortRange {
            from: Port(80),
            to: Port(83),
        };
        assert!(r.contains(Port(80)));
        assert!(r.contains(Port(82)));
        assert!(r.contains(Port(83)));
        assert!(!r.contains(Port(79)));
        assert!(!r.contains(Port(84)));
    }

    #[test]
    fn test_port_list_ports() {
        let pl = PortList::new(vec![
            PortRange {
                from: Port(80),
                to: Port(81),
            },
            PortRange {
                from: Port(443),
                to: Port(443),
            },
        ]);
        let ports = pl.ports();
        assert_eq!(ports, vec![80u32, 81, 443]);
    }

    #[test]
    fn test_memory_port_list() {
        let mpl = MemoryPortList::new(vec![MemoryPortRange {
            from: Port(100),
            to: Port(200),
        }]);
        assert!(mpl.contains(Port(150)));
        assert!(!mpl.contains(Port(250)));
    }

    #[test]
    fn test_single_port_range() {
        let r = SinglePortRange(Port(22));
        assert_eq!(r.from, r.to);
        assert!(r.contains(Port(22)));
        assert!(!r.contains(Port(23)));
    }
}
