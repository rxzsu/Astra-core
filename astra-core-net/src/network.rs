use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Network {
    Unknown,
    Tcp,
    Udp,
    Unix,
}

impl Network {
    pub fn system_string(self) -> &'static str {
        match self {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
            Network::Unix => "unix",
            Network::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.system_string())
    }
}

pub fn HasNetwork(list: &[Network], network: Network) -> bool {
    list.contains(&network)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_display() {
        assert_eq!(Network::Tcp.system_string(), "tcp");
        assert_eq!(Network::Udp.system_string(), "udp");
        assert_eq!(Network::Unix.system_string(), "unix");
    }

    #[test]
    fn test_has_network() {
        let list = [Network::Tcp, Network::Udp];
        assert!(HasNetwork(&list, Network::Tcp));
        assert!(!HasNetwork(&list, Network::Unix));
    }
}
