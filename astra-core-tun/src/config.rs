/// TUN configuration. Mirrors Go's `proxy/tun/Config`.
#[derive(Debug, Clone)]
pub struct Config {
    /// Interface name (e.g., "tun0", "utun4").
    pub name: String,
    /// MTU for the TUN interface.
    pub mtu: u32,
    /// User level for policy.
    pub user_level: u32,
    /// IP addresses to assign to the TUN interface (CIDR notation).
    pub addresses: Vec<String>,
    /// Gateway addresses.
    pub gateway: Vec<String>,
    /// DNS server addresses.
    pub dns: Vec<String>,
    /// Routes to add to the system routing table.
    pub routes: Vec<String>,
    /// Auto-outbound interface binding.
    pub auto_outbound_interface: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            name: "tun0".into(),
            mtu: 1500,
            user_level: 0,
            addresses: Vec::new(),
            gateway: Vec::new(),
            dns: Vec::new(),
            routes: Vec::new(),
            auto_outbound_interface: String::new(),
        }
    }
}
