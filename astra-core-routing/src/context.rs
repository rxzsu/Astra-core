use std::collections::HashMap;
use std::net::IpAddr;

/// Context for a routing decision.
#[derive(Clone, Default)]
pub struct RoutingContext {
    /// Target destination address (string for domain matching)
    pub target_domain: Option<String>,
    /// Target destination IP (if resolved)
    pub target_ip: Option<IpAddr>,
    /// Target port
    pub target_port: u16,
    /// Source IP
    pub source_ip: Option<IpAddr>,
    /// Source port
    pub source_port: u16,
    /// Inbound tag
    pub inbound_tag: String,
    /// Network protocol (tcp, udp)
    pub network: String,
    /// Sniffed protocol (http, tls, bittorrent, etc.)
    pub protocol: Option<String>,
    /// User email
    pub user: Option<String>,
    /// Custom attributes
    pub attributes: HashMap<String, String>,
}
