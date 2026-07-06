//! Reverse proxy (bridge/portal) — 1:1 port of `app/reverse` from Go Xray-core.

use astra_core_net::Destination;
use astra_core_proxy::{async_trait, Dialer, OutboundHandler, ProxyResult, UdpLink};
use astra_core_session::Session;
use astra_core_transport::Link;

const INTERNAL_DOMAIN: &str = "reverse";

// ─── Control protocol ──────────────────────────────────────────────────────

/// Control state between bridge and portal (Go: `Control.State`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ControlState {
    Active,
    Drain,
}

/// Control message (Go: `Control` proto).
#[derive(Debug, Clone)]
pub struct Control {
    pub state: ControlState,
    pub random: Vec<u8>,
}

impl Control {
    pub fn new(state: ControlState) -> Self {
        let len = (rand::random::<u64>() % 64) as usize + 1;
        Control { state, random: (0..len).map(|_| rand::random::<u8>()).collect() }
    }

    pub fn encode(&self) -> Vec<u8> {
        let state_byte = match self.state {
            ControlState::Active => 0u8,
            ControlState::Drain => 1u8,
        };
        let mut buf = vec![state_byte];
        buf.extend_from_slice(&(self.random.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.random);
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 3 { return None; }
        let state = match data[0] {
            0 => ControlState::Active,
            1 => ControlState::Drain,
            _ => return None,
        };
        let len = u16::from_be_bytes([data[1], data[2]]) as usize;
        if data.len() < 3 + len { return None; }
        Some(Control { state, random: data[3..3 + len].to_vec() })
    }
}

fn is_internal_domain(dest: &Destination) -> bool {
    dest.address.as_domain().map(|d| d == INTERNAL_DOMAIN).unwrap_or(false)
}

// ─── Portal outbound handler ───────────────────────────────────────────────

/// Portal side of reverse proxy. Registered as an outbound handler.
/// When traffic arrives, if dest is the portal domain → creates mux worker.
/// Otherwise → dispatches through the mux client manager.
/// Bridge component stub (full implementation pending mux integration).
pub struct Bridge {
    pub tag: String,
    pub domain: String,
}

impl Bridge {
    pub fn new(tag: String, domain: String) -> Self {
        Bridge { tag, domain }
    }
}

pub struct PortalHandler {
    pub tag: String,
    pub domain: String,
}

impl PortalHandler {
    pub fn new(tag: String, domain: String) -> Self {
        PortalHandler { tag, domain }
    }
}

#[async_trait]
impl OutboundHandler for PortalHandler {
    async fn process(&self, session: Session, link: &mut Link, _dialer: &dyn Dialer) -> ProxyResult<()> {
        // Handle inbound traffic through this portal
        let _ = (session, link);
        Err("reverse portal not yet fully implemented".into())
    }

    async fn process_udp(&self, _session: Session, _link: &mut UdpLink) -> ProxyResult<()> {
        Err("reverse portal udp not supported".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra_core_net::{Address, Network, Port};

    #[test]
    fn test_control_roundtrip() {
        let c = Control::new(ControlState::Active);
        let encoded = c.encode();
        let decoded = Control::decode(&encoded).unwrap();
        assert_eq!(decoded.state, ControlState::Active);
        assert_eq!(decoded.random.len(), c.random.len());
        assert_eq!(decoded.random, c.random);
    }

    #[test]
    fn test_control_drain() {
        let c = Control::new(ControlState::Drain);
        let encoded = c.encode();
        let decoded = Control::decode(&encoded).unwrap();
        assert_eq!(decoded.state, ControlState::Drain);
    }

    #[test]
    fn test_internal_domain() {
        let dest = Destination {
            address: Address::Domain("reverse".into()),
            port: Port(0),
            network: Network::Tcp,
        };
        assert!(is_internal_domain(&dest));
    }
}
