//! Router implementation for traffic routing.

use std::sync::Arc;

use astra_core_net::{Destination, TcpDestination};

use super::Delegate;

/// Router configuration.
#[derive(Default)]
pub struct RouterConfig {
    /// List of rules to apply for routing decisions.
    pub rules: Vec<RouteRule>,
}

/// Route rule combining filter and target.
#[derive(Debug, Clone)]
pub struct RouteRule {
    /// Filter for matching traffic.
    pub filter: RouteFilter,
    /// Target destination for matched traffic.
    pub target: Destination,
}

/// Route filter enum for different filter types.
#[derive(Debug, Clone)]
pub enum RouteFilter {
    /// Domain-based filter.
    Domain(String),
    /// IP address filter.
    Address(astra_core_net::Address),
    /// User-based filter.
    User(String),
}

/// Router for handling traffic routing decisions.
pub struct Router {
    config: RouterConfig,
    delegate: Option<Arc<dyn Delegate>>,
}

impl Router {
    pub fn new(config: RouterConfig, delegate: Option<Arc<dyn Delegate>>) -> Self {
        Router { config, delegate }
    }

    /// Apply routing delegate if present.
    fn apply_delegate(&self, dest: &Destination) -> Option<Destination> {
        self.delegate.as_ref().and_then(|d| {
            if d.allow(dest) {
                d.chg_addr(dest).or(Some(dest.clone()))
            } else {
                None
            }
        })
    }

    /// Route a traffic request to a destination.
    pub fn route(&self, addr: &astra_core_net::Address, port: u16) -> Option<Destination> {
        // Try delegate first
        if let Some(result) = self.apply_delegate_to_addr(addr, port) {
            return Some(result);
        }

        // Apply rules
        let dest = TcpDestination(astra_core_net::Address::Ipv4([0, 0, 0, 0]), astra_core_net::Port(port));
        for rule in &self.config.rules {
            if self.matches_filter(&rule.filter, addr, port) {
                return Some(rule.target.clone());
            }
        }

        Some(dest)
    }

    fn apply_delegate_to_addr(&self, addr: &astra_core_net::Address, port: u16) -> Option<Destination> {
        let dest = match addr {
            astra_core_net::Address::Ipv4(o) => TcpDestination(
                astra_core_net::Address::Ipv4(*o),
                astra_core_net::Port(port),
            ),
            astra_core_net::Address::Ipv6(o) => TcpDestination(
                astra_core_net::Address::Ipv6(*o),
                astra_core_net::Port(port),
            ),
            astra_core_net::Address::Domain(d) => TcpDestination(
                astra_core_net::Address::Domain(d.clone()),
                astra_core_net::Port(port),
            ),
        };

        self.apply_delegate(&dest)
    }

    fn matches_filter(&self, filter: &RouteFilter, addr: &astra_core_net::Address, _port: u16) -> bool {
        match filter {
            RouteFilter::Domain(d) => {
                matches_domain(addr, d)
            }
            RouteFilter::Address(a) => {
                addr == a
            }
            RouteFilter::User(email) => {
                // User-based filtering logic would go here
                email == "default"
            }
        }
    }
}

fn matches_domain(addr: &astra_core_net::Address, domain: &str) -> bool {
    match addr {
        astra_core_net::Address::Domain(d) => d == domain,
        _ => false,
    }
}

impl Default for Router {
    fn default() -> Self {
        Router::new(RouterConfig::default(), None)
    }
}