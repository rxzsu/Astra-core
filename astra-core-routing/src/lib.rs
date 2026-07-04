//! Astra-core routing package
//! 
//! Provides traffic routing functionality for proxy servers.

pub mod domain;
pub mod mask;
pub mod range;
pub mod router;
pub mod rule;
pub mod u32_filter;

pub use domain::{Domain, DomainFilter};
pub use mask::{IpMask, IPv4Mask, IPv6Mask};
pub use range::{IPv4Range, IPv6Range, RangeFilter};
pub use router::{RouteFilter, RouteRule, Router, RouterConfig};
pub use rule::{Rule, RuleFilter};
pub use u32_filter::U32Filter;

/// Routing delegate trait for custom routing logic.
pub trait Delegate: Send + Sync {
    fn allow(&self, dest: &astra_core_net::Destination) -> bool;
    fn chg_addr(
        &self,
        dest: &astra_core_net::Destination,
    ) -> Option<astra_core_net::Destination>;
}