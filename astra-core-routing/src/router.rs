use crate::context::RoutingContext;
use crate::rule::RouteRule;

/// Strategy for resolving domain names in routing.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum DomainStrategy {
    #[default]
    AsIs,
    IpIfNonMatch,
    IpOnDemand,
}

impl DomainStrategy {
    pub fn from_str(s: &str) -> Self {
        match s {
            "IpIfNonMatch" => DomainStrategy::IpIfNonMatch,
            "IpOnDemand" => DomainStrategy::IpOnDemand,
            _ => DomainStrategy::AsIs,
        }
    }
}

/// Result of a routing decision.
pub struct RouteResult {
    pub outbound_tag: String,
    pub rule_tag: String,
}

/// Xray-style Router that picks an outbound tag based on rules.
pub struct Router {
    rules: Vec<RouteRule>,
    domain_strategy: DomainStrategy,
}

impl Router {
    pub fn new(rules: Vec<RouteRule>, domain_strategy: DomainStrategy) -> Self {
        Router {
            rules,
            domain_strategy,
        }
    }

    /// Pick a route for the given context.
    /// Returns None if no rule matches (caller should use default handler).
    /// Fires webhooks on match.
    pub fn pick_route(&self, ctx: &RoutingContext) -> Option<RouteResult> {
        for rule in &self.rules {
            if rule.matches_and_notify(ctx) {
                if !rule.outbound_tag.is_empty() {
                    return Some(RouteResult {
                        outbound_tag: rule.outbound_tag.clone(),
                        rule_tag: rule.tag.clone(),
                    });
                }
                if !rule.balancer_tag.is_empty() {
                    return Some(RouteResult {
                        outbound_tag: rule.balancer_tag.clone(),
                        rule_tag: rule.tag.clone(),
                    });
                }
            }
        }
        None
    }

    pub fn domain_strategy(&self) -> DomainStrategy {
        self.domain_strategy
    }
}

impl Default for Router {
    fn default() -> Self {
        Router {
            rules: Vec::new(),
            domain_strategy: DomainStrategy::AsIs,
        }
    }
}
