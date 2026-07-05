use crate::context::RoutingContext;
use crate::matcher::Matcher;

/// A routing rule with a set of conditions (AND) and a target outbound tag.
pub struct RouteRule {
    pub tag: String,
    pub conditions: Vec<Box<dyn Matcher>>,
    pub outbound_tag: String,
    pub balancer_tag: String,
}

impl RouteRule {
    pub fn new(tag: String, outbound_tag: String, balancer_tag: String) -> Self {
        RouteRule { tag, conditions: Vec::new(), outbound_tag, balancer_tag }
    }

    pub fn add_condition(&mut self, matcher: Box<dyn Matcher>) {
        self.conditions.push(matcher);
    }

    pub fn matches(&self, ctx: &RoutingContext) -> bool {
        if self.conditions.is_empty() {
            return false;
        }
        self.conditions.iter().all(|c| c.matches(ctx))
    }
}
