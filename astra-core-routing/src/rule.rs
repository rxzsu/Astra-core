use std::sync::Arc;

use crate::context::RoutingContext;
use crate::matcher::Matcher;
use crate::webhook::WebhookNotifier;

/// A routing rule with a set of conditions (AND) and a target outbound tag.
pub struct RouteRule {
    pub tag: String,
    pub conditions: Vec<Box<dyn Matcher>>,
    pub outbound_tag: String,
    pub balancer_tag: String,
    pub webhook: Option<Arc<WebhookNotifier>>,
}

impl RouteRule {
    pub fn new(tag: String, outbound_tag: String, balancer_tag: String) -> Self {
        RouteRule { tag, conditions: Vec::new(), outbound_tag, balancer_tag, webhook: None }
    }

    pub fn add_condition(&mut self, matcher: Box<dyn Matcher>) {
        self.conditions.push(matcher);
    }

    pub fn with_webhook(mut self, webhook: Arc<WebhookNotifier>) -> Self {
        self.webhook = Some(webhook);
        self
    }

    pub fn matches(&self, ctx: &RoutingContext) -> bool {
        if self.conditions.is_empty() {
            return false;
        }
        self.conditions.iter().all(|c| c.matches(ctx))
    }

    /// Check match and fire webhook if applicable.
    pub fn matches_and_notify(&self, ctx: &RoutingContext) -> bool {
        let matched = self.matches(ctx);
        if matched {
            if let Some(ref webhook) = self.webhook {
                let tag = if !self.outbound_tag.is_empty() { &self.outbound_tag } else { &self.balancer_tag };
                webhook.fire(ctx, tag);
            }
        }
        matched
    }
}
