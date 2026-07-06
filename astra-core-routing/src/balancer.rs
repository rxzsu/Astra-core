use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Strategy for load balancing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BalancerStrategy {
    Random,
    RoundRobin,
    LeastPing,
}

impl BalancerStrategy {
    pub fn from_str(s: &str) -> Self {
        match s {
            "roundRobin" => BalancerStrategy::RoundRobin,
            "leastPing" => BalancerStrategy::LeastPing,
            _ => BalancerStrategy::Random,
        }
    }
}

/// Selects an outbound tag from a list based on the configured strategy.
#[derive(Clone)]
pub struct Balancer {
    pub tag: String,
    pub selector: Vec<String>,
    pub strategy: BalancerStrategy,
    pub fallback_tag: Option<String>,
    counter: Arc<AtomicUsize>,
}

impl Balancer {
    pub fn new(tag: String, selector: Vec<String>, strategy: BalancerStrategy, fallback_tag: Option<String>) -> Self {
        Balancer { tag, selector, strategy, fallback_tag, counter: Arc::new(AtomicUsize::new(0)) }
    }

    /// Pick an outbound tag.
    pub fn pick(&self) -> Option<&str> {
        if self.selector.is_empty() {
            return self.fallback_tag.as_deref();
        }

        match self.strategy {
            BalancerStrategy::Random => {
                let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos();
                let idx = (nanos as usize) % self.selector.len();
                Some(self.selector[idx].as_str())
            }
            BalancerStrategy::RoundRobin => {
                let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.selector.len();
                Some(self.selector[idx % self.selector.len()].as_str())
            }
            BalancerStrategy::LeastPing => {
                let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.selector.len();
                Some(self.selector[idx % self.selector.len()].as_str())
            }
        }
    }
}
