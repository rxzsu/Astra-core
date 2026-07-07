use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
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
    alive: Option<Arc<RwLock<HashSet<String>>>>,
}

impl Balancer {
    pub fn new(tag: String, selector: Vec<String>, strategy: BalancerStrategy, fallback_tag: Option<String>) -> Self {
        Balancer { tag, selector, strategy, fallback_tag, counter: Arc::new(AtomicUsize::new(0)), alive: None }
    }

    /// Attach a shared alive-set from the observatory.
    pub fn with_alive(mut self, alive: Arc<RwLock<HashSet<String>>>) -> Self {
        self.alive = Some(alive);
        self
    }

    /// Pick an outbound tag, skipping any that are known dead.
    pub fn pick(&self) -> Option<&str> {
        let candidates: Vec<&str> = match self.alive {
            Some(ref alive) => {
                let alive_set = alive.read().unwrap();
                self.selector.iter().filter(|t| alive_set.contains(*t)).map(|s| s.as_str()).collect()
            }
            None => self.selector.iter().map(|s| s.as_str()).collect(),
        };

        if candidates.is_empty() {
            return self.fallback_tag.as_deref();
        }

        match self.strategy {
            BalancerStrategy::Random => {
                let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos();
                let idx = (nanos as usize) % candidates.len();
                Some(candidates[idx])
            }
            BalancerStrategy::RoundRobin => {
                let idx = self.counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
                Some(candidates[idx % candidates.len()])
            }
            BalancerStrategy::LeastPing => {
                let idx = self.counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
                Some(candidates[idx % candidates.len()])
            }
        }
    }
}
