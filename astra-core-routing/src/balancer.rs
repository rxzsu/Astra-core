use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Strategy for load balancing.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum BalancerStrategy {
    #[default]
    Random,
    RoundRobin,
    LeastPing,
    LeastLoad,
}

impl std::str::FromStr for BalancerStrategy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "roundRobin" => BalancerStrategy::RoundRobin,
            "leastPing" => BalancerStrategy::LeastPing,
            "leastLoad" => BalancerStrategy::LeastLoad,
            _ => BalancerStrategy::Random,
        })
    }
}

/// Settings for the LeastLoad strategy (mirrors Go's `strategy_leastload.go`).
#[derive(Debug, Clone, Default)]
pub struct LeastLoadConfig {
    /// Per-outbound weight costs (tag -> cost). Higher = less preferred.
    pub costs: std::collections::HashMap<String, f64>,
    /// RTT baseline in ms. Used to normalize RTT readings.
    pub baselines: Vec<f64>,
    /// Expected number of concurrent clients per outbound.
    pub expected: i32,
    /// Maximum acceptable RTT in ms.
    pub max_rtt: i64,
    /// Tolerance multiplier for RTT deviation.
    pub tolerance: f64,
}

/// Observability data for a single outbound (used by LeastLoad).
#[derive(Debug, Clone, Default)]
pub struct OutboundMetrics {
    /// Current RTT in ms (0 = unknown).
    pub rtt_ms: f64,
    /// Number of active connections.
    pub active_conns: i32,
    /// Total connections handled.
    pub total_conns: u64,
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
    /// Per-outbound metrics for LeastLoad.
    pub metrics: Arc<RwLock<std::collections::HashMap<String, OutboundMetrics>>>,
    pub least_load_config: LeastLoadConfig,
    /// Override target (Go: app/router/balancing_override.go).
    override_target: Arc<RwLock<Option<String>>>,
}

impl Balancer {
    pub fn new(
        tag: String,
        selector: Vec<String>,
        strategy: BalancerStrategy,
        fallback_tag: Option<String>,
    ) -> Self {
        Balancer {
            tag,
            selector,
            strategy,
            fallback_tag,
            counter: Arc::new(AtomicUsize::new(0)),
            alive: None,
            metrics: Arc::new(RwLock::new(std::collections::HashMap::new())),
            least_load_config: LeastLoadConfig::default(),
            override_target: Arc::new(RwLock::new(None)),
        }
    }

    pub fn with_alive(mut self, alive: Arc<RwLock<HashSet<String>>>) -> Self {
        self.alive = Some(alive);
        self
    }

    pub fn with_least_load_config(mut self, config: LeastLoadConfig) -> Self {
        self.least_load_config = config;
        self
    }

    /// Override the balancer's selection to always return a specific tag.
    pub fn set_override(&self, target: &str) {
        *self.override_target.write().unwrap() = if target.is_empty() {
            None
        } else {
            Some(target.to_string())
        };
    }

    /// Clear the override, returning to normal selection.
    pub fn clear_override(&self) {
        *self.override_target.write().unwrap() = None;
    }

    /// Get the current override target, if any.
    pub fn get_override(&self) -> Option<String> {
        self.override_target.read().unwrap().clone()
    }

    /// Pick a tag, respecting override. Returns the tag to use, or None for fallback.
    pub fn pick_override(&self) -> Option<String> {
        // Check override first (Go: app/router/balancing_override.go)
        self.override_target.read().unwrap().clone()
    }

    pub fn pick(&self) -> Option<&str> {
        let candidates: Vec<&str> = match self.alive {
            Some(ref alive) => {
                let alive_set = alive.read().unwrap();
                self.selector
                    .iter()
                    .filter(|t| alive_set.contains(*t))
                    .map(|s| s.as_str())
                    .collect()
            }
            None => self.selector.iter().map(|s| s.as_str()).collect(),
        };

        if candidates.is_empty() {
            return self.fallback_tag.as_deref();
        }

        match self.strategy {
            BalancerStrategy::Random => {
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos();
                let idx = (nanos as usize) % candidates.len();
                Some(candidates[idx])
            }
            BalancerStrategy::RoundRobin => {
                let idx = self.counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
                Some(candidates[idx])
            }
            BalancerStrategy::LeastPing => {
                let idx = self.counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
                Some(candidates[idx])
            }
            BalancerStrategy::LeastLoad => {
                // Inline least-load pick to avoid lifetime issues
                if candidates.is_empty() {
                    return self.fallback_tag.as_deref();
                }
                let metrics = self.metrics.read().unwrap();
                let cfg = &self.least_load_config;
                let mut best_idx = 0usize;
                let mut best_score = f64::MAX;
                for (i, &tag) in candidates.iter().enumerate() {
                    let mut score = 0.0f64;
                    if let Some(m) = metrics.get(tag) {
                        if m.rtt_ms > 0.0 && !cfg.baselines.is_empty() {
                            let baseline = cfg.baselines.iter().cloned().fold(f64::MAX, f64::min);
                            if baseline > 0.0 {
                                let rtt_ratio = m.rtt_ms / baseline;
                                if rtt_ratio > 1.0 {
                                    score += (rtt_ratio - 1.0) * cfg.tolerance.max(0.1);
                                }
                            }
                        }
                        if cfg.max_rtt > 0 && m.rtt_ms > cfg.max_rtt as f64 {
                            score += 100.0;
                        }
                        if cfg.expected > 0 {
                            let load_ratio = m.active_conns as f64 / cfg.expected as f64;
                            if load_ratio > 1.0 {
                                score += (load_ratio - 1.0) * 0.5;
                            }
                        }
                    }
                    if let Some(cost) = cfg.costs.get(tag) {
                        score += cost;
                    }
                    if score < best_score {
                        best_score = score;
                        best_idx = i;
                    }
                }
                Some(candidates[best_idx])
            }
        }
    }
}
