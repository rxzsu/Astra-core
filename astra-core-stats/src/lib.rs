use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Instant;

/// A named atomic counter for traffic or connection stats.
pub struct Counter {
    name: String,
    value: AtomicI64,
}

impl Counter {
    pub fn new(name: &str) -> Self {
        Counter {
            name: name.to_string(),
            value: AtomicI64::new(0),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn add(&self, n: i64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    pub fn set(&self, n: i64) {
        self.value.store(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }

    pub fn reset(&self) {
        self.value.store(0, Ordering::Relaxed);
    }
}

/// A stat channel tracking a rate over time (like Xray's "channel" stat).
pub struct Channel {
    name: String,
    value: AtomicI64,
    last_updated: RwLock<Instant>,
}

impl Channel {
    pub fn new(name: &str) -> Self {
        Channel {
            name: name.to_string(),
            value: AtomicI64::new(0),
            last_updated: RwLock::new(Instant::now()),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn add(&self, n: i64) {
        self.value.fetch_add(n, Ordering::Relaxed);
        if let Ok(mut t) = self.last_updated.write() {
            *t = Instant::now();
        }
    }

    pub fn set(&self, n: i64) {
        self.value.store(n, Ordering::Relaxed);
        if let Ok(mut t) = self.last_updated.write() {
            *t = Instant::now();
        }
    }

    pub fn get(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }

    pub fn last_updated(&self) -> Instant {
        self.last_updated
            .read()
            .map(|t| *t)
            .unwrap_or(Instant::now())
    }
}

/// Thread-safe registry of counters and channels by name.
pub struct StatsManager {
    counters: RwLock<HashMap<String, Arc<Counter>>>,
    channels: RwLock<HashMap<String, Arc<Channel>>>,
}

impl Default for StatsManager {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsManager {
    pub fn new() -> Self {
        StatsManager {
            counters: RwLock::new(HashMap::new()),
            channels: RwLock::new(HashMap::new()),
        }
    }

    pub fn register_counter(&self, name: &str) -> Arc<Counter> {
        let mut map = self.counters.write().unwrap();
        map.entry(name.to_string())
            .or_insert_with(|| Arc::new(Counter::new(name)))
            .clone()
    }

    pub fn get_counter(&self, name: &str) -> Option<Arc<Counter>> {
        self.counters.read().unwrap().get(name).cloned()
    }

    pub fn register_channel(&self, name: &str) -> Arc<Channel> {
        let mut map = self.channels.write().unwrap();
        map.entry(name.to_string())
            .or_insert_with(|| Arc::new(Channel::new(name)))
            .clone()
    }

    pub fn get_channel(&self, name: &str) -> Option<Arc<Channel>> {
        self.channels.read().unwrap().get(name).cloned()
    }

    pub fn all_counters(&self) -> Vec<Arc<Counter>> {
        self.counters.read().unwrap().values().cloned().collect()
    }

    pub fn all_channels(&self) -> Vec<Arc<Channel>> {
        self.channels.read().unwrap().values().cloned().collect()
    }

    pub fn remove_counter(&self, name: &str) -> bool {
        self.counters.write().unwrap().remove(name).is_some()
    }

    pub fn remove_channel(&self, name: &str) -> bool {
        self.channels.write().unwrap().remove(name).is_some()
    }
}

/// No-op stats manager: register always returns a live counter that is never stored.
/// Useful when stats feature is disabled (Xray NoopManager parity).
pub struct NoopManager;

impl NoopManager {
    pub fn new() -> Self {
        NoopManager
    }

    pub fn register_counter(&self, name: &str) -> Arc<Counter> {
        Arc::new(Counter::new(name))
    }

    pub fn get_counter(&self, _name: &str) -> Option<Arc<Counter>> {
        None
    }

    pub fn register_channel(&self, name: &str) -> Arc<Channel> {
        Arc::new(Channel::new(name))
    }

    pub fn get_channel(&self, _name: &str) -> Option<Arc<Channel>> {
        None
    }

    pub fn all_counters(&self) -> Vec<Arc<Counter>> {
        Vec::new()
    }

    pub fn all_channels(&self) -> Vec<Arc<Channel>> {
        Vec::new()
    }
}

impl Default for NoopManager {
    fn default() -> Self {
        Self::new()
    }
}

pub mod online_map;

/// Naming helpers matching Xray conventions.
pub mod naming {
    /// Inbound traffic counter name: `inbound>>>{tag}>>>traffic>>>downlink`
    pub fn inbound_downlink(tag: &str) -> String {
        format!("inbound>>>{}>>>traffic>>>downlink", tag)
    }
    /// Inbound traffic counter name: `inbound>>>{tag}>>>traffic>>>uplink`
    pub fn inbound_uplink(tag: &str) -> String {
        format!("inbound>>>{}>>>traffic>>>uplink", tag)
    }
    /// Outbound traffic counter name: `outbound>>>{tag}>>>traffic>>>downlink`
    pub fn outbound_downlink(tag: &str) -> String {
        format!("outbound>>>{}>>>traffic>>>downlink", tag)
    }
    /// Outbound traffic counter name: `outbound>>>{tag}>>>traffic>>>uplink`
    pub fn outbound_uplink(tag: &str) -> String {
        format!("outbound>>>{}>>>traffic>>>uplink", tag)
    }
    /// User traffic counter name: `user>>>{email}>>>traffic>>>downlink`
    pub fn user_downlink(email: &str) -> String {
        format!("user>>>{}>>>traffic>>>downlink", email)
    }
    /// User traffic counter name: `user>>>{email}>>>traffic>>>uplink`
    pub fn user_uplink(email: &str) -> String {
        format!("user>>>{}>>>traffic>>>uplink", email)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter() {
        let c = Counter::new("test");
        assert_eq!(c.get(), 0);
        c.add(42);
        assert_eq!(c.get(), 42);
        c.add(-10);
        assert_eq!(c.get(), 32);
        c.reset();
        assert_eq!(c.get(), 0);
    }

    #[test]
    fn test_noop_manager() {
        let mgr = NoopManager::new();
        let c = mgr.register_counter("x");
        c.add(1);
        assert!(mgr.get_counter("x").is_none());
        assert!(mgr.all_counters().is_empty());
    }

    #[test]
    fn test_manager_register_and_get() {
        let mgr = StatsManager::new();
        let c1 = mgr.register_counter("test.counter");
        c1.add(100);
        let c2 = mgr.get_counter("test.counter").unwrap();
        assert_eq!(c2.get(), 100);

        let ch = mgr.register_channel("test.channel");
        ch.add(50);
        assert_eq!(ch.get(), 50);
    }

    #[test]
    fn test_naming() {
        assert_eq!(
            naming::inbound_downlink("socks"),
            "inbound>>>socks>>>traffic>>>downlink"
        );
        assert_eq!(
            naming::outbound_uplink("freedom"),
            "outbound>>>freedom>>>traffic>>>uplink"
        );
        assert_eq!(
            naming::user_downlink("user@test"),
            "user>>>user@test>>>traffic>>>downlink"
        );
    }
}
