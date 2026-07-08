use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Real-time online IP tracking.
/// Go equivalent: `app/stats/online_map.go`
pub struct OnlineMap {
    inner: Arc<RwLock<HashMap<String, OnlineEntry>>>,
    ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct OnlineEntry {
    pub email: String,
    pub ips: Vec<IpEntry>,
    pub last_seen: Instant,
}

#[derive(Debug, Clone)]
pub struct IpEntry {
    pub ip: SocketAddr,
    pub last_access: Instant,
    pub uplink: u64,
    pub downlink: u64,
}

impl OnlineMap {
    pub fn new(ttl_secs: u64) -> Self {
        OnlineMap {
            inner: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Record an access for a user.
    pub fn record_access(&self, email: &str, ip: SocketAddr, uplink: u64, downlink: u64) {
        let mut map = self.inner.write().unwrap();
        let entry = map.entry(email.to_string()).or_insert_with(|| OnlineEntry {
            email: email.to_string(),
            ips: Vec::new(),
            last_seen: Instant::now(),
        });
        entry.last_seen = Instant::now();

        if let Some(ip_entry) = entry.ips.iter_mut().find(|e| e.ip == ip) {
            ip_entry.last_access = Instant::now();
            ip_entry.uplink += uplink;
            ip_entry.downlink += downlink;
        } else {
            entry.ips.push(IpEntry {
                ip,
                last_access: Instant::now(),
                uplink,
                downlink,
            });
        }
    }

    /// Get online IPs for a user.
    pub fn get_user_ips(&self, email: &str) -> Vec<IpEntry> {
        let map = self.inner.read().unwrap();
        map.get(email).map(|e| e.ips.clone()).unwrap_or_default()
    }

    /// Get all online users.
    pub fn get_all_users(&self) -> Vec<OnlineEntry> {
        let map = self.inner.read().unwrap();
        let now = Instant::now();
        map.values()
            .filter(|e| now.duration_since(e.last_seen) < self.ttl)
            .cloned()
            .collect()
    }

    /// Cleanup expired entries.
    pub fn cleanup(&self) {
        let mut map = self.inner.write().unwrap();
        let now = Instant::now();
        map.retain(|_, e| now.duration_since(e.last_seen) < self.ttl);
        for entry in map.values_mut() {
            entry.ips.retain(|ip| now.duration_since(ip.last_access) < self.ttl);
        }
    }

    pub fn count(&self) -> usize {
        let map = self.inner.read().unwrap();
        map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_online_map() {
        let map = OnlineMap::new(60);
        let addr: SocketAddr = "1.2.3.4:56789".parse().unwrap();
        map.record_access("user@test.com", addr, 100, 50);
        assert_eq!(map.count(), 1);
        
        let ips = map.get_user_ips("user@test.com");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].uplink, 100);
        
        let all = map.get_all_users();
        assert_eq!(all.len(), 1);
        
        map.cleanup();
        assert_eq!(map.count(), 1); // still within TTL
    }
}
