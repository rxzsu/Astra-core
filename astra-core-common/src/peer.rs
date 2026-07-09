use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Peer connection tracking.
/// Go equivalent: `common/peer`

/// Information about a connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub connected_at: Instant,
    pub last_activity: Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl PeerInfo {
    pub fn new(addr: SocketAddr) -> Self {
        let now = Instant::now();
        PeerInfo {
            addr,
            connected_at: now,
            last_activity: now,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    pub fn activity_secs(&self) -> u64 {
        self.last_activity.elapsed().as_secs()
    }
}

/// Thread-safe peer tracker.
pub struct PeerTracker {
    peers: Arc<Mutex<HashMap<SocketAddr, PeerInfo>>>,
}

impl PeerTracker {
    pub fn new() -> Self {
        PeerTracker {
            peers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add(&self, addr: SocketAddr) {
        let mut peers = self.peers.lock().unwrap();
        peers.entry(addr).or_insert_with(|| PeerInfo::new(addr));
    }

    pub fn remove(&self, addr: &SocketAddr) {
        self.peers.lock().unwrap().remove(addr);
    }

    pub fn get(&self, addr: &SocketAddr) -> Option<PeerInfo> {
        self.peers.lock().unwrap().get(addr).cloned()
    }

    pub fn update_activity(&self, addr: &SocketAddr) {
        if let Some(peer) = self.peers.lock().unwrap().get_mut(addr) {
            peer.last_activity = Instant::now();
        }
    }

    pub fn add_bytes(&self, addr: &SocketAddr, sent: u64, received: u64) {
        if let Some(peer) = self.peers.lock().unwrap().get_mut(addr) {
            peer.bytes_sent += sent;
            peer.bytes_received += received;
        }
    }

    pub fn all_peers(&self) -> Vec<PeerInfo> {
        self.peers.lock().unwrap().values().cloned().collect()
    }

    pub fn count(&self) -> usize {
        self.peers.lock().unwrap().len()
    }

    /// Remove peers that have been inactive for longer than the timeout.
    pub fn cleanup(&self, timeout: Duration) {
        let mut peers = self.peers.lock().unwrap();
        peers.retain(|_, info| info.activity_secs() < timeout.as_secs());
    }
}

impl Default for PeerTracker {
    fn default() -> Self {
        PeerTracker::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_tracker() {
        let tracker = PeerTracker::new();
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        tracker.add(addr);
        assert_eq!(tracker.count(), 1);
        assert!(tracker.get(&addr).is_some());
        tracker.add_bytes(&addr, 100, 50);
        let info = tracker.get(&addr).unwrap();
        assert_eq!(info.bytes_sent, 100);
        assert_eq!(info.bytes_received, 50);
        tracker.remove(&addr);
        assert_eq!(tracker.count(), 0);
    }

    #[test]
    fn test_peer_cleanup() {
        let tracker = PeerTracker::new();
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        tracker.add(addr);
        tracker.cleanup(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(2));
        tracker.cleanup(Duration::from_millis(1));
        assert_eq!(tracker.count(), 0);
    }
}
