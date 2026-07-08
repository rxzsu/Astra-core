use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// FullCone NAT for UDP. Maps (src_addr, src_port) to a session.
/// Mirrors Go's `proxy/tun/udp_fullcone.go`.

pub struct FullCone {
    sessions: Arc<Mutex<HashMap<SocketAddr, Session>>>,
}

struct Session {
    dst: SocketAddr,
    tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

impl FullCone {
    pub fn new() -> Self {
        FullCone {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a new session. Returns a receiver for inbound packets.
    pub fn create_session(&self, src: SocketAddr, dst: SocketAddr) -> tokio::sync::mpsc::UnboundedReceiver<Vec<u8>> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.sessions.lock().unwrap().insert(src, Session { dst, tx });
        rx
    }

    /// Forward an inbound packet to the session. Returns the original destination if session exists.
    pub fn forward_inbound(&self, src: &SocketAddr, data: &[u8]) -> Option<SocketAddr> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(src).map(|s| {
            let _ = s.tx.send(data.to_vec());
            s.dst
        })
    }

    /// Get or create a session.
    pub fn get_or_create(&self, src: SocketAddr, dst: SocketAddr) {
        let mut sessions = self.sessions.lock().unwrap();
        if !sessions.contains_key(&src) {
            let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
            sessions.insert(src, Session { dst, tx });
        }
    }

    pub fn has_session(&self, src: &SocketAddr) -> bool {
        self.sessions.lock().unwrap().contains_key(src)
    }

    pub fn remove(&self, src: &SocketAddr) {
        self.sessions.lock().unwrap().remove(src);
    }

    pub fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for FullCone {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_fullcone_create_forward() {
        let fc = FullCone::new();
        let src: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:53".parse().unwrap();

        let mut rx = fc.create_session(src, dst);
        assert!(fc.has_session(&src));
        assert_eq!(fc.len(), 1);

        // Forward inbound packet to session
        let result = fc.forward_inbound(&src, &[1, 2, 3]);
        assert_eq!(result, Some(dst));

        let received = rx.try_recv().ok();
        assert!(received.is_some());
        assert_eq!(received.unwrap(), vec![1, 2, 3]);

        fc.remove(&src);
        assert!(fc.is_empty());
    }

    #[test]
    fn test_fullcone_session_reuse() {
        let fc = FullCone::new();
        let src: SocketAddr = "10.0.0.1:54321".parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:53".parse().unwrap();

        fc.get_or_create(src, dst);
        assert_eq!(fc.len(), 1);

        // Second call with same src should not create new session
        fc.get_or_create(src, dst);
        assert_eq!(fc.len(), 1);
    }
}
