use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// FullCone NAT for UDP. Maps (src_addr, src_port) to a virtual connection.
/// Mirrors Go's `proxy/tun/udp_fullcone.go`.
pub struct FullCone {
    sessions: Arc<Mutex<HashMap<SocketAddr, Session>>>,
}

struct Session {
    dst: SocketAddr,
    // Channel for incoming packets
    tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

impl FullCone {
    pub fn new() -> Self {
        FullCone {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Handle an incoming UDP packet from the TUN interface.
    /// Returns the destination to forward to and the sender channel for responses.
    pub fn handle_packet(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        data: Vec<u8>,
    ) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) {
        let mut sessions = self.sessions.lock().unwrap();
        let entry = sessions.entry(src);
        match entry {
            std::collections::hash_map::Entry::Occupied(mut session) => {
                // Existing session: send data to it
                let _ = session.get().tx.send(data);
                // Return a dummy receiver (the actual processing is elsewhere)
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                (session.get().dst, rx)
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                entry.insert(Session { dst, tx: tx.clone() });
                (dst, rx)
            }
        }
    }

    /// Remove a session when it's done.
    pub fn remove_session(&self, src: &SocketAddr) {
        self.sessions.lock().unwrap().remove(src);
    }
}
