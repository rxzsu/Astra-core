use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;

use tokio::sync::Mutex;
use tokio::sync::Notify;

/// Configuration for mux client strategy.
#[derive(Debug, Clone)]
pub struct MuxClientStrategy {
    pub max_concurrency: u32,
    pub max_connection: u32,
}

impl Default for MuxClientStrategy {
    fn default() -> Self {
        MuxClientStrategy {
            max_concurrency: 8,
            max_connection: 0,
        }
    }
}

/// A single mux session.
pub struct Session {
    pub id: u16,
    closed: AtomicBool,
    notify: Notify,
}

impl Session {
    pub fn new(id: u16) -> Self {
        Session {
            id,
            closed: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    pub async fn wait_closed(&self) {
        self.notify.notified().await;
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.notify.notify_waiters();
    }
}

/// Manages multiple mux sessions.
pub struct SessionManager {
    sessions: Mutex<HashMap<u16, Arc<Session>>>,
    next_id: AtomicU16,
    closed: AtomicBool,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        SessionManager {
            sessions: Mutex::new(HashMap::new()),
            next_id: AtomicU16::new(0),
            closed: AtomicBool::new(false),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    pub async fn size(&self) -> usize {
        self.sessions.lock().await.len()
    }

    pub fn total_allocated(&self) -> u16 {
        self.next_id.load(Ordering::Relaxed)
    }

    pub async fn allocate(&self, strategy: &MuxClientStrategy) -> Option<Arc<Session>> {
        if self.closed.load(Ordering::Relaxed) {
            return None;
        }

        let max_concurrency = strategy.max_concurrency as usize;
        let max_connection = strategy.max_connection;

        let mut sessions = self.sessions.lock().await;

        if (max_concurrency > 0 && sessions.len() >= max_concurrency)
            || (max_connection > 0 && self.next_id.load(Ordering::Relaxed) as u32 >= max_connection)
        {
            return None;
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let session = Arc::new(Session::new(id));
        sessions.insert(id, session.clone());
        Some(session)
    }

    pub async fn add(&self, session: Arc<Session>) -> bool {
        if self.closed.load(Ordering::Relaxed) {
            return false;
        }
        self.sessions.lock().await.insert(session.id, session);
        true
    }

    pub async fn remove(&self, id: u16) {
        self.sessions.lock().await.remove(&id);
    }

    pub async fn get(&self, id: u16) -> Option<Arc<Session>> {
        self.sessions.lock().await.get(&id).cloned()
    }

    pub async fn close_if_no_session_and_idle(&self, check_size: usize, check_count: u16) -> bool {
        if self.closed.load(Ordering::Relaxed) {
            return true;
        }
        let sessions = self.sessions.lock().await;
        if !sessions.is_empty() {
            return false;
        }
        if check_size != 0 || check_count != self.next_id.load(Ordering::Relaxed) {
            return false;
        }
        self.closed.store(true, Ordering::Relaxed);
        true
    }

    pub async fn close(&self) {
        if self.closed.swap(true, Ordering::Relaxed) {
            return;
        }
        let sessions = self.sessions.lock().await;
        for session in sessions.values() {
            session.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_manager_allocate_and_get() {
        let mgr = SessionManager::new();
        let strategy = MuxClientStrategy::default();

        let s = mgr.allocate(&strategy).await;
        assert!(s.is_some());
        let sid = s.unwrap().id;
        assert_eq!(sid, 1);

        let fetched = mgr.get(sid).await;
        assert!(fetched.is_some());
    }

    #[tokio::test]
    async fn test_session_manager_close() {
        let mgr = SessionManager::new();
        let strategy = MuxClientStrategy::default();

        let s = mgr.allocate(&strategy).await.unwrap();
        mgr.close().await;

        assert!(mgr.is_closed());
        assert!(s.is_closed());
    }

    #[tokio::test]
    async fn test_session_allocate_full() {
        let mgr = SessionManager::new();
        let strategy = MuxClientStrategy {
            max_concurrency: 1,
            max_connection: 0,
        };

        let s1 = mgr.allocate(&strategy).await;
        assert!(s1.is_some());

        let s2 = mgr.allocate(&strategy).await;
        assert!(s2.is_none());
    }
}
