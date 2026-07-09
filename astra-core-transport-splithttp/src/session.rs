use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{Mutex, mpsc};

use crate::upload_queue::UploadQueue;

pub fn generate_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub struct Session {
    pub upload_queue: UploadQueue,
    pub download_tx: mpsc::Sender<Vec<u8>>,
}

impl Session {
    pub fn new() -> (Self, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
        let session = Self {
            upload_queue: UploadQueue::new(),
            download_tx: tx,
        };
        (session, rx)
    }
}

#[derive(Clone)]
pub struct SessionManager {
    inner: Arc<Mutex<HashMap<String, Arc<Mutex<Session>>>>>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get or create a session, returning the session handle and a download receiver.
    /// The download receiver is only returned the first time the session is created.
    /// Returns (session, Some(receiver)) for new sessions, (session, None) for existing ones.
    pub async fn get_or_create(
        &self,
        id: &str,
    ) -> (Arc<Mutex<Session>>, Option<mpsc::Receiver<Vec<u8>>>) {
        let mut map = self.inner.lock().await;
        if let Some(session) = map.get(id) {
            (session.clone(), None)
        } else {
            let (session, rx) = Session::new();
            let session = Arc::new(Mutex::new(session));
            map.insert(id.to_string(), session.clone());
            (session, Some(rx))
        }
    }

    pub async fn remove(&self, id: &str) {
        let mut map = self.inner.lock().await;
        map.remove(id);
    }
}
