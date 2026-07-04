use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time;

use crate::frame::{read_frame, write_frame, FrameMetadata, SessionStatus};
use crate::session::{MuxClientStrategy, Session, SessionManager};

/// A mux client connection. Manages a session pool over a single transport.
///
/// Corresponds to Go's `mux.ClientWorker`.
pub struct MuxClient<R, W> {
    session_manager: Arc<SessionManager>,
    writer: tokio::sync::Mutex<W>,
    reader: tokio::sync::Mutex<R>,
    strategy: MuxClientStrategy,
    done: Arc<AtomicBool>,
    done_notify: Arc<tokio::sync::Notify>,
}

impl<R: AsyncRead + Unpin + Send + 'static, W: AsyncWrite + Unpin + Send + 'static>
    MuxClient<R, W>
{
    pub fn new(reader: R, writer: W, strategy: MuxClientStrategy) -> Arc<Self> {
        let session_manager = Arc::new(SessionManager::new());
        let done = Arc::new(AtomicBool::new(false));
        let done_notify = Arc::new(tokio::sync::Notify::new());

        let client = Arc::new(MuxClient {
            session_manager: session_manager.clone(),
            writer: tokio::sync::Mutex::new(writer),
            reader: tokio::sync::Mutex::new(reader),
            strategy,
            done: done.clone(),
            done_notify: done_notify.clone(),
        });

        let c = client.clone();
        tokio::spawn(async move {
            c.read_loop().await;
            done.store(true, Ordering::Relaxed);
            done_notify.notify_waiters();
        });

        let c2 = client.clone();
        tokio::spawn(async move {
            c2.monitor_loop().await;
        });

        client
    }

    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::Relaxed)
    }

    pub async fn wait_done(&self) {
        if !self.is_done() {
            self.done_notify.notified().await;
        }
    }

    pub async fn open_session(&self) -> Option<Arc<Session>> {
        self.session_manager.allocate(&self.strategy).await
    }

    pub async fn write_frame(&self, meta: &FrameMetadata, data: Option<&[u8]>) -> Result<(), String> {
        let mut writer = self.writer.lock().await;
        write_frame(&mut *writer, meta, data).await
    }

    #[allow(dead_code)]
    async fn is_full(&self) -> bool {
        if self.is_done() {
            return true;
        }
        let size = self.session_manager.size().await;
        let count = self.session_manager.total_allocated();

        if self.strategy.max_concurrency > 0 && size >= self.strategy.max_concurrency as usize {
            return true;
        }
        if self.strategy.max_connection > 0 && count as u32 >= self.strategy.max_connection {
            return true;
        }
        false
    }

    async fn read_loop(&self) {
        let mut reader = self.reader.lock().await;
        loop {
            let (meta, _data) = match read_frame(&mut *reader).await {
                Ok(m) => m,
                Err(_) => break,
            };

            match meta.status {
                SessionStatus::Keep => {
                    if let Some(_session) = self.session_manager.get(meta.session_id).await {
                        // Forward data to session output
                    }
                }
                SessionStatus::End => {
                    self.session_manager.remove(meta.session_id).await;
                    if let Some(session) = self.session_manager.get(meta.session_id).await {
                        session.close();
                    }
                }
                _ => {}
            }
        }
    }

    async fn monitor_loop(&self) {
        let mut interval = time::interval(Duration::from_secs(16));
        loop {
            interval.tick().await;
            if self.is_done() {
                return;
            }
            let size = self.session_manager.size().await;
            let count = self.session_manager.total_allocated();
            if self
                .session_manager
                .close_if_no_session_and_idle(size, count)
                .await
            {
                break;
            }
        }
    }
}
