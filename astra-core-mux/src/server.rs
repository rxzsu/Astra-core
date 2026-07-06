use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time;

use crate::frame::{read_frame, write_frame, FrameMetadata, SessionStatus};
use crate::session::{Session, SessionManager};

/// A mux server that accepts sessions from a single mux connection.
///
/// Corresponds to Go's `mux.ServerWorker`.
pub struct MuxServer<R, W> {
    session_manager: Arc<SessionManager>,
    writer: tokio::sync::Mutex<W>,
    reader: tokio::sync::Mutex<R>,
    done: Arc<AtomicBool>,
    #[allow(dead_code)]
    done_notify: Arc<tokio::sync::Notify>,
    new_session_tx: tokio::sync::mpsc::UnboundedSender<u16>,
}

impl<R: AsyncRead + Unpin + Send + 'static, W: AsyncWrite + Unpin + Send + 'static>
    MuxServer<R, W>
{
    pub fn new(reader: R, writer: W) -> (Arc<Self>, tokio::sync::mpsc::UnboundedReceiver<u16>) {
        let session_manager = Arc::new(SessionManager::new());
        let done = Arc::new(AtomicBool::new(false));
        let done_notify = Arc::new(tokio::sync::Notify::new());
        let (new_session_tx, new_session_rx) = tokio::sync::mpsc::unbounded_channel();

        let server = Arc::new(MuxServer {
            session_manager: session_manager.clone(),
            writer: tokio::sync::Mutex::new(writer),
            reader: tokio::sync::Mutex::new(reader),
            done: done.clone(),
            done_notify: done_notify.clone(),
            new_session_tx,
        });

        let s = server.clone();
        tokio::spawn(async move {
            s.read_loop().await;
            done.store(true, Ordering::Relaxed);
            done_notify.notify_waiters();
        });

        let s2 = server.clone();
        tokio::spawn(async move {
            s2.monitor_loop().await;
        });

        (server, new_session_rx)
    }

    pub fn session_manager(&self) -> &Arc<SessionManager> {
        &self.session_manager
    }

    pub async fn write_frame(&self, meta: &FrameMetadata, data: Option<&[u8]>) -> Result<(), String> {
        let mut writer = self.writer.lock().await;
        write_frame(&mut *writer, meta, data).await
    }

    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::Relaxed)
    }

    async fn read_loop(&self) {
        let mut reader = self.reader.lock().await;
        loop {
            let (meta, data) = match read_frame(&mut *reader).await {
                Ok(m) => m,
                Err(_) => break,
            };

            match meta.status {
                SessionStatus::New => {
                    let session = Arc::new(Session::new(meta.session_id));
                    self.session_manager.add(session.clone()).await;
                    let _ = self.new_session_tx.send(meta.session_id);
                }
                SessionStatus::Keep => {
                    if let Some(session) = self.session_manager.get(meta.session_id).await {
                        if let Some(ch) = session.channels.lock().await.as_ref() {
                            if let Some(data) = &data {
                                let _ = ch.data_tx.send(data.clone());
                            }
                        }
                    }
                }
                SessionStatus::End => {
                    if let Some(session) = self.session_manager.get(meta.session_id).await {
                        if let Some(ch) = session.channels.lock().await.take() {
                            let _ = ch.close_tx.send(());
                        }
                        session.close();
                    }
                    self.session_manager.remove(meta.session_id).await;
                }
                _ => {}
            }
        }
    }

    async fn monitor_loop(&self) {
        let mut interval = time::interval(Duration::from_secs(60));
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
