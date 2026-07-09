use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio::sync::mpsc;

use crate::client::MuxClient;
use crate::frame::{FrameMetadata, FrameOption, SessionStatus};
use crate::server::MuxServer;
use crate::session::SessionChannels;

type MuxWriteFn = Arc<
    dyn Fn(u16, Vec<u8>) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> + Send + Sync,
>;

type MuxCloseFn = Arc<
    dyn Fn(u16, bool) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> + Send + Sync,
>;

/// Adapter that wraps a mux session as an AsyncRead + AsyncWrite stream.
///
/// - Reading: receives data from the mux read loop via the session's data channel.
/// - Writing: sends data frames through the mux client/server to the remote peer.
pub struct SessionIo {
    session_id: u16,
    data_rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    write_fn: MuxWriteFn,
    close_fn: MuxCloseFn,
    read_buf: Vec<u8>,
    read_pos: usize,
    eof: bool,
    shutdown: bool,
}

impl SessionIo {
    pub fn new(
        session_id: u16,
        data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
        write_fn: MuxWriteFn,
        close_fn: MuxCloseFn,
    ) -> Self {
        SessionIo {
            session_id,
            data_rx: Mutex::new(data_rx),
            write_fn,
            close_fn,
            read_buf: Vec::new(),
            read_pos: 0,
            eof: false,
            shutdown: false,
        }
    }

    /// Create the write/close function pair from a mux client.
    pub fn make_fns<R, W>(mux: &Arc<MuxClient<R, W>>) -> (MuxWriteFn, MuxCloseFn)
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
        W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let mux_w = mux.clone();
        let write_fn: MuxWriteFn = Arc::new(move |session_id, data| {
            let mux = mux_w.clone();
            Box::pin(async move {
                let mut meta = FrameMetadata::new(session_id, SessionStatus::Keep);
                meta.option.set(FrameOption::DATA);
                mux.write_frame(&meta, Some(&data)).await
            })
        });

        let mux_c = mux.clone();
        let close_fn: MuxCloseFn = Arc::new(move |session_id, has_error| {
            let mux = mux_c.clone();
            Box::pin(async move {
                let mut meta = FrameMetadata::new(session_id, SessionStatus::End);
                if has_error {
                    meta.option.set(FrameOption::ERROR);
                }
                mux.write_frame(&meta, None).await
            })
        });

        (write_fn, close_fn)
    }

    /// Create the write/close function pair from a mux server.
    pub fn make_fns_server<R, W>(mux: &Arc<MuxServer<R, W>>) -> (MuxWriteFn, MuxCloseFn)
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
        W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let mux_w = mux.clone();
        let write_fn: MuxWriteFn = Arc::new(move |session_id, data| {
            let mux = mux_w.clone();
            Box::pin(async move {
                let mut meta = FrameMetadata::new(session_id, SessionStatus::Keep);
                meta.option.set(FrameOption::DATA);
                mux.write_frame(&meta, Some(&data)).await
            })
        });

        let mux_c = mux.clone();
        let close_fn: MuxCloseFn = Arc::new(move |session_id, has_error| {
            let mux = mux_c.clone();
            Box::pin(async move {
                let mut meta = FrameMetadata::new(session_id, SessionStatus::End);
                if has_error {
                    meta.option.set(FrameOption::ERROR);
                }
                mux.write_frame(&meta, None).await
            })
        });

        (write_fn, close_fn)
    }
}

/// Helper to create a `SessionIo` from a `MuxClient` after allocating a session.
pub async fn open_mux_stream<R, W>(mux: &Arc<MuxClient<R, W>>) -> Option<SessionIo>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let session = mux.open_session().await?;
    let (data_tx, data_rx) = mpsc::unbounded_channel();
    let (close_tx, _close_rx) = tokio::sync::oneshot::channel();
    let ch = SessionChannels { data_tx, close_tx };
    session.attach_channels(ch).await;
    let (write_fn, close_fn) = SessionIo::make_fns(mux);
    Some(SessionIo::new(session.id, data_rx, write_fn, close_fn))
}

impl AsyncRead for SessionIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Drain internal buffer first.
        if this.read_pos < this.read_buf.len() {
            let remaining = &this.read_buf[this.read_pos..];
            let len = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..len]);
            this.read_pos += len;
            if this.read_pos >= this.read_buf.len() {
                this.read_buf.clear();
                this.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        if this.eof {
            return Poll::Ready(Ok(()));
        }

        // Try to receive next chunk from the session channel.
        let mut rx = match this.data_rx.try_lock() {
            Ok(guard) => guard,
            Err(_) => return Poll::Pending,
        };

        match rx.try_recv() {
            Ok(data) => {
                let len = data.len().min(buf.remaining());
                buf.put_slice(&data[..len]);
                if len < data.len() {
                    this.read_buf = data;
                    this.read_pos = len;
                }
                Poll::Ready(Ok(()))
            }
            Err(mpsc::error::TryRecvError::Empty) => Poll::Pending,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                this.eof = true;
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for SessionIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        if this.shutdown {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "session closed",
            )));
        }

        let data = buf.to_vec();
        let session_id = this.session_id;
        let write_fn = this.write_fn.clone();

        tokio::spawn(async move {
            let _ = write_fn(session_id, data).await;
        });

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        if this.shutdown {
            return Poll::Ready(Ok(()));
        }
        this.shutdown = true;

        let session_id = this.session_id;
        let close_fn = this.close_fn.clone();

        tokio::spawn(async move {
            let _ = close_fn(session_id, false).await;
        });

        Poll::Ready(Ok(()))
    }
}
