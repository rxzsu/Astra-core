use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// A bidirectional connection backed by mpsc channels.
/// read_rx provides data for AsyncRead, write_tx receives data from AsyncWrite.
pub struct SplitConn {
    read_rx: mpsc::Receiver<Vec<u8>>,
    write_tx: mpsc::Sender<Vec<u8>>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl SplitConn {
    pub fn new(read_rx: mpsc::Receiver<Vec<u8>>, write_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            read_rx,
            write_tx,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

impl AsyncRead for SplitConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.read_pos < this.read_buf.len() {
            let n = std::cmp::min(buf.remaining(), this.read_buf.len() - this.read_pos);
            buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + n]);
            this.read_pos += n;
            if this.read_pos >= this.read_buf.len() {
                this.read_buf.clear();
                this.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        match this.read_rx.try_recv() {
            Ok(data) => {
                let n = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    this.read_buf = data;
                    this.read_pos = n;
                }
                Poll::Ready(Ok(()))
            }
            Err(mpsc::error::TryRecvError::Empty) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TryRecvError::Disconnected) => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncWrite for SplitConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        match this.write_tx.try_send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "write channel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}
