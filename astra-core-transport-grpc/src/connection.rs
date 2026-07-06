use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::proto;

/// Wraps a gRPC bidirectional stream as AsyncRead + AsyncWrite (single-stream mode).
///
/// Uses internal mpsc channels to bridge poll-based IO with tonic's async gRPC streams.
pub struct HunkConn {
    read_buf: BytesMut,
    read_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    write_tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl HunkConn {
    pub fn new(
        mut grpc_rx: tonic::codec::Streaming<proto::Hunk>,
        grpc_tx: mpsc::Sender<proto::Hunk>,
    ) -> Self {
        let (read_tx, read_rx) = mpsc::unbounded_channel();
        let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        tokio::spawn(async move {
            while let Some(hunk) = grpc_rx.message().await.unwrap_or(None) {
                if read_tx.send(hunk.data.to_vec()).is_err() {
                    break;
                }
            }
        });

        tokio::spawn(async move {
            while let Some(data) = write_rx.recv().await {
                if grpc_tx.send(proto::Hunk { data: data }).await.is_err() {
                    break;
                }
            }
        });

        HunkConn {
            read_buf: BytesMut::new(),
            read_rx,
            write_tx,
        }
    }
}

impl AsyncRead for HunkConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.read_buf.is_empty() {
            let n = std::cmp::min(buf.remaining(), self.read_buf.len());
            buf.put_slice(&self.read_buf[..n]);
            self.read_buf.advance(n);
            return Poll::Ready(Ok(()));
        }

        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf.extend_from_slice(&data[n..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for HunkConn {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.write_tx.send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(std::io::Error::other("grpc write channel closed"))),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

/// Wraps a gRPC bidirectional stream as AsyncRead + AsyncWrite (multi-stream mode).
///
/// Batches multiple write chunks into a single MultiHunk gRPC message.
pub struct MultiHunkConn {
    inner: HunkConn,
}

impl MultiHunkConn {
    pub fn new(
        mut grpc_rx: tonic::codec::Streaming<proto::MultiHunk>,
        grpc_tx: mpsc::Sender<proto::MultiHunk>,
    ) -> Self {
        let (read_tx, read_rx) = mpsc::unbounded_channel();
        let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        tokio::spawn(async move {
            while let Some(multi) = grpc_rx.message().await.unwrap_or(None) {
                for chunk in multi.data {
                    if read_tx.send(chunk.to_vec()).is_err() {
                        return;
                    }
                }
            }
        });

        tokio::spawn(async move {
            while let Some(data) = write_rx.recv().await {
                let msg = proto::MultiHunk {
                    data: vec![data],
                };
                if grpc_tx.send(msg).await.is_err() {
                    break;
                }
            }
        });

        MultiHunkConn {
            inner: HunkConn {
                read_buf: BytesMut::new(),
                read_rx,
                write_tx,
            },
        }
    }
}

impl AsyncRead for MultiHunkConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for MultiHunkConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
