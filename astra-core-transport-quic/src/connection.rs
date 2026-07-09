use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Wraps a QUIC bidirectional stream as AsyncRead + AsyncWrite.
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    eof: bool,
}

impl QuicStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        QuicStream {
            send,
            recv,
            eof: false,
        }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.eof {
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut self.recv).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().is_empty() {
                    self.eof = true;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(std::io::Error::other)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(std::io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(std::io::Error::other)
    }
}
