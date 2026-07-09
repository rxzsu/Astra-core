/// No-op header for TCP connections. Passes data through unchanged.
/// Go equivalent: `transport/internet/headers/noop.NoOpConnectionHeader`
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A no-op connection wrapper that passes all data through.
/// Used as a default/fallback connection header.
pub struct NoOpConn<T: AsyncRead + AsyncWrite + Unpin>(pub T);

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for NoOpConn<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for NoOpConn<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

/// A no-op packet header with zero size.
/// Used in KCP and other transports where no header encoding is needed.
pub struct NoOpHeader;

impl NoOpHeader {
    pub const fn size() -> i32 {
        0
    }
    pub fn serialize(_buf: &mut [u8]) {}
}
