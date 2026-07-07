use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::ReadBuf;
use tokio::time::Sleep;

use crate::AsyncConn;

/// Wraps any AsyncRead + AsyncWrite with per-operation idle timeout.
/// Always used behind `Box<TimeoutConn>` which provides `Unpin`.
pub struct TimeoutConn {
    inner: Box<dyn AsyncConn>,
    read_deadline: Pin<Box<Sleep>>,
    write_deadline: Pin<Box<Sleep>>,
    idle: Duration,
}

impl TimeoutConn {
    pub fn new(inner: Box<dyn AsyncConn>, idle: Duration) -> Self {
        let now = tokio::time::Instant::now();
        TimeoutConn {
            inner,
            read_deadline: Box::pin(tokio::time::sleep_until(now + idle)),
            write_deadline: Box::pin(tokio::time::sleep_until(now + idle)),
            idle,
        }
    }

    fn bump_read(&mut self) {
        self.read_deadline = Box::pin(tokio::time::sleep(self.idle));
    }

    fn bump_write(&mut self) {
        self.write_deadline = Box::pin(tokio::time::sleep(self.idle));
    }
}

impl tokio::io::AsyncRead for TimeoutConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // SAFETY: TimeoutConn is always behind Box<TimeoutConn> which is Unpin.
        // Pin guarantees are preserved.
        let this = unsafe { self.get_unchecked_mut() };
        if this.read_deadline.as_mut().poll(cx).is_ready() {
            this.bump_read();
            return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "read idle timeout")));
        }
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if result.is_ready() {
            this.bump_read();
        }
        result
    }
}

impl tokio::io::AsyncWrite for TimeoutConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = unsafe { self.get_unchecked_mut() };
        if this.write_deadline.as_mut().poll(cx).is_ready() {
            this.bump_write();
            return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "write idle timeout")));
        }
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if result.is_ready() {
            this.bump_write();
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let this = unsafe { self.get_unchecked_mut() };
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let this = unsafe { self.get_unchecked_mut() };
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
