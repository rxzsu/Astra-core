/// VStream — WebSocket over HTTP/1.1 upgrade transport.
/// Go equivalent: `transport/internet/headers/` VStream.
/// Uses HTTP Upgrade mechanism (not the WebSocket protocol) for proxying.
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// VStream connection wrapping a TCP stream with HTTP upgrade headers.
pub struct VStream<T: AsyncRead + AsyncWrite + Unpin> {
    inner: T,
}

impl<T: AsyncRead + AsyncWrite + Unpin> VStream<T> {
    pub fn new(inner: T) -> Self {
        VStream { inner }
    }

    /// Perform the HTTP/1.1 upgrade handshake.
    pub async fn handshake(&mut self, host: &str, path: &str) -> Result<(), String> {
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            path, host
        );
        self.inner
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("vstream handshake write: {}", e))?;

        // Read response (simplified — read first line)
        let mut buf = [0u8; 1024];
        let n = self
            .inner
            .read(&mut buf)
            .await
            .map_err(|e| format!("vstream handshake read: {}", e))?;
        let response = String::from_utf8_lossy(&buf[..n]);
        if !response.contains("101") && !response.contains("Switching Protocols") {
            return Err(format!(
                "vstream handshake failed: {}",
                response.lines().next().unwrap_or("unknown")
            ));
        }
        Ok(())
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for VStream<T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VStream<T> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
