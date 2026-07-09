use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Buf;
use futures_core::stream::Stream;
use futures_sink::Sink;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::WebSocketStream;

/// Wraps a tokio-tungstenite WebSocket stream as an AsyncRead + AsyncWrite.
pub struct WsConnection<S> {
    ws: WebSocketStream<S>,
    read_buf: bytes::BytesMut,
}

impl<S> WsConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(ws: WebSocketStream<S>) -> Self {
        WsConnection {
            ws,
            read_buf: bytes::BytesMut::new(),
        }
    }
}

impl<S> AsyncRead for WsConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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

        loop {
            match Pin::new(&mut self.ws).poll_next(cx) {
                Poll::Ready(Some(Ok(msg))) => match msg {
                    tokio_tungstenite::tungstenite::Message::Binary(data) => {
                        let n = std::cmp::min(buf.remaining(), data.len());
                        buf.put_slice(&data[..n]);
                        if n < data.len() {
                            self.read_buf.extend_from_slice(&data[n..]);
                        }
                        return Poll::Ready(Ok(()));
                    }
                    tokio_tungstenite::tungstenite::Message::Ping(_)
                    | tokio_tungstenite::tungstenite::Message::Pong(_) => continue,
                    tokio_tungstenite::tungstenite::Message::Close(_) => {
                        return Poll::Ready(Ok(()));
                    }
                    _ => continue,
                },
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::other(e.to_string())));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for WsConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        use tokio_tungstenite::tungstenite::Message;

        match Pin::new(&mut self.ws).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(std::io::Error::other(e.to_string()))),
            Poll::Pending => return Poll::Pending,
        }

        let msg = Message::Binary(bytes::Bytes::from(buf.to_vec()));
        match Pin::new(&mut self.ws).start_send(msg) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(e) => Poll::Ready(Err(std::io::Error::other(e.to_string()))),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.ws)
            .poll_flush(cx)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.ws)
            .poll_close(cx)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}
