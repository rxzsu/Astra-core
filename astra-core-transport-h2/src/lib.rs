use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub mod config;
pub mod dialer;
pub mod listener;

/// Wraps h2 SendStream + RecvStream as a bidirectional AsyncRead + AsyncWrite.
pub struct H2Stream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    recv_buf: BytesMut,
    closed: bool,
    send_closed: bool,
}

impl H2Stream {
    pub fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        H2Stream {
            send,
            recv,
            recv_buf: BytesMut::new(),
            closed: false,
            send_closed: false,
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if !self.recv_buf.is_empty() {
                let n = std::cmp::min(self.recv_buf.len(), buf.remaining());
                buf.put_slice(&self.recv_buf.split_to(n));
                return Poll::Ready(Ok(()));
            }
            if self.closed {
                return Poll::Ready(Ok(()));
            }
            match self.recv.poll_data(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    self.recv_buf.extend_from_slice(&data);
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::other(e)));
                }
                Poll::Ready(None) => {
                    self.closed = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.send_closed {
            return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "send closed")));
        }
        match self.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => {
                let len = buf.len().min(capacity);
                let data = Bytes::copy_from_slice(&buf[..len]);
                if let Err(e) = self.send.send_data(data, false) {
                    return Poll::Ready(Err(std::io::Error::other(e)));
                }
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(std::io::Error::other(e)))
            }
            Poll::Ready(None) => {
                self.send_closed = true;
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "stream closed")))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.send.send_data(Bytes::new(), true).ok();
        self.send_closed = true;
        Poll::Ready(Ok(()))
    }
}

pub fn build_tls_client_config() -> Result<rustls::ClientConfig, String> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(cfg)
}

pub fn build_tls_server_config(
    cert_data: Vec<u8>,
    key_data: Vec<u8>,
) -> Result<rustls::ServerConfig, String> {
    let cert = rustls::pki_types::CertificateDer::from(cert_data);
    let key = rustls::pki_types::PrivateKeyDer::try_from(key_data)
        .map_err(|e| format!("invalid tls key: {:?}", e))?;

    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| format!("tls config: {}", e))?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(cfg)
}
