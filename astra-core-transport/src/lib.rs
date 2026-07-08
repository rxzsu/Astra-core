use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite};

use astra_core_net::Destination;

/// CounterConnection — wraps a connection with byte counters.
/// Go equivalent: `transport/internet/stat.CounterConnection`
pub struct CounterConnection<T: AsyncRead + AsyncWrite + Unpin> {
    inner: T,
    pub read_counter: Arc<AtomicI64>,
    pub write_counter: Arc<AtomicI64>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> CounterConnection<T> {
    pub fn new(inner: T) -> Self {
        CounterConnection {
            inner,
            read_counter: Arc::new(AtomicI64::new(0)),
            write_counter: Arc::new(AtomicI64::new(0)),
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for CounterConnection<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        let after = buf.filled().len();
        self.read_counter.fetch_add((after - before) as i64, Ordering::Relaxed);
        result
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for CounterConnection<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            self.write_counter.fetch_add(*n as i64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct Link {
    pub reader: tokio::io::DuplexStream,
    pub writer: tokio::io::DuplexStream,
}

pub fn new_link_pair() -> (Link, Link) {
    let (up_reader, up_writer) = tokio::io::duplex(64 * 1024);
    let (down_reader, down_writer) = tokio::io::duplex(64 * 1024);
    (
        Link {
            reader: down_reader,
            writer: up_writer,
        },
        Link {
            reader: up_reader,
            writer: down_writer,
        },
    )
}

pub struct LinkStream {
    pub reader: tokio::io::DuplexStream,
    pub writer: tokio::io::DuplexStream,
}

impl AsyncRead for LinkStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for LinkStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

pub fn new_link_stream(link: Link) -> LinkStream {
    LinkStream {
        reader: link.reader,
        writer: link.writer,
    }
}

/// A single UDP datagram with routing info.
#[derive(Debug, Clone)]
pub struct UdpPacket {
    pub source: Destination,
    pub target: Destination,
    pub data: Vec<u8>,
}

impl UdpPacket {
    pub fn new(source: Destination, target: Destination, data: Vec<u8>) -> Self {
        UdpPacket { source, target, data }
    }
}

/// Bidirectional UDP packet channel.
/// `reader` receives packets, `writer` sends packets.
pub struct UdpLink {
    pub reader: tokio::sync::mpsc::UnboundedReceiver<UdpPacket>,
    pub writer: tokio::sync::mpsc::UnboundedSender<UdpPacket>,
}

impl UdpLink {
    pub async fn recv(&mut self) -> Option<UdpPacket> {
        self.reader.recv().await
    }

    pub fn send(&self, packet: UdpPacket) -> Result<(), String> {
        self.writer.send(packet).map_err(|_| "udp link closed".into())
    }
}

pub mod tagged;
pub mod vstream;

pub fn new_udp_link_pair() -> (UdpLink, UdpLink) {
    let (tx1, rx1) = tokio::sync::mpsc::unbounded_channel();
    let (tx2, rx2) = tokio::sync::mpsc::unbounded_channel();
    (
        UdpLink { reader: rx1, writer: tx2 },
        UdpLink { reader: rx2, writer: tx1 },
    )
}
