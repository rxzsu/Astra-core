use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite};

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
