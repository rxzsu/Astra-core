use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use tokio::net::UdpSocket;

use crate::config::Config;
use crate::connection::{ConnMetadata, Connection, PacketCloser, PacketWriter};
use crate::io::KcpPacketReader;

static GLOBAL_CONV: AtomicU16 = AtomicU16::new(1);

struct UdpPacketWriter {
    socket: Arc<UdpSocket>,
    remote: SocketAddr,
}

#[async_trait::async_trait]
impl PacketWriter for UdpPacketWriter {
    async fn write_packet(&self, buf: &[u8]) -> std::io::Result<()> {
        self.socket.send_to(buf, self.remote).await?;
        Ok(())
    }
}

struct UdpCloser;

#[async_trait::async_trait]
impl PacketCloser for UdpCloser {
    async fn close(&self) {
        // UDP sockets don't need closing per-connection
    }
}

pub async fn dial_kcp(
    bind_addr: SocketAddr,
    remote_addr: SocketAddr,
    config: Config,
) -> std::io::Result<Arc<Connection>> {
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    socket.connect(remote_addr).await?;

    let conv = GLOBAL_CONV.fetch_add(1, Ordering::Relaxed);

    let meta = ConnMetadata {
        local_addr: socket.local_addr()?,
        remote_addr,
        conversation: conv,
    };

    let writer = Arc::new(UdpPacketWriter {
        socket: socket.clone(),
        remote: remote_addr,
    });
    let closer = Arc::new(UdpCloser);

    let conn = Connection::new(meta, writer, closer, config.clone());

    let reader = KcpPacketReader;
    let c = conn.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; config.mtu as usize];
        loop {
            let n = match socket.recv(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => break,
            };
            let segments = reader.read(&buf[..n]);
            if !segments.is_empty() {
                c.input(segments).await;
            }
        }
    });

    Ok(conn)
}
