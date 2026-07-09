use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::config::Config;
use crate::connection::{ConnMetadata, Connection, PacketCloser, PacketWriter};
use crate::io::KcpPacketReader;

#[derive(Clone, Hash, Eq, PartialEq)]
struct SessionId {
    remote: SocketAddr,
    conv: u16,
}

struct SessionWriter {
    socket: Arc<UdpSocket>,
    dest: SocketAddr,
}

#[async_trait::async_trait]
impl PacketWriter for SessionWriter {
    async fn write_packet(&self, buf: &[u8]) -> std::io::Result<()> {
        self.socket.send_to(buf, self.dest).await?;
        Ok(())
    }
}

struct SessionCloser {
    id: SessionId,
    sessions: Arc<Mutex<HashMap<SessionId, Arc<Connection>>>>,
}

#[async_trait::async_trait]
impl PacketCloser for SessionCloser {
    async fn close(&self) {
        let mut sessions = self.sessions.lock().await;
        sessions.remove(&self.id);
    }
}

pub async fn listen_kcp(
    bind_addr: SocketAddr,
    config: Config,
    handler: Arc<dyn Fn(Arc<Connection>) + Send + Sync>,
) -> std::io::Result<()> {
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    let local_addr = socket.local_addr()?;
    let sessions: Arc<Mutex<HashMap<SessionId, Arc<Connection>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let reader = KcpPacketReader;

    let mut buf = vec![0u8; 65536];
    loop {
        let (n, remote) = socket.recv_from(&mut buf).await?;
        if n == 0 {
            continue;
        }
        let segments = reader.read(&buf[..n]);
        if segments.is_empty() {
            continue;
        }

        let conv = segments[0].conv();
        let id = SessionId { remote, conv };

        let conn = {
            let lock = sessions.lock().await;
            lock.get(&id).cloned()
        };

        let conn = match conn {
            Some(c) => c,
            None => {
                let writer = Arc::new(SessionWriter {
                    socket: socket.clone(),
                    dest: id.remote,
                });
                let closer = Arc::new(SessionCloser {
                    id: id.clone(),
                    sessions: sessions.clone(),
                });
                let meta = ConnMetadata {
                    local_addr,
                    remote_addr: id.remote,
                    conversation: conv,
                };
                let conn = Connection::new(meta, writer, closer, config.clone());

                let mut lock = sessions.lock().await;
                lock.insert(id.clone(), conn.clone());
                drop(lock);

                handler(conn.clone());
                conn
            }
        };

        conn.input(segments).await;
    }
}
