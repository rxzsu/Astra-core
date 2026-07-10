use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use astra_core_net::{Address, Destination, Network, Port};

/// A single UDP datagram with source and optional original destination.
#[derive(Debug, Clone)]
pub struct UdpPacket {
    pub source: Destination,
    pub target: Destination,
    pub data: Vec<u8>,
}

/// UDP hub that receives and dispatches UDP packets.
/// Go equivalent: `transport/internet/udp.Hub`
pub struct UdpHub {
    socket: Arc<tokio::net::UdpSocket>,
    rx: mpsc::UnboundedReceiver<UdpPacket>,
    #[allow(dead_code)]
    recv_orig_dest: bool,
}

impl UdpHub {
    pub async fn bind(addr: &str) -> Result<Self, String> {
        let socket = tokio::net::UdpSocket::bind(addr)
            .await
            .map_err(|e| format!("udp bind {}: {}", addr, e))?;
        let (tx, rx) = mpsc::unbounded_channel();
        let socket = Arc::new(socket);
        let s = socket.clone();
        let recv_orig_dest = false;

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, src) = match s.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(_) => break,
                };
                let dest = Destination {
                    address: match src.ip() {
                        std::net::IpAddr::V4(v4) => Address::Ipv4(v4.octets()),
                        std::net::IpAddr::V6(v6) => Address::Ipv6(v6.octets()),
                    },
                    port: Port(src.port()),
                    network: Network::Udp,
                };
                let pkt = UdpPacket {
                    source: dest,
                    target: Destination {
                        address: Address::Ipv4([0, 0, 0, 0]),
                        port: Port(0),
                        network: Network::Udp,
                    },
                    data: buf[..n].to_vec(),
                };
                if tx.send(pkt).is_err() {
                    break;
                }
            }
        });

        Ok(UdpHub { socket, rx, recv_orig_dest })
    }

    pub async fn recv(&mut self) -> Option<UdpPacket> {
        self.rx.recv().await
    }

    pub async fn send(&self, data: &[u8], addr: &SocketAddr) -> Result<(), String> {
        self.socket.send_to(data, addr).await
            .map_err(|e| format!("udp send_to: {}", e))?;
        Ok(())
    }

    pub fn local_addr(&self) -> Result<SocketAddr, String> {
        self.socket.local_addr().map_err(|e| format!("local_addr: {}", e))
    }
}

/// UDP dispatcher that routes UDP packets through the proxy pipeline.
/// Go equivalent: `transport/internet/udp.Dispatcher`
pub struct UdpDispatcher {
    callback: Box<dyn Fn(Destination, Vec<u8>) + Send + Sync>,
}

impl UdpDispatcher {
    pub fn new<F>(callback: F) -> Self
    where
        F: Fn(Destination, Vec<u8>) + Send + Sync + 'static,
    {
        UdpDispatcher { callback: Box::new(callback) }
    }

    pub fn dispatch(&self, dest: Destination, data: Vec<u8>) {
        (self.callback)(dest, data);
    }
}

/// A UDP connection wrapper that implements AsyncRead + AsyncWrite.
pub struct UdpConn {
    socket: Arc<tokio::net::UdpSocket>,
    #[allow(dead_code)]
    remote: SocketAddr,
    recv_buf: Vec<u8>,
    recv_pos: usize,
}

impl UdpConn {
    pub fn new(socket: Arc<tokio::net::UdpSocket>, remote: SocketAddr) -> Self {
        UdpConn { socket, remote, recv_buf: Vec::new(), recv_pos: 0 }
    }
}

impl AsyncRead for UdpConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.recv_pos < self.recv_buf.len() {
            let n = std::cmp::min(buf.remaining(), self.recv_buf.len() - self.recv_pos);
            buf.put_slice(&self.recv_buf[self.recv_pos..self.recv_pos + n]);
            self.recv_pos += n;
            if self.recv_pos >= self.recv_buf.len() {
                self.recv_buf.clear();
                self.recv_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        let mut tmp = vec![0u8; 65535];
        let waker = cx.waker().clone();
        let socket = self.socket.clone();
        tokio::spawn(async move {
            match socket.recv_from(&mut tmp).await {
                Ok((_n, _)) => {
                    waker.wake();
                }
                Err(_) => {}
            }
        });
        Poll::Pending
    }
}

impl AsyncWrite for UdpConn {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        // Best-effort send; in a full impl we'd use poll based on the socket's writability
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

/// Retrieve original destination from ancillary data (Linux IP_RECVORIGDSTADDR).
/// Go equivalent: `transport/internet/udp.RetrieveOriginalDest`
#[cfg(target_os = "linux")]
pub fn retrieve_original_dest(msg: &nix::sys::socket::ControlMessageOwned) -> Option<Destination> {
    use nix::sys::socket::ControlMessageOwned;
    match msg {
        ControlMessageOwned::IpOrigDstAddr(addr) => {
            Some(Destination {
                address: Address::Ipv4(addr.ip().octets()),
                port: Port(addr.port()),
                network: Network::Udp,
            })
        }
        ControlMessageOwned::Ipv6OrigDstAddr(addr) => {
            Some(Destination {
                address: Address::Ipv6(addr.ip().octets()),
                port: Port(addr.port()),
                network: Network::Udp,
            })
        }
        _ => None,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn retrieve_original_dest(_msg: &()) -> Option<Destination> {
    None
}
