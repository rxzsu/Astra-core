use std::net::SocketAddr;
use std::sync::Arc;

use astra_core_net::{Address, Destination, Network, Port};
use astra_core_proxy::{async_trait, OutboundHandler, ProxyResult, UdpLink};
use astra_core_session::Session;
use astra_core_transport::{Link, UdpPacket};

/// Forwards DNS queries to a configured upstream DNS server.
pub struct Handler {
    server_addr: SocketAddr,
}

impl Handler {
    pub fn new(address: Address, port: u16) -> Result<Self, String> {
        let ip = address
            .as_ip()
            .ok_or_else(|| format!("dns server must be an IP address, got: {}", address))?;
        let server_addr = SocketAddr::new(ip, port);
        Ok(Handler { server_addr })
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    async fn process(&self, _session: Session, _link: &mut Link, _dialer: &dyn astra_core_proxy::Dialer) -> ProxyResult<()> {
        Err("DNS outbound only supports UDP".into())
    }

    async fn process_udp(&self, _session: Session, link: &mut UdpLink) -> ProxyResult<()> {
        let socket = Arc::new(
            tokio::net::UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| format!("bind udp: {}", e))?,
        );

        let writer = link.writer.clone();
        let sock_recv = socket.clone();
        let server = self.server_addr;

        // Receive responses from upstream DNS, send back through link
        let recv_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 512];
            loop {
                match sock_recv.recv_from(&mut buf).await {
                    Ok((n, _)) => {
                        let addr = match server.ip() {
                            std::net::IpAddr::V4(v4) => Address::Ipv4(v4.octets()),
                            std::net::IpAddr::V6(v6) => Address::Ipv6(v6.octets()),
                        };
                        let dest = Destination { address: addr, port: Port(server.port()), network: Network::Udp };
                        let pkt = UdpPacket::new(dest.clone(), dest, buf[..n].to_vec());
                        if writer.send(pkt).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Read query packets from link, forward to upstream DNS
        while let Some(packet) = link.recv().await {
            if socket.send_to(&packet.data, self.server_addr).await.is_err() {
                break;
            }
        }

        let _ = recv_handle.await;
        Ok(())
    }
}
