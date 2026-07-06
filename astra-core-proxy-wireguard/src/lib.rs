//! WireGuard outbound — port of Go `proxy/wireguard/`.
//!
//! Requires a TUN interface or netstack for full functionality.
//! This implementation provides the WireGuard tunnel management and UDP transport.

use std::sync::Arc;

use astra_core_net::{Address, Destination, Network, Port};
use astra_core_proxy::{async_trait, Dialer, OutboundHandler, ProxyResult, UdpLink};
use astra_core_session::Session;
use astra_core_transport::{Link, UdpPacket};

/// WireGuard peer configuration.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub endpoint_address: Address,
    pub endpoint_port: u16,
    pub public_key: Vec<u8>,      // 32 bytes
    pub pre_shared_key: Vec<u8>,   // 32 bytes (optional, zeros if not used)
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: u32,
}

/// WireGuard device configuration.
#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub private_key: Vec<u8>,     // 32 bytes
    pub listen_port: u16,          // 0 = auto
    pub peers: Vec<PeerConfig>,
}

/// WireGuard outbound handler.
/// Establishes a WireGuard tunnel to the configured peer and routes traffic through it.
pub struct Handler {
    config: DeviceConfig,
    /// WireGuard tunnel instance (full implementation requires TUN/netstack integration)
    tunnel: Option<Arc<tokio::sync::Mutex<WireGuardTunnel>>>,
}

/// Simple WireGuard tunnel using UDP.
/// For a production implementation, this needs integration with boringtun's noise protocol
/// and a TUN device or netstack for IP-level routing.
struct WireGuardTunnel {
    peer: PeerConfig,
    private_key: Vec<u8>,
    udp_socket: tokio::net::UdpSocket,
}

impl WireGuardTunnel {
    async fn connect(peer: PeerConfig, private_key: Vec<u8>, listen_port: u16) -> ProxyResult<Self> {
        let bind_addr = if listen_port > 0 { format!("0.0.0.0:{}", listen_port) } else { "0.0.0.0:0".to_string() };
        let socket = tokio::net::UdpSocket::bind(&bind_addr)
            .await
            .map_err(|e| format!("wg bind: {}", e))?;

        let endpoint = format!("{}:{}", peer.endpoint_address, peer.endpoint_port);
        socket.connect(&endpoint).await.map_err(|e| format!("wg connect: {}", e))?;

        // WireGuard handshake would happen here using boringtun's noise::Tunn
        // For now, we establish a basic UDP connection

        Ok(WireGuardTunnel { peer, private_key, udp_socket: socket })
    }

    async fn send(&self, data: &[u8]) -> Result<(), String> {
        
        // Real implementation: encrypt with WireGuard noise protocol
        self.udp_socket.send(data).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, String> {
        // Real implementation: decrypt with WireGuard noise protocol
        self.udp_socket.recv(buf).await.map_err(|e| e.to_string())
    }
}

impl Handler {
    pub fn new(config: DeviceConfig) -> Self {
        Handler { config, tunnel: None }
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    async fn process(
        &self,
        _session: Session,
        _link: &mut Link,
        _dialer: &dyn Dialer,
    ) -> ProxyResult<()> {
        Err("WireGuard outbound: requires TUN/netstack integration — use as UDP forwarder".into())
    }

    async fn process_udp(&self, _session: Session, link: &mut UdpLink) -> ProxyResult<()> {
        let peer = self.config.peers.first().cloned()
            .ok_or_else(|| "WireGuard: no peer configured".to_string())?;
        let private_key = self.config.private_key.clone();
        let listen_port = self.config.listen_port;

        let tunnel = WireGuardTunnel::connect(peer, private_key, listen_port).await?;
        let tunnel = Arc::new(tokio::sync::Mutex::new(tunnel));

        let t_send = tunnel.clone();
        let writer = link.writer.clone();
        let recv_handle = tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                let n = match t_send.lock().await.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => break,
                };
                let pkt = UdpPacket::new(
                    Destination { address: Address::Ipv4([0;4]), port: Port(0), network: Network::Udp },
                    Destination { address: Address::Ipv4([0;4]), port: Port(0), network: Network::Udp },
                    buf[..n].to_vec(),
                );
                if writer.send(pkt).is_err() { break; }
            }
        });

        while let Some(pkt) = link.recv().await {
            if tunnel.lock().await.send(&pkt.data).await.is_err() { break; }
        }

        let _ = recv_handle.await;
        Ok(())
    }
}
