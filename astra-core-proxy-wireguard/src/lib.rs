use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

use astra_core_net::{Address, Destination, Network, Port};
use astra_core_proxy::{Dialer, OutboundHandler, ProxyResult, UdpLink, async_trait};
use astra_core_session::Session;
use astra_core_transport::{Link, UdpPacket};

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub endpoint: String, // host:port, domain resolved at connect time
    pub public_key: [u8; 32],
    pub pre_shared_key: Option<[u8; 32]>,
    pub persistent_keepalive: u32,
    pub allowed_ips: Vec<String>, // CIDR notation
}

#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub private_key: [u8; 32],
    pub listen_port: u16,
    pub peers: Vec<PeerConfig>,
}

impl DeviceConfig {
    fn resolve_endpoint(endpoint: &str) -> Result<String, String> {
        if let Some((host, _port)) = endpoint.rsplit_once(':') {
            if host.parse::<IpAddr>().is_ok() {
                Ok(endpoint.to_string())
            } else {
                Err(format!("async resolution needed for {}", endpoint))
            }
        } else {
            Err(format!("invalid endpoint: {}", endpoint))
        }
    }
}

pub struct WireGuardTunnel {
    tunn: tokio::sync::Mutex<Tunn>,
    udp: Arc<tokio::net::UdpSocket>,
    running: Arc<AtomicBool>,
}

impl WireGuardTunnel {
    pub async fn connect(config: &DeviceConfig) -> ProxyResult<Arc<Self>> {
        let peer = config.peers.first().ok_or_else(|| "no peer".to_string())?;
        let endpoint = DeviceConfig::resolve_endpoint(&peer.endpoint)?;

        let bind = if config.listen_port > 0 {
            format!("0.0.0.0:{}", config.listen_port)
        } else {
            "0.0.0.0:0".to_string()
        };
        let udp = Arc::new(
            tokio::net::UdpSocket::bind(&bind)
                .await
                .map_err(|e| format!("bind: {}", e))?,
        );
        udp.connect(&endpoint)
            .await
            .map_err(|e| format!("connect: {}", e))?;

        let private = StaticSecret::from(config.private_key);
        let public = PublicKey::from(peer.public_key);
        let keepalive = if peer.persistent_keepalive > 0 {
            Some(peer.persistent_keepalive as u16)
        } else {
            None
        };

        let tunn = Tunn::new(private, public, peer.pre_shared_key, keepalive, 0, None);

        let running = Arc::new(AtomicBool::new(true));
        let tunnel = Arc::new(WireGuardTunnel {
            tunn: tokio::sync::Mutex::new(tunn),
            udp: udp.clone(),
            running: running.clone(),
        });

        let t = tunnel.clone();
        tokio::spawn(async move {
            t.run_loop().await;
        });

        Ok(tunnel)
    }

    async fn run_loop(&self) {
        let mut dst = [0u8; 2000];
        loop {
            if !self.running.load(Ordering::Relaxed) {
                break;
            }
            let mut tunn = self.tunn.lock().await;
            match tunn.encapsulate(&[], &mut dst) {
                TunnResult::WriteToNetwork(data) => {
                    let _ = self.udp.send(data).await;
                }
                TunnResult::Done => {
                    drop(tunn);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                TunnResult::Err(_) => break,
                _ => {}
            }
        }
    }

    pub async fn encapsulate(&self, data: &[u8]) -> ProxyResult<Vec<u8>> {
        let mut dst = [0u8; 2000];
        let mut tunn = self.tunn.lock().await;
        match tunn.encapsulate(data, &mut dst) {
            TunnResult::WriteToNetwork(data) => Ok(data.to_vec()),
            TunnResult::Done => Err("tunnel not ready".into()),
            TunnResult::Err(e) => Err(format!("wg enc: {:?}", e)),
            _ => Err("unexpected".into()),
        }
    }

    pub async fn decapsulate(&self, data: &[u8]) -> ProxyResult<Vec<u8>> {
        let mut dst = [0u8; 2000];
        let mut tunn = self.tunn.lock().await;
        match tunn.decapsulate(None, data, &mut dst) {
            TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                Ok(data.to_vec())
            }
            TunnResult::WriteToNetwork(data) => {
                let _ = self.udp.send(data).await;
                Err("handshake in progress".into())
            }
            TunnResult::Done => Err("no data".into()),
            TunnResult::Err(e) => Err(format!("wg dec: {:?}", e)),
        }
    }

    pub fn close(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

pub struct Handler {
    pub config: DeviceConfig,
}

impl Handler {
    pub fn new(config: DeviceConfig) -> Self {
        Handler { config }
    }

    /// Create tunnels for each peer. In a real impl, this would use a routing table
    /// based on AllowedIPs. For now, return the primary peer tunnel.
    async fn connect_peers(&self) -> ProxyResult<Arc<WireGuardTunnel>> {
        WireGuardTunnel::connect(&self.config).await
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    async fn process(
        &self,
        _session: Session,
        link: &mut Link,
        _dialer: &dyn Dialer,
    ) -> ProxyResult<()> {
        let tunnel = self.connect_peers().await?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let t = tunnel.clone();
        let to_remote = async {
            let mut buf = [0u8; 16384];
            loop {
                let n = match link.reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if let Ok(enc) = t.encapsulate(&buf[..n]).await {
                    let _ = t.udp.send(&enc).await;
                }
            }
            Ok::<_, String>(())
        };

        let to_client = async {
            let mut buf = [0u8; 65535];
            loop {
                let n = match tunnel.udp.recv(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => break,
                };
                if let Ok(dec) = tunnel.decapsulate(&buf[..n]).await
                    && link.writer.write_all(&dec).await.is_err()
                {
                    break;
                }
            }
            Ok::<_, String>(())
        };

        tokio::select! {
            r = to_remote => r?,
            r = to_client => r?,
        }
        Ok(())
    }

    async fn process_udp(&self, _session: Session, link: &mut UdpLink) -> ProxyResult<()> {
        let tunnel = self.connect_peers().await?;

        let t = tunnel.clone();
        let writer = link.writer.clone();
        let recv = tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                let n = match t.udp.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => break,
                };
                if let Ok(dec) = t.decapsulate(&buf[..n]).await {
                    let pkt = UdpPacket::new(
                        Destination {
                            address: Address::Ipv4([0; 4]),
                            port: Port(0),
                            network: Network::Udp,
                        },
                        Destination {
                            address: Address::Ipv4([0; 4]),
                            port: Port(0),
                            network: Network::Udp,
                        },
                        dec,
                    );
                    if writer.send(pkt).is_err() {
                        break;
                    }
                }
            }
        });

        while let Some(pkt) = link.recv().await {
            if let Ok(enc) = tunnel.encapsulate(&pkt.data).await {
                let _ = tunnel.udp.send(&enc).await;
            }
        }

        let _ = recv.await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_endpoint_ip() {
        let result = DeviceConfig::resolve_endpoint("1.2.3.4:51820");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "1.2.3.4:51820");
    }

    #[test]
    fn test_peer_config_basic() {
        let peer = PeerConfig {
            endpoint: "10.0.0.1:51820".into(),
            public_key: [0u8; 32],
            pre_shared_key: None,
            persistent_keepalive: 25,
            allowed_ips: vec!["0.0.0.0/0".into()],
        };
        assert_eq!(peer.endpoint, "10.0.0.1:51820");
    }

    #[test]
    fn test_device_config() {
        let cfg = DeviceConfig {
            private_key: [1u8; 32],
            listen_port: 51820,
            peers: vec![PeerConfig {
                endpoint: "192.168.1.1:51820".into(),
                public_key: [2u8; 32],
                pre_shared_key: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["10.0.0.0/8".into()],
            }],
        };
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].allowed_ips[0], "10.0.0.0/8");
    }
}
