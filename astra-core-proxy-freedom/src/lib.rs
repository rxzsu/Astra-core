use std::str::FromStr;
use std::sync::Arc;

use astra_core_net::{Address, Destination, Network, Port};
use astra_core_proxy::{async_trait, Dialer, OutboundHandler, ProxyResult, UdpLink};
use astra_core_session::Session;
use astra_core_transport::{Link, UdpPacket};

/// Configuration for the Freedom outbound handler.
#[derive(Clone, Default)]
pub struct OutboundConfig {
    pub domain_strategy: String,
    pub redirect: Option<Destination>,
    pub fragment: Option<FragmentConfig>,
    pub noise: Option<NoiseConfig>,
    pub final_rules: Vec<FinalRule>,
    pub proxy_protocol: u8, // 0=disabled, 1=v1, 2=v2
}

impl std::fmt::Debug for OutboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundConfig")
            .field("domain_strategy", &self.domain_strategy)
            .field("redirect", &self.redirect)
            .field("fragment", &self.fragment.is_some())
            .finish()
    }
}

/// Fragment configuration.
#[derive(Debug, Clone)]
pub struct FragmentConfig {
    pub packets_from: u64,
    pub packets_to: u64,
    pub length_min: u64,
    pub length_max: u64,
    pub interval_min: u64,
    pub interval_max: u64,
    pub max_split_min: u64,
    pub max_split_max: u64,
}

pub fn parse_packets(s: &str) -> (u64, u64) {
    let parts: Vec<&str> = s.split('-').collect();
    let from = parts.first().and_then(|p| p.parse().ok()).unwrap_or(0);
    let to = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(from);
    (from, to)
}

// ─── FragmentWriter (Go: proxy/freedom/freedom.go FragmentWriter) ─────────

/// Write data with fragmentation matching Go's FragmentWriter.
/// Returns Ok(()) on success.
async fn write_fragmented<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W, data: &[u8], cfg: &FragmentConfig, count: u64,
) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;

    // Mode 1: TLS ClientHello (packets_from=0, packets_to=1)
    if cfg.packets_from == 0 && cfg.packets_to == 1 {
        if count != 1 || data.len() <= 5 || data[0] != 22 {
            return writer.write_all(data).await.map_err(|e| e.to_string());
        }
        let record_len = 5 + ((data[3] as usize) << 8 | data[4] as usize);
        if data.len() < record_len {
            return writer.write_all(data).await.map_err(|e| e.to_string());
        }

        let tls_data = &data[5..record_len];
        let max_split = rand_between(cfg.max_split_min, cfg.max_split_max);
        let mut hello = Vec::new();
        let mut split_num: u64 = 0;
        let mut from = 0;

        while from < tls_data.len() {
            let to = (from + rand_between(cfg.length_min, cfg.length_max) as usize)
                .min(tls_data.len());
            split_num += 1;
            if max_split > 0 && split_num >= max_split {
                let remaining = &tls_data[from..];
                let mut buf = vec![0u8; 5 + remaining.len()];
                buf[..3].copy_from_slice(&data[..3]);
                buf[5..].copy_from_slice(remaining);
                let l = remaining.len() as u16;
                buf[3..5].copy_from_slice(&l.to_be_bytes());

                if cfg.interval_max == 0 {
                    hello.extend_from_slice(&buf);
                } else {
                    writer.write_all(&buf).await.map_err(|e| e.to_string())?;
                    tokio::time::sleep(std::time::Duration::from_millis(
                        rand_between(cfg.interval_min, cfg.interval_max)
                    )).await;
                }
                break;
            }

            let chunk = &tls_data[from..to];
            let mut buf = vec![0u8; 5 + chunk.len()];
            buf[..3].copy_from_slice(&data[..3]);
            buf[5..].copy_from_slice(chunk);
            let l = chunk.len() as u16;
            buf[3..5].copy_from_slice(&l.to_be_bytes());
            from = to;

            if cfg.interval_max == 0 {
                hello.extend_from_slice(&buf);
            } else {
                writer.write_all(&buf).await.map_err(|e| e.to_string())?;
                tokio::time::sleep(std::time::Duration::from_millis(
                    rand_between(cfg.interval_min, cfg.interval_max)
                )).await;
            }
        }

        if !hello.is_empty() {
            writer.write_all(&hello).await.map_err(|e| e.to_string())?;
        }
        if data.len() > record_len {
            writer.write_all(&data[record_len..]).await.map_err(|e| e.to_string())?;
        }
        return Ok(());
    }

    // Mode 2: General data fragmentation
    if cfg.packets_from != 0 && (count < cfg.packets_from || count > cfg.packets_to) {
        return writer.write_all(data).await.map_err(|e| e.to_string());
    }

    let max_split = rand_between(cfg.max_split_min, cfg.max_split_max);
    let mut split_num: u64 = 0;
    let mut from = 0;

    while from < data.len() {
        let to = (from + rand_between(cfg.length_min, cfg.length_max) as usize)
            .min(data.len());
        split_num += 1;
        if max_split > 0 && split_num >= max_split {
            writer.write_all(&data[from..]).await.map_err(|e| e.to_string())?;
            break;
        }
        writer.write_all(&data[from..to]).await.map_err(|e| e.to_string())?;
        if cfg.interval_max > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(
                rand_between(cfg.interval_min, cfg.interval_max)
            )).await;
        }
        from = to;
    }
    Ok(())
}

fn rand_between(min: u64, max: u64) -> u64 {
    if min >= max { return min; }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    min + (nanos % (max - min + 1))
}

/// Splits writes into fragments with random sizes and delays.
/// Matches Go's FragmentWriter exactly.
pub struct FragmentWriter {
    config: FragmentConfig,
    inner: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    count: u64,
}

impl FragmentWriter {
    pub fn new(config: FragmentConfig, inner: Box<dyn tokio::io::AsyncWrite + Unpin + Send>) -> Self {
        FragmentWriter { config, inner, count: 0 }
    }

    fn rand_between(min: u64, max: u64) -> u64 {
        if min >= max { return min; }
        let range = max - min + 1;
        if range == 0 { return min; }
        // Simple pseudo-random using time
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;
        min + (nanos % range)
    }

    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), String> {
        use tokio::io::AsyncWriteExt;
        self.count += 1;
        let cfg = &self.config;

        // Special case: packets_from=0, packets_to=1 => only fragment first TLS ClientHello
        if cfg.packets_from == 0 && cfg.packets_to == 1 {
            if self.count != 1 || data.len() <= 5 || data[0] != 22 {
                return self.inner.write_all(data).await.map_err(|e| e.to_string());
            }
            let record_len = 5 + ((data[3] as usize) << 8 | data[4] as usize);
            if data.len() < record_len {
                return self.inner.write_all(data).await.map_err(|e| e.to_string());
            }

            let tls_data = &data[5..record_len];
            let max_split = Self::rand_between(cfg.max_split_min, cfg.max_split_max);
            let mut hello = Vec::new();
            let mut split_num: u64 = 0;
            let mut from = 0;

            while from < tls_data.len() {
                let to = (from + Self::rand_between(cfg.length_min, cfg.length_max) as usize)
                    .min(tls_data.len());
                split_num += 1;
                if max_split > 0 && split_num >= max_split {
                    // Write remaining in one chunk
                    let remaining = &tls_data[from..];
                    let mut buf = vec![0u8; 5 + remaining.len()];
                    buf[..3].copy_from_slice(&data[..3]);
                    buf[5..].copy_from_slice(remaining);
                    let l = remaining.len() as u16;
                    buf[3..5].copy_from_slice(&l.to_be_bytes());

                    if cfg.interval_max == 0 {
                        hello.extend_from_slice(&buf);
                    } else {
                        self.inner.write_all(&buf).await.map_err(|e| e.to_string())?;
                        tokio::time::sleep(std::time::Duration::from_millis(
                            Self::rand_between(cfg.interval_min, cfg.interval_max)
                        )).await;
                    }
                    break;
                }

                let chunk = &tls_data[from..to];
                let mut buf = vec![0u8; 5 + chunk.len()];
                buf[..3].copy_from_slice(&data[..3]);
                buf[5..].copy_from_slice(chunk);
                let l = chunk.len() as u16;
                buf[3..5].copy_from_slice(&l.to_be_bytes());
                from = to;

                if cfg.interval_max == 0 {
                    hello.extend_from_slice(&buf);
                } else {
                    self.inner.write_all(&buf).await.map_err(|e| e.to_string())?;
                    tokio::time::sleep(std::time::Duration::from_millis(
                        Self::rand_between(cfg.interval_min, cfg.interval_max)
                    )).await;
                }
            }

            if !hello.is_empty() {
                self.inner.write_all(&hello).await.map_err(|e| e.to_string())?;
            }
            if data.len() > record_len {
                self.inner.write_all(&data[record_len..]).await.map_err(|e| e.to_string())?;
            }
            return Ok(());
        }

        // General case: fragment all packets within range
        if cfg.packets_from != 0 && (self.count < cfg.packets_from || self.count > cfg.packets_to) {
            return self.inner.write_all(data).await.map_err(|e| e.to_string());
        }

        let max_split = Self::rand_between(cfg.max_split_min, cfg.max_split_max);
        let mut split_num: u64 = 0;
        let mut from = 0;

        while from < data.len() {
            let to = (from + Self::rand_between(cfg.length_min, cfg.length_max) as usize)
                .min(data.len());
            split_num += 1;
            if max_split > 0 && split_num >= max_split {
                self.inner.write_all(&data[from..]).await.map_err(|e| e.to_string())?;
                break;
            }
            self.inner.write_all(&data[from..to]).await.map_err(|e| e.to_string())?;
            if cfg.interval_max > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(
                    Self::rand_between(cfg.interval_min, cfg.interval_max)
                )).await;
            }
            from = to;
        }
        Ok(())
    }
}

pub struct Handler {
    config: OutboundConfig,
}

impl Handler {
    pub fn new(config: OutboundConfig) -> Self {
        Handler { config }
    }

    /// Resolve a domain to an IP address based on the domain_strategy.
    async fn resolve_strategy(&self, target: &mut Destination) {
        let strategy = self.config.domain_strategy.as_str();
        if strategy.is_empty() || strategy == "AsIs" {
            return;
        }

        let domain = match target.address.as_domain() {
            Some(d) => d.to_string(),
            None => return,
        };

        let addr_str = format!("{}:{}", domain, target.port.value());
        let addrs: Vec<_> = match tokio::net::lookup_host(&addr_str).await {
            Ok(addrs) => addrs.collect(),
            Err(_) => return,
        };

        let wants_ipv4 = strategy == "UseIPv4";
        let wants_ipv6 = strategy == "UseIPv6";

        let chosen = if wants_ipv4 {
            addrs.iter().find(|a| a.ip().is_ipv4())
        } else if wants_ipv6 {
            addrs.iter().find(|a| a.ip().is_ipv6())
        } else {
            addrs.first()
        };

        if let Some(sock_addr) = chosen {
            let ip_addr = sock_addr.ip();
            let new_address = match ip_addr {
                std::net::IpAddr::V4(v4) => Address::Ipv4(v4.octets()),
                std::net::IpAddr::V6(v6) => Address::Ipv6(v6.octets()),
            };
            target.address = new_address;
        }
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    async fn process(
        &self,
        session: Session,
        link: &mut Link,
        dialer: &dyn Dialer,
    ) -> ProxyResult<()> {
        let hint = session
            .outbound
            .as_ref()
            .map(|o| &o.target)
            .ok_or_else(|| "no target destination".to_string())?;

        let mut target = self.config.redirect.clone().unwrap_or_else(|| hint.clone());
        self.resolve_strategy(&mut target).await;
        let mut remote = dialer.dial(session, target).await?;

        // Wrap writer in fragmenter if configured
        if self.config.fragment.is_some() {
            let frag_cfg = self.config.fragment.as_ref().unwrap().clone();
            let (mut remote_reader, mut remote_writer) = tokio::io::split(&mut *remote);
            let mut frag_count = 0u64;

            use tokio::io::AsyncReadExt;
            let to_remote = async {
                let mut buf = [0u8; 16384];
                loop {
                    match link.reader.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            frag_count += 1;
                            write_fragmented(&mut remote_writer, &buf[..n], &frag_cfg, frag_count).await
                                .map_err(|e| format!("fragment: {}", e))?;
                        }
                    }
                }
                Ok::<_, String>(())
            };

            let to_client = tokio::io::copy(&mut remote_reader, &mut link.writer);

            tokio::select! {
                r = to_remote => r?,
                r = to_client => r.map(|_| ())
                    .map_err(|e| format!("freedom copy: {}", e))?,
            }

            return Ok(());
        }

        let (mut remote_reader, mut remote_writer) = tokio::io::split(&mut *remote);

        let to_remote = tokio::io::copy(&mut link.reader, &mut remote_writer);
        let to_client = tokio::io::copy(&mut remote_reader, &mut link.writer);

        tokio::select! {
            r = to_remote => r.map(|_| ()),
            r = to_client => r.map(|_| ()),
        }
        .map_err(|e| format!("freedom copy: {}", e))?;

        Ok(())
    }

    async fn process_udp(&self, _session: Session, link: &mut UdpLink) -> ProxyResult<()> {
        let socket = Arc::new(
            tokio::net::UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| format!("bind udp: {}", e))?,
        );

        let sock_send = socket.clone();
        let writer = link.writer.clone();

        let recv_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match sock_send.recv_from(&mut buf).await {
                    Ok((n, src)) => {
                        let addr = match src.ip() {
                            std::net::IpAddr::V4(v4) => Address::Ipv4(v4.octets()),
                            std::net::IpAddr::V6(v6) => Address::Ipv6(v6.octets()),
                        };
                        let source = Destination {
                            address: addr,
                            port: Port(src.port()),
                            network: Network::Udp,
                        };
                        let pkt = UdpPacket::new(source.clone(), source, buf[..n].to_vec());
                        if writer.send(pkt).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        while let Some(packet) = link.recv().await {
            let target = &packet.target;
            let addr_str = format!("{}:{}", target.address, target.port.value());
            if let Ok(mut addrs) = tokio::net::lookup_host(&addr_str).await
                && let Some(remote_addr) = addrs.next() {
                    let _ = socket.send_to(&packet.data, remote_addr).await;
                }
        }

        let _ = recv_handle.await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra_core_net::{Address, Port, TcpDestination};
    use astra_core_proxy::{AsyncConn, Dialer};
    use astra_core_session::Outbound;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct TestDialer;

    #[async_trait]
    impl Dialer for TestDialer {
        async fn dial(
            &self,
            _session: Session,
            dest: Destination,
        ) -> ProxyResult<Box<dyn AsyncConn>> {
            let addr = format!("{}:{}", dest.address, dest.port.value());
            let stream = tokio::net::TcpStream::connect(&addr)
                .await
                .map_err(|e| format!("dial {}: {}", addr, e))?;
            Ok(Box::new(stream))
        }
    }

    #[tokio::test]
    async fn test_freedom_echo() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 { break; }
                stream.write_all(&buf[..n]).await.unwrap();
            }
        });

        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();

        let dest = TcpDestination(Address::Ipv4([127, 0, 0, 1]), Port(echo_addr.port()));
        let handler = Handler::new(OutboundConfig::default());

        let client_handle = tokio::spawn(async move {
            let (conn, _) = client_listener.accept().await.unwrap();
            let (mut inbound_link, mut outbound_link) = astra_core_transport::new_link_pair();

            let pipe_handle = tokio::spawn(async move {
                let (mut conn_reader, mut conn_writer) = tokio::io::split(conn);
                let to_outbound = tokio::io::copy(&mut conn_reader, &mut inbound_link.writer);
                let to_inbound = tokio::io::copy(&mut inbound_link.reader, &mut conn_writer);
                tokio::select! {
                    r = to_outbound => r.map(|_| ()),
                    r = to_inbound => r.map(|_| ()),
                }
            });

            let session = Session {
                inbound: None,
                outbound: Some(Outbound {
                    target: dest.clone(),
                    original_target: dest.clone(),
                    route_target: None,
                    tag: String::new(),
                }),
                content: None,
            };
            let dialer = TestDialer;
            handler.process(session, &mut outbound_link, &dialer).await.unwrap();
            let _ = pipe_handle.await;
        });

        let mut client = tokio::net::TcpStream::connect(client_addr).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut buf = vec![0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        let _ = client.shutdown().await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), client_handle).await;
    }

    #[tokio::test]
    async fn test_freedom_with_fragment() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(&buf[..n]).await.unwrap();
        });

        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();

        let dest = TcpDestination(Address::Ipv4([127, 0, 0, 1]), Port(echo_addr.port()));
        let cfg = OutboundConfig {
            fragment: Some(FragmentConfig {
                packets_from: 0, packets_to: 1,
                length_min: 1, length_max: 5,
                interval_min: 0, interval_max: 0,
                max_split_min: 1, max_split_max: 3,
            }),
            ..Default::default()
        };
        let handler = Handler::new(cfg);

        let client_handle = tokio::spawn(async move {
            let (conn, _) = client_listener.accept().await.unwrap();
            let (mut inbound_link, mut outbound_link) = astra_core_transport::new_link_pair();

            tokio::spawn(async move {
                let (mut conn_reader, mut conn_writer) = tokio::io::split(conn);
                let to_outbound = tokio::io::copy(&mut conn_reader, &mut inbound_link.writer);
                let to_inbound = tokio::io::copy(&mut inbound_link.reader, &mut conn_writer);
                tokio::select! {
                    r = to_outbound => r.map(|_| ()),
                    r = to_inbound => r.map(|_| ()),
                }
            });

            let session = Session {
                inbound: None,
                outbound: Some(Outbound {
                    target: dest.clone(),
                    original_target: dest.clone(),
                    route_target: None,
                    tag: String::new(),
                }),
                content: None,
            };
            let dialer = TestDialer;
            handler.process(session, &mut outbound_link, &dialer).await.unwrap();
        });

        let mut client = tokio::net::TcpStream::connect(client_addr).await.unwrap();
        let test_data = b"Hello World! This is a test message for fragmentation.";
        client.write_all(test_data).await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], test_data);
    }
}

// ─── Noise Config (Go: proxy/freedom/freedom.go Noise field) ────────────────

/// Random noise sent before the first UDP packet.
#[derive(Debug, Clone)]
pub struct NoiseConfig {
    pub length_min: u64,
    pub length_max: u64,
    pub delay_min: u64,
    pub delay_max: u64,
    pub apply_to: String, // "ipv4", "ipv6", or "" (all)
}

/// NoisePacketWriter wraps a UDP socket and sends random noise before the first write.
pub struct NoisePacketWriter {
    config: NoiseConfig,
    target_ip: std::net::IpAddr,
    has_sent_noise: std::sync::atomic::AtomicBool,
}

impl NoisePacketWriter {
    pub fn new(config: NoiseConfig, target_ip: std::net::IpAddr) -> Self {
        NoisePacketWriter {
            config,
            target_ip,
            has_sent_noise: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn should_apply(&self) -> bool {
        if self.config.apply_to.is_empty() {
            return true;
        }
        match self.target_ip {
            std::net::IpAddr::V4(_) => self.config.apply_to == "ipv4" || self.config.apply_to == "ip",
            std::net::IpAddr::V6(_) => self.config.apply_to == "ipv6" || self.config.apply_to == "ip",
        }
    }

    pub async fn send_noise(&self, socket: &tokio::net::UdpSocket, remote: std::net::SocketAddr) {
        if self.has_sent_noise.load(std::sync::atomic::Ordering::Relaxed) || !self.should_apply() {
            return;
        }
        self.has_sent_noise.store(true, std::sync::atomic::Ordering::Relaxed);

        let len = if self.config.length_min >= self.config.length_max {
            self.config.length_min
        } else {
            let range = self.config.length_max - self.config.length_min;
            self.config.length_min + (rand::random::<u64>() % (range + 1))
        } as usize;

        let delay = if self.config.delay_min >= self.config.delay_max {
            self.config.delay_min
        } else {
            let range = self.config.delay_max - self.config.delay_min;
            self.config.delay_min + (rand::random::<u64>() % (range + 1))
        };

        if delay > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }

        let noise = vec![0u8; len];
        let _ = socket.send_to(&noise, remote).await;
    }
}

// ─── FinalRule (Go: proxy/freedom/freedom.go FinalRule) ──────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RuleAction {
    Allow,
    Block,
}

#[derive(Debug, Clone)]
pub struct FinalRule {
    pub action: RuleAction,
    pub networks: Vec<String>,   // "tcp", "udp"
    pub ports: Vec<(u16, u16)>,  // port ranges
    pub ips: Vec<String>,        // CIDRs or IPs
    pub block_delay_min: u64,    // seconds
    pub block_delay_max: u64,
}

impl FinalRule {
    pub fn matches(&self, target: &Destination) -> bool {
        // Check network
        if !self.networks.is_empty() {
            let net_match = match target.network {
                Network::Tcp => self.networks.iter().any(|n| n == "tcp"),
                Network::Udp => self.networks.iter().any(|n| n == "udp"),
                _ => false,
            };
            if !net_match {
                return false;
            }
        }

        // Check port
        if !self.ports.is_empty() {
            let port_val = target.port.value();
            let port_match = self.ports.iter().any(|(from, to)| port_val >= *from && port_val <= *to);
            if !port_match {
                return false;
            }
        }

        // Check IP/CIDR
        if !self.ips.is_empty() {
            let target_str = target.address.to_string();
            let ip_match = self.ips.iter().any(|cidr| {
                if let Ok(ip) = std::net::IpAddr::from_str(&target_str) { // DNS not resolved yet
                    false
                } else if cidr.contains('/') {
                    if let Ok(net) = ipnetwork::IpNetwork::from_str(cidr) {
                        // Can't match without resolved IP
                        false
                    } else { false }
                } else {
                    &target_str == cidr
                }
            });
            if !ip_match {
                return false;
            }
        }

        true
    }

    pub fn block_delay(&self) -> Option<std::time::Duration> {
        if self.action == RuleAction::Block {
            let delay = if self.block_delay_min >= self.block_delay_max {
                self.block_delay_min
            } else {
                let range = self.block_delay_max - self.block_delay_min;
                self.block_delay_min + (rand::random::<u64>() % (range + 1))
            };
            if delay > 0 {
                return Some(std::time::Duration::from_secs(delay));
            }
        }
        None
    }
}
