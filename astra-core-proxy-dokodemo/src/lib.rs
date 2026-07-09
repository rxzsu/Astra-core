use std::collections::HashMap;
use std::sync::Arc;

use astra_core_net::{Address, Destination, Network, Port};
use astra_core_proxy::{async_trait, Conn, Dispatcher, InboundHandler, ProxyResult};
use astra_core_session::Session;
use astra_core_transport::new_link_stream;

#[derive(Debug, Clone, Default)]
pub struct InboundConfig {
    pub address: Option<Address>,
    pub port: u16,
    pub follow_redirect: bool,
    pub user_level: u32,
    /// Port mapping: local_port -> "addr:port"
    pub port_map: HashMap<String, String>,
}

pub struct Handler {
    config: InboundConfig,
}

impl Handler {
    pub fn new(config: InboundConfig) -> Self {
        Handler { config }
    }

    fn resolve_dest(
        &self,
        local_addr: &str,
        session: &Session,
    ) -> Result<Destination, String> {
        // FollowRedirect: use session outbound target
        if self.config.follow_redirect {
            if let Some(ref ob) = session.outbound {
                if ob.target.is_valid() {
                    return Ok(ob.target.clone());
                }
            }
        }

        // Derive destination from local address if no explicit address configured
        let dest_addr = if let Some(ref addr) = self.config.address {
            addr.clone()
        } else {
            let (host, _port) = split_host_port(local_addr);

            if host.contains(':') {
                Address::Ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
            } else if !host.is_empty() && host != "0.0.0.0" && host != "::" {
                if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                    Address::Ipv4(ip.octets())
                } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
                    Address::Ipv6(ip.octets())
                } else {
                    return Err("dokodemo: cannot resolve local address".into());
                }
            } else if self.config.follow_redirect {
                return Err("follow_redirect: no outbound target".into());
            } else {
                return Err("dokodemo: no address configured".into());
            }
        };

        let dest_port = if self.config.port > 0 {
            Port(self.config.port)
        } else {
            let (_host, port_str) = split_host_port(local_addr);
            let p: u16 = port_str.parse().unwrap_or(0);
            if p == 0 {
                return Err("dokodemo: no port".into());
            }
            Port(p)
        };

        let mut dest = Destination {
            address: dest_addr,
            port: dest_port,
            network: Network::Tcp,
        };

        // Apply port map
        let port_str = dest.port.value().to_string();
        if let Some(mapped) = self.config.port_map.get(&port_str) {
            let (host, port_str) = split_host_port(mapped);
            if !host.is_empty() {
                if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                    dest.address = Address::Ipv4(ip.octets());
                } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
                    dest.address = Address::Ipv6(ip.octets());
                } else {
                    dest.address = Address::Domain(host.to_string());
                }
            }
            if let Ok(p) = port_str.parse::<u16>() {
                dest.port = Port(p);
            }
        }

        Ok(dest)
    }
}

#[async_trait]
impl InboundHandler for Handler {
    async fn process(
        &self,
        session: Session,
        conn: Conn,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> ProxyResult<()> {
        let local_str = session.inbound.as_ref()
            .and_then(|i| i.local.as_ref())
            .map(|d| d.address.to_string())
            .unwrap_or_else(|| "0.0.0.0:0".to_string());
        let port_str = session.inbound.as_ref()
            .and_then(|i| i.local.as_ref())
            .map(|d| d.port.value().to_string())
            .unwrap_or_else(|| "0".to_string());
        let local_addr = format!("{}:{}", local_str, port_str);

        let dest = self.resolve_dest(&local_addr, &session)?;
        let link = dispatcher.dispatch(session, dest).await?;
        let mut link_stream = new_link_stream(link);
        let mut conn = conn;

        tokio::io::copy_bidirectional(&mut *conn, &mut link_stream)
            .await
            .map_err(|e| format!("dokodemo copy: {}", e))?;
        Ok(())
    }
}

// ─── TPROXY / FakeUDP ────────────────────────────────────────────────────────
// On Linux, creates a raw UDP socket with IP_TRANSPARENT for transparent proxy.
// On other platforms, returns error.

#[cfg(target_os = "linux")]
pub fn fake_udp(addr: &std::net::SocketAddrV4) -> Result<tokio::net::UdpSocket, String> {
    use std::os::unix::io::AsRawFd;
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if addr.ip().is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| format!("fake_udp socket: {}", e))?;

    let _ = sock.set_reuse_address(true);
    #[cfg(target_os = "linux")]
    {
        let _ = sock.set_reuse_port(true);
        let fd = sock.as_raw_fd();
        let optval: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_IP,
                libc::IP_TRANSPARENT,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    sock.bind(&socket2::SockAddr::from(*addr))
        .map_err(|e| format!("fake_udp bind: {}", e))?;

    let std_udp: std::net::UdpSocket = sock.into();
    std_udp.set_nonblocking(true)
        .map_err(|e| format!("fake_udp nonblock: {}", e))?;
    tokio::net::UdpSocket::from_std(std_udp)
        .map_err(|e| format!("fake_udp to tokio: {}", e))
}

#[cfg(not(target_os = "linux"))]
pub fn fake_udp(_addr: &std::net::SocketAddrV4) -> Result<tokio::net::UdpSocket, String> {
    Err("FakeUDP/TPROXY is only supported on Linux".into())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn split_host_port(s: &str) -> (String, String) {
    if let Some(idx) = s.rfind(':') {
        let host = &s[..idx];
        let port = &s[idx + 1..];
        (host.to_string(), port.to_string())
    } else {
        (s.to_string(), String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dokodemo_resolve_config() {
        let config = InboundConfig {
            address: Some(Address::Ipv4([1, 2, 3, 4])),
            port: 8080,
            ..Default::default()
        };
        let handler = Handler::new(config);
        let session = Session::default();
        let dest = handler.resolve_dest("127.0.0.1:12345", &session).unwrap();
        assert_eq!(dest.address.to_string(), "1.2.3.4");
        assert_eq!(dest.port.value(), 8080);
    }

    #[tokio::test]
    async fn test_dokodemo_follow_redirect() {
        let config = InboundConfig {
            follow_redirect: true,
            ..Default::default()
        };
        let handler = Handler::new(config);
        let session = Session {
            outbound: Some(astra_core_session::Outbound {
                target: Destination {
                    address: Address::Ipv4([10, 0, 0, 1]),
                    port: Port(443),
                    network: Network::Tcp,
                },
                original_target: Destination {
                    address: Address::Ipv4([10, 0, 0, 1]),
                    port: Port(443),
                    network: Network::Tcp,
                },
                route_target: None,
                tag: String::new(),
            }),
            ..Default::default()
        };
        let dest = handler.resolve_dest("127.0.0.1:12345", &session).unwrap();
        assert_eq!(dest.address.to_string(), "10.0.0.1");
        assert_eq!(dest.port.value(), 443);
    }

    #[tokio::test]
    async fn test_dokodemo_port_map() {
        let mut port_map = HashMap::new();
        port_map.insert("80".to_string(), "192.168.1.1:8080".to_string());
        let config = InboundConfig {
            address: Some(Address::Ipv4([0, 0, 0, 0])),
            port: 80,
            port_map,
            ..Default::default()
        };
        let handler = Handler::new(config);
        let session = Session::default();
        let dest = handler.resolve_dest("0.0.0.0:80", &session).unwrap();
        assert_eq!(dest.address.to_string(), "192.168.1.1");
        assert_eq!(dest.port.value(), 8080);
    }

    #[test]
    fn test_split_host_port() {
        let (h, p) = split_host_port("192.168.1.1:443");
        assert_eq!(h, "192.168.1.1");
        assert_eq!(p, "443");
    }
}
