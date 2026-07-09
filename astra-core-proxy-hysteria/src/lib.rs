use std::any::Any;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use astra_core_net::{Address, Destination, Network, Port};
use astra_core_proxy::{Conn, Dispatcher, InboundHandler, OutboundHandler, ProxyResult};
use astra_core_proxy::dialer::Dialer;
use astra_core_session::{Inbound, Session};
use astra_core_transport::{Link, UdpLink, UdpPacket};
use quinn::crypto::rustls::QuicClientConfig;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

// ─── Config ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HysteriaConfig {
    pub server: Option<String>,
    pub server_name: Option<String>,
    pub password: String,
    pub up: String,
    pub down: String,
    #[serde(default)]
    pub obfs: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HysteriaInboundConfig {
    pub password: String,
    pub obfs: Option<String>,
}

// ─── Auth protocol & padding ──────────────────────────────────────────────────

const PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

pub fn random_padding(min: usize, max: usize) -> String {
    let n = min + fastrand::usize(..(max - min));
    (0..n).map(|_| PADDING_CHARS[fastrand::usize(..PADDING_CHARS.len())] as char).collect()
}

#[derive(Serialize, Deserialize)]
struct AuthRequest {
    auth: String,
}

#[derive(Serialize, Deserialize)]
struct AuthResponse {
    ok: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    error: String,
}

// ─── Bandwidth parsing ─────────────────────────────────────────────────────

fn parse_bandwidth(s: &str) -> Result<u64, String> {
    let s = s.trim().to_lowercase();
    if let Some(v) = s.strip_suffix("mbps").or_else(|| s.strip_suffix("m")) {
        let v: f64 = v.trim().parse().map_err(|_| format!("invalid bandwidth: {}", s))?;
        Ok((v * 1_000_000.0) as u64)
    } else if let Some(v) = s.strip_suffix("kbps").or_else(|| s.strip_suffix("k")) {
        let v: f64 = v.trim().parse().map_err(|_| format!("invalid bandwidth: {}", s))?;
        Ok((v * 1_000.0) as u64)
    } else if let Some(v) = s.strip_suffix("gbps").or_else(|| s.strip_suffix("g")) {
        let v: f64 = v.trim().parse().map_err(|_| format!("invalid bandwidth: {}", s))?;
        Ok((v * 1_000_000_000.0) as u64)
    } else if let Some(v) = s.strip_suffix("bps").or_else(|| s.strip_suffix("b")) {
        let v: f64 = v.trim().parse().map_err(|_| format!("invalid bandwidth: {}", s))?;
        Ok(v as u64)
    } else {
        s.parse::<f64>()
            .map(|v| (v * 1_000_000.0) as u64)
            .map_err(|_| format!("invalid bandwidth: {}", s))
    }
}

// ─── Brutal congestion controller ─────────────────────────────────────────

pub struct BrutalController {
    target_bps: u64,
    min_cwnd: u64,
    max_cwnd: u64,
    cwnd: u64,
}

impl BrutalController {
    pub fn new(target_bps: u64) -> Self {
        let cwnd = (target_bps / 8).max(2048);
        BrutalController {
            target_bps,
            min_cwnd: 2048,
            max_cwnd: cwnd * 10,
            cwnd,
        }
    }
}

impl quinn::congestion::Controller for BrutalController {
    fn on_ack(&mut self, _now: Instant, _sent: Instant, _bytes: u64, _app_limited: bool, _rtt: &quinn_proto::RttEstimator) {
        if self.cwnd < self.max_cwnd {
            let target = (self.target_bps / 8).max(self.min_cwnd);
            if self.cwnd < target {
                self.cwnd += ((target - self.cwnd) / 16).max(1);
            }
        }
    }

    fn on_congestion_event(&mut self, _now: Instant, _sent: Instant, _is_persistent: bool, _lost_bytes: u64) {
        if _is_persistent || _lost_bytes > 0 {
            self.cwnd = (self.cwnd as f64 * 0.7) as u64;
            if self.cwnd < self.min_cwnd {
                self.cwnd = self.min_cwnd;
            }
        }
    }

    fn on_mtu_update(&mut self, _new_mtu: u16) {}

    fn window(&self) -> u64 { self.cwnd }

    fn initial_window(&self) -> u64 { self.min_cwnd }

    fn clone_box(&self) -> Box<dyn quinn::congestion::Controller> {
        Box::new(BrutalController {
            target_bps: self.target_bps,
            min_cwnd: self.min_cwnd,
            max_cwnd: self.max_cwnd,
            cwnd: self.cwnd,
        })
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> { self }
}

struct BrutalFactory {
    target_bps: u64,
}

impl quinn::congestion::ControllerFactory for BrutalFactory {
    fn build(self: Arc<Self>, _now: Instant, _current_mtu: u16) -> Box<dyn quinn::congestion::Controller> {
        Box::new(BrutalController::new(self.target_bps))
    }
}

// ─── QUIC connection pool ──────────────────────────────────────────────────

struct QuicPool {
    conn: tokio::sync::Mutex<Option<quinn::Connection>>,
    config: HysteriaConfig,
}

impl QuicPool {
    fn new(config: HysteriaConfig) -> Self {
        QuicPool { conn: tokio::sync::Mutex::new(None), config }
    }

    async fn get_or_create(&self) -> Result<quinn::Connection, String> {
        let mut guard = self.conn.lock().await;
        if let Some(ref conn) = *guard
            && conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
        let conn = Self::dial_quic(&self.config).await?;
        *guard = Some(conn.clone());
        Ok(conn)
    }

    async fn dial_quic(config: &HysteriaConfig) -> Result<quinn::Connection, String> {
        let server = config.server.as_ref().ok_or("hysteria: no server addr")?;
        let remote: SocketAddr = server.parse().map_err(|e| format!("invalid server: {}", e))?;
        let bind: SocketAddr = if remote.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };

        let endpoint = quinn::Endpoint::client(bind).map_err(|e| format!("endpoint: {}", e))?;
        let server_name = config.server_name.as_deref().unwrap_or("localhost");

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let quic_cfg = QuicClientConfig::try_from(tls_cfg).map_err(|e| format!("tls: {}", e))?;
        let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));

        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(100u32.into());
        transport.datagram_receive_buffer_size(Some(65536));

        let up_bps = parse_bandwidth(&config.up)?;
        transport.congestion_controller_factory(Arc::new(BrutalFactory { target_bps: up_bps }));

        client_cfg.transport_config(Arc::new(transport));

        let connecting = endpoint.connect_with(client_cfg, remote, server_name)
            .map_err(|e| format!("connect: {}", e))?;
        let conn = connecting.await.map_err(|e| format!("handshake: {}", e))?;

        // Auth: JSON on first stream
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| format!("auth stream: {}", e))?;
        let auth = AuthRequest { auth: config.password.clone() };
        let body = serde_json::to_string(&auth).map_err(|e| format!("serialize auth: {}", e))?;
        send.write_all(body.as_bytes()).await.map_err(|e| format!("send auth: {}", e))?;
        send.write_all(b"\n").await.map_err(|e| format!("send auth nl: {}", e))?;
        send.finish().map_err(|e| format!("finish auth: {}", e))?;

        let buf = recv.read_to_end(65536).await.map_err(|e| format!("read auth: {}", e))?;
        let resp: AuthResponse = serde_json::from_slice(&buf).map_err(|e| format!("parse auth: {}", e))?;
        if !resp.ok {
            return Err(format!("auth rejected: {}", resp.error));
        }
        drop((send, recv));
        Ok(conn)
    }
}

// ─── Hysteria Outbound ─────────────────────────────────────────────────────

pub struct HysteriaOutbound {
    pool: Arc<QuicPool>,
}

impl HysteriaOutbound {
    pub fn new(config: HysteriaConfig) -> Self {
        HysteriaOutbound { pool: Arc::new(QuicPool::new(config)) }
    }
}

#[async_trait::async_trait]
impl OutboundHandler for HysteriaOutbound {
    async fn process(
        &self,
        session: Session,
        link: &mut Link,
        _dialer: &dyn Dialer,
    ) -> ProxyResult<()> {
        let conn = self.pool.get_or_create().await?;
        let dest = &session.outbound.as_ref().ok_or("no outbound target")?.target;
        let addr_str = format!("{}:{}", dest.address, dest.port.value());

        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| format!("open stream: {}", e))?;
        let mut addr_bytes = addr_str.into_bytes();
        addr_bytes.push(b'\n');
        send.write_all(&addr_bytes).await.map_err(|e| format!("send addr: {}", e))?;

        let c1 = tokio::io::copy(&mut link.reader, &mut send);
        let c2 = tokio::io::copy(&mut recv, &mut link.writer);
        tokio::pin!(c1, c2);

        tokio::select! {
            _ = c1 => {},
            _ = c2 => {},
        };
        Ok(())
    }

    async fn process_udp(
        &self,
        session: Session,
        link: &mut UdpLink,
    ) -> ProxyResult<()> {
        let conn = self.pool.get_or_create().await?;
        let dest = &session.outbound.as_ref().ok_or("no outbound target")?.target;
        let addr_str = format!("{}:{}\n", dest.address, dest.port.value());

        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| format!("open stream: {}", e))?;
        send.write_all(addr_str.as_bytes()).await.map_err(|e| format!("send addr: {}", e))?;
        send.write_all(b"u\n").await.map_err(|e| format!("send udp mode: {}", e))?;

        let placeholder = Destination {
            address: Address::Ipv4([0, 0, 0, 0]),
            port: Port(0),
            network: Network::Udp,
        };

        let link_writer = link.writer.clone();
        let link_reader = &mut link.reader;

        // link -> stream (length-prefixed packets)
        let to_stream = async {
            loop {
                let pkt = link_reader.recv().await;
                match pkt {
                    Some(pkt) => {
                        let len = pkt.data.len() as u16;
                        send.write_all(&len.to_be_bytes()).await
                            .map_err(|e| format!("write udp len: {}", e))?;
                        send.write_all(&pkt.data).await
                            .map_err(|e| format!("write udp data: {}", e))?;
                    }
                    None => break,
                }
            }
            #[allow(unreachable_code)]
            Ok::<_, String>(())
        };

        // stream -> link (length-prefixed packets)
        let to_link = async {
            let mut len_buf = [0u8; 2];
            loop {
                match recv.read_exact(&mut len_buf).await {
                    Ok(()) => {
                        let len = u16::from_be_bytes(len_buf) as usize;
                        let mut data = vec![0u8; len];
                        if recv.read_exact(&mut data).await.is_err() {
                            break;
                        }
                        let pkt = UdpPacket::new(placeholder.clone(), placeholder.clone(), data);
                        if link_writer.send(pkt).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            #[allow(unreachable_code)]
            Ok::<_, String>(())
        };

        tokio::select! {
            _ = to_stream => {},
            _ = to_link => {},
        };
        Ok(())
    }
}

// ─── Hysteria Inbound ──────────────────────────────────────────────────────

pub struct HysteriaInbound {
    config: HysteriaInboundConfig,
}

impl HysteriaInbound {
    pub fn new(config: HysteriaInboundConfig) -> Self {
        HysteriaInbound { config }
    }

    pub fn password(&self) -> &str {
        &self.config.password
    }
}

/// Handle a single hysteria stream. Detects UDP vs TCP mode from the protocol marker.
pub async fn handle_hysteria_stream(
    stream: Conn,
    dispatcher: Arc<dyn Dispatcher>,
    tag: String,
    source: Destination,
) -> ProxyResult<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);

    let mut buf_reader = BufReader::new(&mut reader);
    let mut addr_line = String::new();
    buf_reader.read_line(&mut addr_line).await
        .map_err(|e| format!("hysteria: read addr: {}", e))?;

    let addr_str = addr_line.trim();
    let (host, port_str) = addr_str.split_once(':')
        .ok_or_else(|| format!("hysteria: invalid addr: {}", addr_str))?;

    let port_num: u16 = port_str.parse()
        .map_err(|_| format!("hysteria: invalid port: {}", port_str))?;

    let address = if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        Address::Ipv4(ip.octets())
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        Address::Ipv6(ip.octets())
    } else {
        Address::Domain(host.to_string())
    };

    // Peek at remaining buffer to detect UDP mode marker "u\n"
    let is_udp = match buf_reader.fill_buf().await {
        Ok(buf) if buf.len() >= 2 && buf[0] == b'u' && buf[1] == b'\n' => true,
        _ => false,
    };

    if is_udp {
        buf_reader.consume(2);
        let stream_reader = buf_reader.into_inner();
        let session = Session {
            inbound: Some(Inbound { source, local: None, gateway: None, tag }),
            outbound: None,
            content: None,
        };
        let mut udp_link = dispatcher.dispatch_udp(session).await?;

        let placeholder = Destination {
            address: Address::Ipv4([0, 0, 0, 0]),
            port: Port(0),
            network: Network::Udp,
        };

        let udp_writer = udp_link.writer.clone();
        let udp_reader = &mut udp_link.reader;

        // stream -> udp_link
        let to_udp = async {
            let mut len_buf = [0u8; 2];
            loop {
                if stream_reader.read_exact(&mut len_buf).await.is_err() {
                    break;
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                let mut data = vec![0u8; len];
                if stream_reader.read_exact(&mut data).await.is_err() {
                    break;
                }
                let pkt = UdpPacket::new(placeholder.clone(), placeholder.clone(), data);
                if udp_writer.send(pkt).is_err() {
                    break;
                }
            }
            #[allow(unreachable_code)]
            Ok::<_, String>(())
        };

        // udp_link -> stream
        let to_writer = async {
            loop {
                let pkt = udp_reader.recv().await;
                match pkt {
                    Some(pkt) => {
                        let len = pkt.data.len() as u16;
                        if writer.write_all(&len.to_be_bytes()).await.is_err() {
                            break;
                        }
                        if writer.write_all(&pkt.data).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            #[allow(unreachable_code)]
            Ok::<_, String>(())
        };

        tokio::select! {
            _ = to_udp => {},
            _ = to_writer => {},
        };
        return Ok(());
    }

    // TCP mode (default, backward compatible)
    let tcp_target = Destination {
        address,
        port: Port(port_num),
        network: Network::Tcp,
    };

    let session = Session {
        inbound: Some(Inbound { source, local: None, gateway: None, tag }),
        outbound: None,
        content: None,
    };

    let link = dispatcher.dispatch(session, tcp_target).await?;
    let (mut link_reader, mut link_writer) = tokio::io::split(astra_core_transport::new_link_stream(link));

    let mut stream_reader = buf_reader.into_inner();
    let c1 = tokio::io::copy(&mut stream_reader, &mut link_writer);
    let c2 = tokio::io::copy(&mut link_reader, &mut writer);
    tokio::pin!(c1, c2);

    tokio::select! {
        _ = c1 => {},
        _ = c2 => {},
    };
    Ok(())
}

/// Perform hysteria authentication on the first stream.
/// Returns Ok if auth passes, Err otherwise.
pub async fn hysteria_auth_first_stream(
    conn: &quinn::Connection,
    expected_password: &str,
) -> Result<(), String> {
    let (mut send, mut recv) = conn.accept_bi().await
        .map_err(|e| format!("hysteria: accept auth stream: {}", e))?;

    let buf = recv.read_to_end(4096).await
        .map_err(|e| format!("hysteria: read auth: {}", e))?;

    let auth_req: AuthRequest = serde_json::from_slice(&buf)
        .map_err(|e| format!("hysteria: parse auth: {}", e))?;

    if auth_req.auth != expected_password {
        let resp = AuthResponse { ok: false, error: "invalid password".into() };
        let body = serde_json::to_string(&resp)
            .map_err(|e| format!("hysteria: serialize auth resp: {}", e))?;
        send.write_all(body.as_bytes()).await
            .map_err(|e| format!("hysteria: send auth resp: {}", e))?;
        return Err("hysteria: auth rejected".into());
    }

    let resp = AuthResponse { ok: true, error: String::new() };
    let body = serde_json::to_string(&resp)
        .map_err(|e| format!("hysteria: serialize auth ok: {}", e))?;
    send.write_all(body.as_bytes()).await
        .map_err(|e| format!("hysteria: send auth ok: {}", e))?;
    send.finish().map_err(|e| format!("hysteria: finish auth: {}", e))?;

    Ok(())
}

#[async_trait::async_trait]
impl InboundHandler for HysteriaInbound {
    async fn process(
        &self,
        _session: Session,
        _conn: Conn,
        _dispatcher: Arc<dyn Dispatcher>,
    ) -> ProxyResult<()> {
        Err("hysteria inbound uses QUIC directly, not individual streams".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use quinn::congestion::Controller;

    #[test]
    fn test_parse_bandwidth_mbps() {
        assert_eq!(parse_bandwidth("10 mbps").unwrap(), 10_000_000);
        assert_eq!(parse_bandwidth("10mbps").unwrap(), 10_000_000);
        assert_eq!(parse_bandwidth("10m").unwrap(), 10_000_000);
        assert_eq!(parse_bandwidth("10 M").unwrap(), 10_000_000);
    }

    #[test]
    fn test_parse_bandwidth_kbps() {
        assert_eq!(parse_bandwidth("500 kbps").unwrap(), 500_000);
        assert_eq!(parse_bandwidth("500k").unwrap(), 500_000);
    }

    #[test]
    fn test_parse_bandwidth_gbps() {
        assert_eq!(parse_bandwidth("1 gbps").unwrap(), 1_000_000_000);
        assert_eq!(parse_bandwidth("2g").unwrap(), 2_000_000_000);
    }

    #[test]
    fn test_parse_bandwidth_bps() {
        assert_eq!(parse_bandwidth("1000 bps").unwrap(), 1000);
        assert_eq!(parse_bandwidth("500b").unwrap(), 500);
    }

    #[test]
    fn test_parse_bandwidth_numeric() {
        assert_eq!(parse_bandwidth("5").unwrap(), 5_000_000);
        assert_eq!(parse_bandwidth("0.5").unwrap(), 500_000);
    }

    #[test]
    fn test_parse_bandwidth_invalid() {
        assert!(parse_bandwidth("").is_err());
        assert!(parse_bandwidth("abc").is_err());
    }

    #[test]
    fn test_brutal_controller_initial_cwnd() {
        let ctrl = BrutalController::new(10_000_000);
        assert!(ctrl.window() >= 1250000, "10Mbps target window");
    }

    #[test]
    fn test_brutal_controller_min_cwnd() {
        let ctrl = BrutalController::new(1000);
        assert_eq!(ctrl.initial_window(), 2048);
        assert!(ctrl.window() >= 2048);
    }

    #[test]
    fn test_brutal_controller_on_loss_reduction() {
        let mut ctrl = BrutalController::new(10_000_000);
        let initial = ctrl.window();
        ctrl.on_congestion_event(Instant::now(), Instant::now(), true, 1000);
        assert!(ctrl.window() < initial, "cwnd should reduce on loss");
        assert!(ctrl.window() >= 2048, "cwnd should not go below min");
    }

    #[test]
    fn test_brutal_controller_on_loss_non_persistent() {
        let mut ctrl = BrutalController::new(10_000_000);
        let initial = ctrl.window();
        // Non-persistent loss with 0 lost_bytes should NOT reduce cwnd
        ctrl.on_congestion_event(Instant::now(), Instant::now(), false, 0);
        assert_eq!(ctrl.window(), initial, "non-persistent loss with 0 lost should not reduce");
    }

    #[test]
    fn test_hysteria_config_serde() {
        let json = r#"{
            "server": "example.com:443",
            "serverName": "example.com",
            "password": "secret",
            "up": "10 mbps",
            "down": "100 mbps"
        }"#;
        let cfg: HysteriaConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.server.as_deref(), Some("example.com:443"));
        assert_eq!(cfg.server_name.as_deref(), Some("example.com"));
        assert_eq!(cfg.password, "secret");
        assert_eq!(cfg.up, "10 mbps");
        assert_eq!(cfg.down, "100 mbps");
        assert!(cfg.obfs.is_none());
    }

    #[test]
    fn test_hysteria_config_with_obfs() {
        let json = r#"{"password":"x","up":"1m","down":"1m","obfs":"f4.com"}"#;
        let cfg: HysteriaConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.obfs.as_deref(), Some("f4.com"));
    }

    #[test]
    fn test_auth_request_serialize() {
        let req = AuthRequest { auth: "mypassword".into() };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"auth":"mypassword"}"#);
    }

    #[test]
    fn test_auth_response_ok() {
        let resp = AuthResponse { ok: true, error: String::new() };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""ok":true"#));
        assert!(!json.contains("error"));
    }

    #[test]
    fn test_auth_response_error() {
        let resp = AuthResponse { ok: false, error: "bad password".into() };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""ok":false"#));
        assert!(json.contains(r#""error":"bad password""#));
    }

    #[test]
    fn test_hysteria_inbound_config() {
        let cfg = HysteriaInboundConfig {
            password: "test".into(),
            obfs: None,
        };
        let handler = HysteriaInbound::new(cfg);
        assert_eq!(handler.password(), "test");
    }

    #[test]
    fn test_hysteria_inbound_config_with_obfs() {
        let cfg = HysteriaInboundConfig {
            password: "secret".into(),
            obfs: Some("f4.com".into()),
        };
        assert_eq!(cfg.obfs.as_deref(), Some("f4.com"));
    }

}
