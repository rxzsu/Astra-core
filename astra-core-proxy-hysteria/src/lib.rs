use std::any::Any;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use astra_core_proxy::{OutboundHandler, ProxyResult};
use astra_core_proxy::dialer::Dialer;
use astra_core_session::Session;
use astra_core_transport::{Link, UdpLink};
use quinn::crypto::rustls::QuicClientConfig;
use serde::{Deserialize, Serialize};

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

// ─── Auth protocol ──────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct AuthRequest {
    auth: String,
}

#[derive(Serialize, Deserialize)]
struct AuthResponse {
    ok: bool,
    #[serde(default)]
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
        if let Some(ref conn) = *guard {
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
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

        let connecting = endpoint.connect_with(client_cfg, remote, &server_name)
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
        _session: Session,
        _link: &mut UdpLink,
    ) -> ProxyResult<()> {
        Err("hysteria UDP not yet implemented".into())
    }
}
