use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use crate::transport;
use astra_core_dispatcher::DispatchHandler;
use astra_core_mux::client::MuxClient;
use astra_core_mux::io as mux_io;
use astra_core_mux::session::MuxClientStrategy;
use astra_core_net::Destination;
use astra_core_proxy::timeout::TimeoutConn;
use astra_core_proxy::{AsyncConn, Dialer, OutboundHandler, ProxyResult, UdpLink, async_trait};
use astra_core_session::Session;
use astra_core_transport::Link;

/// TLS configuration for outbound connections.
pub struct TlsConfig {
    pub server_name: String,
    pub allow_insecure: bool,
    /// Browser fingerprint for DPI bypass (default: Chrome)
    pub fingerprint: Option<astra_core_transport_tls::TlsFingerprint>,
}

/// REALITY configuration for outbound connections.
pub struct RealityConfig {
    pub server_name: String,
    pub fingerprint: String,
    pub public_key: Vec<u8>,
    pub short_id: Vec<u8>,
}

/// Mux configuration for outbound connections.
#[derive(Debug, Clone)]
pub struct MuxConfig {
    pub enabled: bool,
    pub concurrency: i16,
}

/// Type-erased async connection usable as a bidirectional transport.
type Conn = Box<dyn AsyncConn>;

/// Mux client over a type-erased transport.
type MuxClientType = MuxClient<tokio::io::ReadHalf<Conn>, tokio::io::WriteHalf<Conn>>;

pub struct Handler {
    pub tag: String,
    proxy: Arc<dyn OutboundHandler>,
    tls: Option<TlsConfig>,
    reality: Option<RealityConfig>,
    transport: transport::Transport,
    pub mux: Option<MuxConfig>,
    mux_client: tokio::sync::Mutex<Option<Arc<MuxClientType>>>,
    pub tcp_keepalive_interval: Option<u32>,
    pub tcp_fast_open: bool,
    pub idle_timeout: Option<Duration>,
}

impl Handler {
    pub fn new(tag: String, proxy: Arc<dyn OutboundHandler>) -> Self {
        Handler {
            tag,
            proxy,
            tls: None,
            reality: None,
            transport: transport::Transport::RawTcp,
            mux: None,
            mux_client: tokio::sync::Mutex::new(None),
            tcp_keepalive_interval: None,
            tcp_fast_open: false,
            idle_timeout: None,
        }
    }

    pub fn with_tls(mut self, tls: TlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    pub fn with_reality(mut self, reality: RealityConfig) -> Self {
        self.reality = Some(reality);
        self
    }

    pub fn with_transport(mut self, t: transport::Transport) -> Self {
        self.transport = t;
        self
    }

    pub fn with_mux(mut self, mux: MuxConfig) -> Self {
        self.mux = Some(mux);
        self
    }

    pub fn with_keepalive(mut self, interval: u32) -> Self {
        self.tcp_keepalive_interval = Some(interval);
        self
    }

    pub fn with_tcp_fast_open(mut self, enable: bool) -> Self {
        self.tcp_fast_open = enable;
        self
    }

    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = Some(timeout);
        self
    }
}

impl Handler {
    async fn dial_transport(&self, dest: &Destination) -> ProxyResult<Conn> {
        if let Some(ref reality_cfg) = self.reality {
            let tcp = transport::dial_transport(&self.transport, dest, None).await?;
            let sn = if reality_cfg.server_name.is_empty() {
                dest.address.to_string()
            } else {
                reality_cfg.server_name.clone()
            };
            // REALITY with custom TLS fingerprint
            let mut tls_cfg = astra_core_transport_tls::TlsConfig {
                server_name: sn.clone(),
                alpn: vec!["h2".into(), "http/1.1".into()],
                fingerprint: astra_core_transport_tls::TlsFingerprint::Chrome,
                insecure_skip_verify: false,
                ca_cert_pem: None,
            };
            // Parse fingerprint from reality config
            match reality_cfg.fingerprint.to_lowercase().as_str() {
                "chrome" => tls_cfg.fingerprint = astra_core_transport_tls::TlsFingerprint::Chrome,
                "firefox" => tls_cfg.fingerprint = astra_core_transport_tls::TlsFingerprint::Firefox,
                "safari" => tls_cfg.fingerprint = astra_core_transport_tls::TlsFingerprint::Safari,
                "edge" => tls_cfg.fingerprint = astra_core_transport_tls::TlsFingerprint::Edge,
                "random" => tls_cfg.fingerprint = astra_core_transport_tls::TlsFingerprint::Random,
                _ => {}
            }
            return astra_core_transport_tls::tls_connect(tcp, &tls_cfg).await
                .map(|s| Box::new(s) as Conn);
        }

        let raw = transport::dial_transport(&self.transport, dest, None).await?;

        if let Some(ref tls_cfg) = self.tls {
            let fingerprint = tls_cfg.fingerprint.unwrap_or(astra_core_transport_tls::TlsFingerprint::Chrome);
            let boring_cfg = astra_core_transport_tls::TlsConfig {
                server_name: tls_cfg.server_name.clone(),
                alpn: vec!["h2".into(), "http/1.1".into()],
                fingerprint,
                insecure_skip_verify: tls_cfg.allow_insecure,
                ca_cert_pem: None,
            };
            return astra_core_transport_tls::tls_connect(raw, &boring_cfg).await
                .map(|s| Box::new(s) as Conn);
        }

        Ok(raw)
    }

    async fn dial_mux(&self, dest: &Destination) -> ProxyResult<Conn> {
        {
            let guard = self.mux_client.lock().await;
            if let Some(ref client) = *guard
                && let Some(session_io) = mux_io::open_mux_stream(client).await
            {
                return Ok(Box::new(session_io));
            }
        }

        let conn = self.dial_transport(dest).await?;
        let mux_client = MuxClientType::new_from_stream(conn, MuxClientStrategy::default());

        let session_io = mux_io::open_mux_stream(&mux_client)
            .await
            .ok_or_else(|| "mux: failed to open initial session".to_string())?;

        *self.mux_client.lock().await = Some(mux_client);
        Ok(Box::new(session_io))
    }
}

#[async_trait]
impl Dialer for Handler {
    async fn dial(&self, _session: Session, dest: Destination) -> ProxyResult<Box<dyn AsyncConn>> {
        let conn = if self.mux.as_ref().is_some_and(|m| m.enabled) {
            self.dial_mux(&dest).await?
        } else {
            self.dial_transport(&dest).await?
        };

        if let Some(idle) = self.idle_timeout {
            Ok(Box::new(TimeoutConn::new(conn, idle)))
        } else {
            Ok(conn)
        }
    }
}

impl Handler {
    pub fn wrap_with_proxy(self) -> Arc<dyn OutboundHandler> {
        struct Wrapper {
            inner: Handler,
        }

        #[async_trait]
        impl OutboundHandler for Wrapper {
            async fn process(&self, session: Session, link: &mut Link, _dialer: &dyn Dialer) -> ProxyResult<()> {
                // Use self as dialer
                let dialer = &self.inner;
                self.inner.proxy.process(session, link, dialer).await
            }

            async fn process_udp(&self, _session: Session, _link: &mut UdpLink) -> ProxyResult<()> {
                Err("outbound tls wrapper: udp not supported".into())
            }
        }

        Arc::new(Wrapper { inner: self })
    }
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handler")
            .field("tag", &self.tag)
            .field("tls", &self.tls.as_ref().map(|t| &t.server_name))
            .finish()
    }
}

impl DispatchHandler for Handler {
    async fn dispatch(&self, session: Session, link: &mut Link) -> ProxyResult<()> {
        self.proxy.process(session, link, self).await
    }

    async fn dispatch_udp(&self, session: Session, link: &mut UdpLink) -> ProxyResult<()> {
        self.proxy.process_udp(session, link).await
    }
}

// ─── Manager ────────────────────────────────────────────────────────────────

pub struct Manager {
    handlers: RwLock<HashMap<String, Arc<dyn OutboundHandler>>>,
}

impl Manager {
    pub fn new() -> Self {
        Manager {
            handlers: RwLock::new(HashMap::new()),
        }
    }

    pub fn add_handler(&self, tag: String, handler: Arc<dyn OutboundHandler>) {
        self.handlers.write().unwrap().insert(tag, handler);
    }

    pub fn remove_handler(&self, tag: &str) -> Option<Arc<dyn OutboundHandler>> {
        self.handlers.write().unwrap().remove(tag)
    }

    pub fn get_handler(&self, tag: &str) -> Option<Arc<dyn OutboundHandler>> {
        self.handlers.read().unwrap().get(tag).cloned()
    }

    pub fn list_handlers(&self) -> Vec<(String, String)> {
        self.handlers
            .read()
            .unwrap()
            .iter()
            .map(|(tag, _)| (tag.clone(), "outbound".into()))
            .collect()
    }

    pub fn get_default_handler(&self) -> Option<Arc<dyn OutboundHandler>> {
        self.handlers.read().unwrap().values().next().cloned()
    }
}

impl Default for Manager {
    fn default() -> Self {
        Self::new()
    }
}
