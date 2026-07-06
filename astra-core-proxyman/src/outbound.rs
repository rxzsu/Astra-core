use std::collections::HashMap;
use std::sync::Arc;

use astra_core_dispatcher::DispatchHandler;
use astra_core_mux::client::MuxClient;
use astra_core_mux::io as mux_io;
use astra_core_mux::session::MuxClientStrategy;
use astra_core_net::Destination;
use astra_core_proxy::{async_trait, AsyncConn, Dialer, OutboundHandler, ProxyResult};
use astra_core_session::Session;
use astra_core_transport::Link;
use rustls::pki_types::ServerName;
use crate::transport;

/// TLS configuration for outbound connections.
pub struct TlsConfig {
    pub server_name: String,
    pub allow_insecure: bool,
}

/// Mux configuration for outbound connections.
#[derive(Debug, Clone)]
pub struct MuxConfig {
    pub enabled: bool,
    pub concurrency: i16,
}

/// A certificate verifier that accepts all server certificates (for allowInsecure).
#[derive(Debug)]
struct NoopVerifier;

impl rustls::client::danger::ServerCertVerifier for NoopVerifier {
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
}

/// Type-erased async connection usable as a bidirectional transport.
type Conn = Box<dyn AsyncConn>;

/// Mux client over a type-erased transport.
type MuxClientType = MuxClient<tokio::io::ReadHalf<Conn>, tokio::io::WriteHalf<Conn>>;

pub struct Handler {
    pub tag: String,
    proxy: Arc<dyn OutboundHandler>,
    tls: Option<TlsConfig>,
    transport: transport::Transport,
    pub mux: Option<MuxConfig>,
    mux_client: tokio::sync::Mutex<Option<Arc<MuxClientType>>>,
}

impl Handler {
    pub fn new(tag: String, proxy: Arc<dyn OutboundHandler>) -> Self {
        Handler {
            tag,
            proxy,
            tls: None,
            transport: transport::Transport::RawTcp,
            mux: None,
            mux_client: tokio::sync::Mutex::new(None),
        }
    }

    pub fn with_tls(mut self, tls: TlsConfig) -> Self {
        self.tls = Some(tls);
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

    /// Dial the underlying transport (TCP/TLS or KCP/WS/etc.) without mux.
    async fn dial_transport(&self, dest: &Destination) -> ProxyResult<Conn> {
        // First dial the base transport
        let raw = transport::dial_transport(&self.transport, dest).await?;

        // Apply TLS on top if configured
        if let Some(ref tls_cfg) = self.tls {
            let server_name_str = tls_cfg.server_name.clone();
            let server_name = ServerName::try_from(server_name_str)
                .map_err(|e| format!("invalid server name: {}", e))?;

            let config = if tls_cfg.allow_insecure {
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoopVerifier))
                    .with_no_client_auth()
            } else {
                let root_store = rustls::RootCertStore {
                    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                };
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth()
            };

            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let tls_stream = connector
                .connect(server_name, raw)
                .await
                .map_err(|e| format!("tls handshake: {}", e))?;
            Ok(Box::new(tls_stream))
        } else {
            Ok(raw)
        }
    }

    /// Dial using mux: reuse or create a mux client and open a new session.
    async fn dial_mux(&self, dest: &Destination) -> ProxyResult<Conn> {
        {
            let guard = self.mux_client.lock().await;
            if let Some(ref client) = *guard {
                if let Some(session_io) = mux_io::open_mux_stream(client).await {
                    return Ok(Box::new(session_io));
                }
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
#[async_trait]
impl Dialer for Handler {
    async fn dial(
        &self,
        _session: Session,
        dest: Destination,
    ) -> ProxyResult<Box<dyn AsyncConn>> {
        if self.mux.as_ref().is_some_and(|m| m.enabled) {
            return self.dial_mux(&dest).await;
        }
        self.dial_transport(&dest).await
    }
}

#[async_trait]
impl DispatchHandler for Handler {
    async fn dispatch(&self, session: Session, link: &mut Link) -> ProxyResult<()> {
        self.proxy.process(session, link, self).await
    }
}

pub struct Manager {
    handlers: HashMap<String, Arc<dyn DispatchHandler>>,
    default_handler: Option<Arc<dyn DispatchHandler>>,
}

impl Default for Manager {
    fn default() -> Self {
        Self::new()
    }
}

impl Manager {
    pub fn new() -> Self {
        Manager {
            handlers: HashMap::new(),
            default_handler: None,
        }
    }

    pub fn add_handler(&mut self, tag: String, handler: Arc<dyn DispatchHandler>) {
        if self.default_handler.is_none() {
            self.default_handler = Some(handler.clone());
        }
        self.handlers.insert(tag, handler);
    }

    pub fn get_handler(&self, tag: &str) -> Option<&Arc<dyn DispatchHandler>> {
        self.handlers.get(tag)
    }

    pub fn get_default_handler(&self) -> Option<&Arc<dyn DispatchHandler>> {
        self.default_handler.as_ref()
    }
}
