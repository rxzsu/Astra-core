use std::collections::HashMap;
use std::sync::Arc;

use astra_core_dispatcher::DispatchHandler;
use astra_core_net::Destination;
use astra_core_proxy::{async_trait, AsyncConn, Dialer, OutboundHandler, ProxyResult};
use astra_core_session::Session;
use astra_core_transport::Link;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;

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

pub struct Handler {
    pub tag: String,
    proxy: Arc<dyn OutboundHandler>,
    tls: Option<TlsConfig>,
    pub mux: Option<MuxConfig>,
}

impl Handler {
    pub fn new(tag: String, proxy: Arc<dyn OutboundHandler>) -> Self {
        Handler { tag, proxy, tls: None, mux: None }
    }

    pub fn with_tls(mut self, tls: TlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    pub fn with_mux(mut self, mux: MuxConfig) -> Self {
        self.mux = Some(mux);
        self
    }
}

#[async_trait]
impl Dialer for Handler {
    async fn dial(
        &self,
        _session: Session,
        dest: Destination,
    ) -> ProxyResult<Box<dyn AsyncConn>> {
        let addr = format!("{}:{}", dest.address, dest.port.value());
        let stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("dial {}: {}", addr, e))?;

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
                .connect(server_name, stream)
                .await
                .map_err(|e| format!("tls handshake: {}", e))?;
            Ok(Box::new(tls_stream))
        } else {
            Ok(Box::new(stream))
        }
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
