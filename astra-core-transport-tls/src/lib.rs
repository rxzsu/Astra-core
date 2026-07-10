/// Browser TLS fingerprint presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TlsFingerprint {
    #[serde(rename = "chrome")] Chrome,
    #[serde(rename = "firefox")] Firefox,
    #[serde(rename = "safari")] Safari,
    #[serde(rename = "edge")] Edge,
    #[serde(rename = "random")] Random,
    #[serde(rename = "randomized")] Randomized,
}

impl Default for TlsFingerprint {
    fn default() -> Self { TlsFingerprint::Chrome }
}

/// TLS configuration.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub server_name: String,
    pub alpn: Vec<String>,
    pub fingerprint: TlsFingerprint,
    pub insecure_skip_verify: bool,
    pub ca_cert_pem: Option<Vec<u8>>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        TlsConfig {
            server_name: String::new(),
            alpn: vec!["h2".into(), "http/1.1".into()],
            fingerprint: TlsFingerprint::Chrome,
            insecure_skip_verify: false,
            ca_cert_pem: None,
        }
    }
}

// ─── BoringSSL backend (feature = "boring") ────────────────────────────────

#[cfg(feature = "boring")]
mod backend {
    use boring::ssl::{SslConnector, SslMethod, SslAcceptor};
    use boring::x509::X509;
    use tokio::io::{AsyncRead, AsyncWrite};

    use crate::TlsConfig;

    pub fn build_client_config(config: &TlsConfig) -> Result<SslConnector, String> {
        let mut builder = SslConnector::builder(SslMethod::tls())
            .map_err(|e| format!("ssl builder: {}", e))?;

        if !config.alpn.is_empty() {
            let wire: Vec<u8> = config.alpn.iter()
                .flat_map(|s| { let mut v = vec![s.len() as u8]; v.extend_from_slice(s.as_bytes()); v })
                .collect();
            builder.set_alpn_protos(&wire).map_err(|e| format!("alpn: {}", e))?;
        }

        if let Some(ref ca_pem) = config.ca_cert_pem {
            let cert = X509::from_pem(ca_pem).map_err(|e| format!("ca cert: {}", e))?;
            let mut store = boring::x509::store::X509StoreBuilder::new()
                .map_err(|e| format!("store: {}", e))?;
            store.add_cert(cert).map_err(|e| format!("add cert: {}", e))?;
            builder.set_verify_cert_store(store.build())
                .map_err(|e| format!("verify store: {}", e))?;
        }

        if config.insecure_skip_verify {
            builder.set_verify(boring::ssl::SslVerifyMode::NONE);
        }

        builder.set_grease_enabled(true);
        builder.set_permute_extensions(true);
        Ok(builder.build())
    }

    pub async fn tls_connect<S>(
        tcp: S, config: &TlsConfig,
    ) -> Result<tokio_boring::SslStream<S>, String>
    where S: AsyncRead + AsyncWrite + Unpin + Send + 'static {
        let connector = build_client_config(config)?;
        let domain = config.server_name.clone();
        let connect_cfg = connector.configure()
            .map_err(|e| format!("ssl configure: {}", e))?;
        tokio_boring::connect(connect_cfg, &domain, tcp)
            .await.map_err(|e| format!("tls handshake: {}", e))
    }

    pub fn build_server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<SslAcceptor, String> {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
            .map_err(|e| format!("ssl acceptor: {}", e))?;
        let cert = X509::from_pem(cert_pem).map_err(|e| format!("cert: {}", e))?;
        let key = boring::pkey::PKey::private_key_from_pem(key_pem)
            .map_err(|e| format!("key: {}", e))?;
        builder.set_certificate(&cert).map_err(|e| format!("set cert: {}", e))?;
        builder.set_private_key(&key).map_err(|e| format!("set key: {}", e))?;
        builder.check_private_key().map_err(|e| format!("check key: {}", e))?;
        Ok(builder.build())
    }

    pub async fn tls_accept<S>(
        tcp: S, acceptor: &SslAcceptor,
    ) -> Result<tokio_boring::SslStream<S>, String>
    where S: AsyncRead + AsyncWrite + Unpin + Send + 'static {
        tokio_boring::accept(acceptor, tcp)
            .await.map_err(|e| format!("tls accept: {}", e))
    }
}

#[cfg(feature = "boring")]
pub use backend::*;

// ─── Rustls backend (default) ──────────────────────────────────────────────

#[cfg(not(feature = "boring"))]
mod backend {
    use std::sync::Arc;
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio_rustls::TlsConnector as RustlsConnector;

    use crate::TlsConfig;

    struct NoopVerifier;
    impl std::fmt::Debug for NoopVerifier {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "NoopVerifier") }
    }
    impl rustls::client::danger::ServerCertVerifier for NoopVerifier {
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
                rustls::SignatureScheme::ED25519, rustls::SignatureScheme::ED448,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
            ]
        }
        fn verify_server_cert(&self, _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8], _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(&self, _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
    }

    pub fn build_client_config(config: &TlsConfig) -> Result<rustls::ClientConfig, String> {
        let mut root_store = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        if let Some(ref ca_pem) = config.ca_cert_pem {
            let cert = rustls::pki_types::CertificateDer::from(ca_pem.clone());
            root_store.add(cert).ok();
        }

        let builder = if config.insecure_skip_verify {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoopVerifier))
                .with_no_client_auth()
        } else {
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };
        Ok(builder)
    }

    pub async fn tls_connect<S>(
        tcp: S, config: &TlsConfig,
    ) -> Result<tokio_rustls::client::TlsStream<S>, String>
    where S: AsyncRead + AsyncWrite + Unpin + Send + 'static {
        let server_name = rustls::pki_types::ServerName::try_from(config.server_name.clone())
            .map_err(|e| format!("server name: {:?}", e))?;
        let config = build_client_config(config)?;
        let connector = RustlsConnector::from(Arc::new(config));
        connector.connect(server_name, tcp)
            .await.map_err(|e| format!("tls handshake: {}", e))
    }

    pub fn build_server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<rustls::ServerConfig>, String> {
        let cert = rustls::pki_types::CertificateDer::from(cert_pem.to_vec());
        let key = rustls::pki_types::PrivateKeyDer::try_from(key_pem.to_vec())
            .map_err(|e| format!("invalid key: {:?}", e))?;
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| format!("tls config: {}", e))?;
        Ok(Arc::new(config))
    }

    pub async fn tls_accept<S>(
        tcp: S, acceptor: &Arc<rustls::ServerConfig>,
    ) -> Result<tokio_rustls::server::TlsStream<S>, String>
    where S: AsyncRead + AsyncWrite + Unpin + Send + 'static {
        let acceptor = tokio_rustls::TlsAcceptor::from(acceptor.clone());
        acceptor.accept(tcp)
            .await.map_err(|e| format!("tls accept: {}", e))
    }
}

#[cfg(not(feature = "boring"))]
pub use backend::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_serde() {
        let fp: TlsFingerprint = serde_json::from_str("\"chrome\"").unwrap();
        assert_eq!(fp, TlsFingerprint::Chrome);
    }
}
