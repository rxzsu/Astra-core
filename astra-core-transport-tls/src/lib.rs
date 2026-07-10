use boring::ssl::{SslConnector, SslMethod, SslAcceptor};
use boring::x509::X509;

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

/// TLS configuration with browser fingerprint impersonation.
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

/// Build a BoringSSL client TLS connector.
pub fn build_client_config(config: &TlsConfig) -> Result<SslConnector, String> {
    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|e| format!("ssl builder: {}", e))?;

    // ALPN wire format: each string prefixed by length byte
    if !config.alpn.is_empty() {
        let wire: Vec<u8> = config.alpn.iter()
            .flat_map(|s| {
                let mut v = vec![s.len() as u8];
                v.extend_from_slice(s.as_bytes());
                v
            })
            .collect();
        builder.set_alpn_protos(&wire)
            .map_err(|e| format!("alpn: {}", e))?;
    }

    // Custom CA certificate
    if let Some(ref ca_pem) = config.ca_cert_pem {
        let cert = X509::from_pem(ca_pem)
            .map_err(|e| format!("ca cert: {}", e))?;
        let mut store = boring::x509::store::X509StoreBuilder::new()
            .map_err(|e| format!("store: {}", e))?;
        store.add_cert(cert)
            .map_err(|e| format!("add cert: {}", e))?;
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

/// Async TLS connect.
pub async fn tls_connect(
    tcp: tokio::net::TcpStream,
    config: &TlsConfig,
) -> Result<tokio_boring::SslStream<tokio::net::TcpStream>, String> {
    let connector = build_client_config(config)?;
    let domain = config.server_name.clone();
    let connect_cfg = connector.configure()
        .map_err(|e| format!("ssl configure: {}", e))?;

    tokio_boring::connect(connect_cfg, &domain, tcp)
        .await
        .map_err(|e| format!("tls handshake: {}", e))
}

/// Build a server TLS acceptor.
pub fn build_server_config(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<SslAcceptor, String> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .map_err(|e| format!("ssl acceptor: {}", e))?;

    let cert = X509::from_pem(cert_pem)
        .map_err(|e| format!("cert: {}", e))?;
    let key = boring::pkey::PKey::private_key_from_pem(key_pem)
        .map_err(|e| format!("key: {}", e))?;

    builder.set_certificate(&cert)
        .map_err(|e| format!("set cert: {}", e))?;
    builder.set_private_key(&key)
        .map_err(|e| format!("set key: {}", e))?;
    builder.check_private_key()
        .map_err(|e| format!("check key: {}", e))?;

    Ok(builder.build())
}

/// Async TLS accept.
pub async fn tls_accept(
    tcp: tokio::net::TcpStream,
    acceptor: SslAcceptor,
) -> Result<tokio_boring::SslStream<tokio::net::TcpStream>, String> {
    tokio_boring::accept(&acceptor, tcp)
        .await
        .map_err(|e| format!("tls accept: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_serde() {
        let fp: TlsFingerprint = serde_json::from_str("\"chrome\"").unwrap();
        assert_eq!(fp, TlsFingerprint::Chrome);
    }

    #[test]
    fn test_build_client_default() {
        let config = TlsConfig {
            server_name: "example.com".into(),
            ..Default::default()
        };
        let conn = build_client_config(&config);
        assert!(conn.is_ok());
    }
}
