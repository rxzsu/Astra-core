use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use astra_core_proxy::{Conn, ProxyResult};

/// Wraps a TCP stream with TLS server-side handling.
pub async fn accept_tls(
    tcp: TcpStream,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> ProxyResult<Conn> {
    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
        .map_err(|e| format!("invalid private key: {:?}", e))?;

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| format!("tls config: {}", e))?;

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let tls_stream = acceptor
        .accept(tcp)
        .await
        .map_err(|e| format!("tls accept: {}", e))?;

    Ok(Box::new(tls_stream))
}
