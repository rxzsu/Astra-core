use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use astra_core_proxy::{Conn, ProxyResult};

use crate::config::RealityConfig;

pub async fn dial_reality(tcp: TcpStream, config: &RealityConfig) -> ProxyResult<Conn> {
    let server_name_str = if config.server_name.is_empty() {
        let addr = tcp.peer_addr().map_err(|e| format!("peer_addr: {}", e))?;
        addr.to_string()
    } else {
        config.server_name.clone()
    };

    let server_name = rustls::pki_types::ServerName::try_from(server_name_str.clone())
        .map_err(|e| format!("invalid server name '{}': {}", server_name_str, e))?;

    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(tls_config));
    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("reality tls handshake: {}", e))?;

    Ok(Box::new(tls_stream))
}

pub async fn dial_tls(tcp: Conn, server_name: &str, allow_insecure: bool) -> ProxyResult<Conn> {
    let sn = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|e| format!("invalid server name '{}': {}", server_name, e))?;

    let config = if allow_insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::cert::RealityCertVerifier::new(
                [0u8; 32], true,
            )))
            .with_no_client_auth()
    } else {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let connector = TlsConnector::from(Arc::new(config));
    let tls_stream = connector
        .connect(sn, tcp)
        .await
        .map_err(|e| format!("tls handshake: {}", e))?;

    Ok(Box::new(tls_stream))
}
