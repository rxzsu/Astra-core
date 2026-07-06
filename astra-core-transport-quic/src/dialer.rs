use std::net::SocketAddr;

use astra_core_net::Destination;

use crate::config::QuicConfig;
use crate::connection::QuicStream;

/// Dial a QUIC connection to the given destination.
pub async fn dial_quic(
    dest: &Destination,
    _config: &QuicConfig,
) -> Result<QuicStream, String> {
    let remote_addr: SocketAddr = format!("{}:{}", dest.address, dest.port.value())
        .parse()
        .map_err(|e| format!("invalid address: {}", e))?;

    let bind_addr: SocketAddr = if remote_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };

    let endpoint = quinn::Endpoint::client(bind_addr)
        .map_err(|e| format!("create endpoint: {}", e))?;

    let server_name = dest.address.to_string();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut client_cfg = quinn::ClientConfig::with_root_certificates(root_store.into())
        .map_err(|e| format!("QUIC TLS config: {}", e))?;
    client_cfg.transport_config(std::sync::Arc::new(quinn::TransportConfig::default()));

    let connect = endpoint
        .connect_with(client_cfg, remote_addr, &server_name)
        .map_err(|e| format!("connect: {}", e))?;

    let conn = connect
        .await
        .map_err(|e| format!("QUIC handshake: {}", e))?;

    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("open stream: {}", e))?;

    Ok(QuicStream::new(send, recv))
}
