use std::sync::Arc;

use h2::client;
use http::Request;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use astra_core_net::Destination;

use astra_core_proxy::{Conn, ProxyResult};

use crate::{build_tls_client_config, H2Stream};

pub async fn dial_h2(dest: &Destination, host: &str, path: &str) -> ProxyResult<Conn> {
    let addr_str = format!("{}:{}", dest.address, dest.port.value());
    let tcp = TcpStream::connect(&addr_str)
        .await
        .map_err(|e| format!("h2 dial tcp: {}", e))?;

    let server_name = if host.is_empty() {
        dest.address.to_string()
    } else {
        host.to_string()
    };

    let tls_cfg = Arc::new(build_tls_client_config()?);
    let connector = TlsConnector::from(tls_cfg);

    let server_name_ref = tokio_rustls::rustls::pki_types::ServerName::try_from(server_name)
        .map_err(|e| format!("invalid server name: {}", e))?;

    let tls = connector
        .connect(server_name_ref, tcp)
        .await
        .map_err(|e| format!("h2 tls handshake: {}", e))?;

    let (mut h2, h2_conn) = client::handshake(tls)
        .await
        .map_err(|e| format!("h2 handshake: {}", e))?;

    tokio::spawn(async move {
        if let Err(e) = h2_conn.await {
            tracing::error!("h2 connection error: {}", e);
        }
    });

    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/grpc")
        .body(())
        .map_err(|e| format!("h2 build request: {}", e))?;

    let (response_future, send) = h2
        .send_request(req, false)
        .map_err(|e| format!("h2 send request: {}", e))?;

    let response = response_future
        .await
        .map_err(|e| format!("h2 response: {}", e))?;

    let recv = response.into_body();
    let stream = H2Stream::new(send, recv);
    Ok(Box::new(stream))
}
