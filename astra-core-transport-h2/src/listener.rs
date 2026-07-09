use std::sync::Arc;

use h2::server;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use astra_core_proxy::{Conn, ProxyResult};

use crate::{H2Stream, build_tls_server_config};

pub async fn serve_h2(
    listen_addr: &str,
    cert_data: Vec<u8>,
    key_data: Vec<u8>,
    on_conn: Arc<dyn Fn(Conn) + Send + Sync>,
) -> ProxyResult<()> {
    let tls_cfg = Arc::new(build_tls_server_config(cert_data, key_data)?);
    let acceptor = TlsAcceptor::from(tls_cfg);

    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| format!("h2 bind {}: {}", listen_addr, e))?;

    loop {
        let (tcp, _) = listener
            .accept()
            .await
            .map_err(|e| format!("h2 accept: {}", e))?;

        let acceptor = acceptor.clone();
        let on_conn = on_conn.clone();

        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(tls) => tls,
                Err(e) => {
                    tracing::error!("h2 tls accept: {}", e);
                    return;
                }
            };

            let mut h2 = match server::handshake(tls).await {
                Ok(h2) => h2,
                Err(e) => {
                    tracing::error!("h2 server handshake: {}", e);
                    return;
                }
            };

            while let Some(result) = h2.accept().await {
                let (req, mut respond) = match result {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!("h2 accept stream: {}", e);
                        break;
                    }
                };

                let on_conn = on_conn.clone();
                let recv = req.into_body();

                tokio::spawn(async move {
                    let send = match respond.send_response(
                        http::Response::builder().status(200).body(()).unwrap(),
                        false,
                    ) {
                        Ok(send) => send,
                        Err(e) => {
                            tracing::error!("h2 send response: {}", e);
                            return;
                        }
                    };

                    let stream = H2Stream::new(send, recv);
                    on_conn(Box::new(stream));
                });
            }
        });
    }
}
