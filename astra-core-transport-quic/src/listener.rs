use crate::config::QuicConfig;
use crate::connection::QuicStream;

/// Start a QUIC listener on the given address.
///
/// For each incoming connection, one bidirectional stream is accepted and
/// passed to the handler.
pub async fn serve_quic<F>(
    _bind_addr: &str,
    _config: &QuicConfig,
    endpoint: quinn::Endpoint,
    on_conn: F,
) -> Result<(), String>
where
    F: Fn(QuicStream) + Send + Sync + Clone + 'static,
{
    tracing::info!("QUIC endpoint ready");

    loop {
        match endpoint.accept().await {
            Some(connecting) => {
                let on_conn = on_conn.clone();
                tokio::spawn(async move {
                    match connecting.await {
                        Ok(conn) => {
                            if let Ok((send, recv)) = conn.accept_bi().await {
                                on_conn(QuicStream::new(send, recv));
                            }
                        }
                        Err(e) => {
                            tracing::error!("QUIC accept error: {}", e);
                        }
                    }
                });
            }
            None => break,
        }
    }

    Ok(())
}
