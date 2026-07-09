use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;

use crate::connection::WsConnection;

/// Callback for handling new WebSocket connections.
pub type WsConnHandler = Arc<dyn Fn(WsConnection<tokio::net::TcpStream>) + Send + Sync>;

/// Configuration for the WebSocket listener.
#[derive(Debug, Clone)]
pub struct WsListenerConfig {
    pub host: String,
    pub path: String,
}

impl Default for WsListenerConfig {
    fn default() -> Self {
        WsListenerConfig {
            host: String::new(),
            path: "/".into(),
        }
    }
}

/// A shutdown handle returned by `serve_ws`.
#[derive(Clone)]
pub struct ShutdownHandle {
    flag: Arc<AtomicBool>,
}

impl ShutdownHandle {
    pub fn shutdown(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }
}

/// Start a WebSocket listener on the given address.
///
/// Returns the bound local address and a shutdown handle.
pub async fn serve_ws(
    bind_addr: &str,
    config: WsListenerConfig,
    handler: WsConnHandler,
) -> Result<(std::net::SocketAddr, ShutdownHandle), String> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| format!("bind {}: {}", bind_addr, e))?;

    let local_addr = listener
        .local_addr()
        .map_err(|e| format!("get local addr: {}", e))?;

    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let handle = ShutdownHandle {
        flag: shutdown_flag.clone(),
    };

    tokio::spawn(async move {
        loop {
            if shutdown_flag.load(Ordering::Relaxed) {
                break;
            }

            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _peer_addr)) => {
                            let handler = handler.clone();
                            let config = config.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_upgrade(stream, &config, handler).await {
                                    eprintln!("ws upgrade error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("accept error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });

    Ok((local_addr, handle))
}

async fn handle_upgrade(
    stream: tokio::net::TcpStream,
    _config: &WsListenerConfig,
    handler: WsConnHandler,
) -> Result<(), String> {
    let peer = stream.peer_addr().ok();
    let ws = accept_async(stream)
        .await
        .map_err(|e| format!("ws accept from {:?}: {}", peer, e))?;

    handler(WsConnection::new(ws));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra_core_net::destination::TcpDestination;
    use astra_core_net::{Address, Port};
    use tokio::time::{Duration, sleep};

    #[tokio::test]
    async fn test_ws_minimal_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        });

        sleep(Duration::from_millis(50)).await;

        let dest = TcpDestination(Address::Ipv4([127, 0, 0, 1]), Port(addr.port()));
        let _conn = crate::dialer::dial_ws(&dest, &crate::dialer::WsDialerConfig::default())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_serve_ws_connect() {
        let called = Arc::new(std::sync::Mutex::new(false));
        let c = called.clone();
        let handler: WsConnHandler = Arc::new(move |_conn| {
            *c.lock().unwrap() = true;
        });

        let (addr, _shutdown) = serve_ws("127.0.0.1:0", WsListenerConfig::default(), handler)
            .await
            .unwrap();

        sleep(Duration::from_millis(100)).await;

        let dest = TcpDestination(Address::Ipv4([127, 0, 0, 1]), Port(addr.port()));
        let r = crate::dialer::dial_ws(&dest, &crate::dialer::WsDialerConfig::default()).await;
        if let Err(ref e) = r {
            panic!("dial_ws failed: {}", e);
        }

        sleep(Duration::from_millis(200)).await;
        assert!(*called.lock().unwrap(), "server handler should be called");
    }
}
