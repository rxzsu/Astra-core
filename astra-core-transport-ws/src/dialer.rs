use astra_core_net::Destination;
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;

use crate::connection::WsConnection;

/// Configuration for WebSocket dialer.
#[derive(Debug, Clone)]
pub struct WsDialerConfig {
    pub host: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
}

impl Default for WsDialerConfig {
    fn default() -> Self {
        WsDialerConfig {
            host: String::new(),
            path: "/".into(),
            headers: Vec::new(),
        }
    }
}

/// Dial a WebSocket connection to the given destination (ws://).
pub async fn dial_ws(
    dest: &Destination,
    config: &WsDialerConfig,
) -> Result<WsConnection<TcpStream>, String> {
    let addr = format!("{}:{}", dest.address, dest.port.value());

    let tcp = TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("tcp connect to {}: {}", addr, e))?;

    let path = if config.path.is_empty() || config.path.starts_with('/') {
        config.path.clone()
    } else {
        format!("/{}", config.path)
    };

    let uri = format!("ws://{}{}", addr, path);

    let (ws, _) = tokio_tungstenite::client_async(&uri, tcp)
        .await
        .map_err(|e| format!("ws handshake: {}", e))?;

    Ok(WsConnection::new(ws))
}

/// Dial a WebSocket connection over TLS (wss://).
pub async fn dial_wss(
    dest: &Destination,
    config: &WsDialerConfig,
) -> Result<WsConnection<MaybeTlsStream<TcpStream>>, String> {
    let _addr = format!("{}:{}", dest.address, dest.port.value());

    let path = if config.path.is_empty() || config.path.starts_with('/') {
        config.path.clone()
    } else {
        format!("/{}", config.path)
    };

    let host = if config.host.is_empty() {
        dest.address.to_string()
    } else {
        config.host.clone()
    };

    let uri = format!("wss://{}{}", host, path);

    let (ws, _) = tokio_tungstenite::connect_async(&uri)
        .await
        .map_err(|e| format!("wss dial: {}", e))?;

    Ok(WsConnection::new(ws))
}
