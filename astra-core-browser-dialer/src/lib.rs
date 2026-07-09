use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// Embedded HTML page for the browser dialer.
const DIALER_HTML: &str = include_str!("dialer.html");

/// Task sent to the browser via WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Task {
    method: String,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    extra: Option<Extra>,
    #[serde(default)]
    stream_response: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Extra {
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cookies: Option<HashMap<String, String>>,
}

/// Browser Dialer for routing HTTP requests through a browser
/// to avoid IP-based blocking.
pub struct BrowserDialer {
    running: Arc<AtomicBool>,
    active_conns: Arc<Mutex<Vec<mpsc::UnboundedSender<Vec<u8>>>>>,
}

impl BrowserDialer {
    pub fn new() -> Self {
        BrowserDialer {
            running: Arc::new(AtomicBool::new(false)),
            active_conns: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Start the browser dialer HTTP+WebSocket server.
    /// Serves the browser dialer HTML page and accepts WebSocket connections
    /// from browsers.
    pub async fn start(&self, addr: &str) -> Result<(), String> {
        if self.running.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.running.store(true, Ordering::Relaxed);

        let token = uuid::Uuid::new_v4().to_string();
        let html = DIALER_HTML.replace("TOKEN", &token);
        let running = self.running.clone();
        let conns = self.active_conns.clone();

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("browser dialer bind {}: {}", addr, e))?;

        tracing::info!("Browser dialer listening on http://{}/", addr);

        tokio::spawn(async move {
            while running.load(Ordering::Relaxed) {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let html = html.clone();
                        let token = token.clone();
                        let conns = conns.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, &token, &html, conns).await {
                                tracing::debug!("browser dialer connection: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("browser dialer accept: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop the browser dialer.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Check if the dialer is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Send a GET request through the browser.
    pub async fn dial_get(&self, uri: &str, headers: HashMap<String, String>) -> Result<Vec<u8>, String> {
        let (tx, mut rx) = mpsc::unbounded_channel();

        {
            let mut conns = self.active_conns.lock().unwrap();
            conns.push(tx);
        }

        let task = Task {
            method: "GET".into(),
            url: uri.to_string(),
            extra: Some(Extra {
                protocol: None,
                headers: Some(headers),
                cookies: None,
            }),
            stream_response: false,
        };

        let data = serde_json::to_vec(&task).map_err(|e| format!("serialize: {}", e))?;

        // In a real implementation, this would be sent over the WebSocket
        // For now, return a placeholder
        let _ = data;
        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            rx.recv(),
        ).await {
            Ok(Some(data)) => Ok(data),
            Ok(None) => Err("browser dialer: connection closed".into()),
            Err(_) => Err("browser dialer: timeout".into()),
        }
    }
}

impl Default for BrowserDialer {
    fn default() -> Self {
        Self::new()
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    token: &str,
    html: &str,
    conns: Arc<Mutex<Vec<mpsc::UnboundedSender<Vec<u8>>>>>,
) -> Result<(), String> {
    use tokio_tungstenite::accept_async;
    use tokio_tungstenite::tungstenite::Message;
    use futures_util::StreamExt;

    let peer = stream.peer_addr().ok();
    let mut buf = [0u8; 4096];
    let mut stream = stream;

    // Simple HTTP parsing: check if it's a WebSocket upgrade or regular HTTP
    let n = stream.peek(&mut buf).await.map_err(|e| format!("peek: {}", e))?;
    let header = String::from_utf8_lossy(&buf[..n.min(200)]);

    if header.contains("/websocket") && header.contains(&format!("token={}", token)) {
        // WebSocket upgrade
        let ws_stream = accept_async(stream).await.map_err(|e| format!("ws accept: {}", e))?;
        let (mut _write, mut read) = ws_stream.split();

        while let Some(msg) = read.next().await {
            match msg {
                Ok(Message::Binary(data)) => {
                    // Received response data from browser
                    let guard = conns.lock().unwrap();
                    if let Some(tx) = guard.first() {
                        let _ = tx.send(data.to_vec());
                    }
                }
                Ok(Message::Text(text)) => {
                    // "ok" or "fail" messages
                    tracing::debug!("browser: {}", text);
                }
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {}
            }
        }
    } else {
        // Serve HTML page
        use tokio::io::AsyncWriteExt;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
            html.len(),
            html
        );
        stream.write_all(response.as_bytes()).await.map_err(|e| format!("write: {}", e))?;
    }

    if let Some(addr) = peer {
        tracing::debug!("browser dialer peer {} disconnected", addr);
    }

    Ok(())
}
