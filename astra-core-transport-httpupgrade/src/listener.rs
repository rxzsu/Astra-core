use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::config::Config;

pub type ConnHandler = Arc<dyn Fn(TcpStream) + Send + Sync>;

pub struct ShutdownHandle {
    flag: Arc<AtomicBool>,
}

impl ShutdownHandle {
    pub fn shutdown(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }
}

pub async fn serve(
    bind_addr: &str,
    config: Config,
    handler: ConnHandler,
) -> Result<(std::net::SocketAddr, ShutdownHandle), String> {
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|e| format!("httpupgrade serve: bind {}: {}", bind_addr, e))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("httpupgrade serve: local addr: {}", e))?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        let path = config.normalized_path();

        loop {
            if shutdown_clone.load(Ordering::Relaxed) {
                break;
            }

            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };

            let cfg = config.clone();
            let path = path.clone();
            let handler = handler.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_conn(stream, &cfg, &path, handler).await {
                    tracing::warn!("httpupgrade handle: {}", e);
                }
            });
        }
    });

    Ok((addr, ShutdownHandle { flag: shutdown }))
}

async fn handle_conn(
    mut stream: TcpStream,
    config: &Config,
    expected_path: &str,
    handler: ConnHandler,
) -> Result<(), String> {
    let mut reader = BufReader::new(&mut stream);

    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .await
        .map_err(|e| format!("read request line: {}", e))?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "GET" {
        return Err("invalid request line".into());
    }
    let req_path = parts[1];

    if req_path != expected_path {
        return Err(format!("bad path: {}", req_path));
    }

    let mut host = String::new();
    let mut connection = String::new();
    let mut upgrade = String::new();

    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("read header: {}", e))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(v) = trimmed.strip_prefix("Host:") {
            host = v.trim().to_lowercase();
        } else if let Some(v) = trimmed.strip_prefix("Connection:") {
            connection = v.trim().to_lowercase();
        } else if let Some(v) = trimmed.strip_prefix("Upgrade:") {
            upgrade = v.trim().to_lowercase();
        }
    }

    if !config.host.is_empty() && host != config.host.to_lowercase() {
        return Err(format!("bad host: {}", host));
    }

    if connection != "upgrade" || upgrade != "websocket" {
        return Err("not an upgrade request".into());
    }

    let response = "HTTP/1.1 101 Switching Protocols\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         \r\n";

    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|e| format!("write response: {}", e))?;

    handler(stream);
    Ok(())
}
