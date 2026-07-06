use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use astra_core_proxy::{Conn, ProxyResult};

use crate::config::Config;
use crate::session::SessionManager;

pub struct SplitHTTPListener {
    config: Arc<Config>,
    session_mgr: SessionManager,
}

impl SplitHTTPListener {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
            session_mgr: SessionManager::new(),
        }
    }

    pub async fn serve<F>(self, listen_addr: &str, on_conn: F) -> ProxyResult<()>
    where
        F: Fn(Conn) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(listen_addr)
            .await
            .map_err(|e| format!("splithttp bind {}: {}", listen_addr, e))?;

        let session_mgr = self.session_mgr;
        let config = self.config;
        let on_conn = Arc::new(on_conn);

        loop {
            let (tcp, _) = listener
                .accept()
                .await
                .map_err(|e| format!("splithttp accept: {}", e))?;

            let session_mgr = session_mgr.clone();
            let config = config.clone();
            let on_conn = on_conn.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_conn(tcp, &session_mgr, &config, &on_conn).await {
                    tracing::debug!("splithttp handle_conn: {}", e);
                }
            });
        }
    }
}

async fn handle_conn<F>(
    tcp: TcpStream,
    session_mgr: &SessionManager,
    config: &Config,
    on_conn: &Arc<F>,
) -> Result<(), String>
where
    F: Fn(Conn) + Send + Sync + 'static,
{
    let (reader, writer) = tokio::io::split(tcp);
    let mut reader = BufReader::new(reader);

    let request_line = read_request_line(&mut reader).await?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!("invalid request line: {}", request_line));
    }

    let method = parts[0];
    let raw_path = parts[1];

    let headers = read_headers(&mut reader).await?;

    let params = parse_query(raw_path);
    let session_id = match params.get("session_id") {
        Some(sid) => sid.clone(),
        None => {
            let mut w = writer;
            send_http_response(&mut w, 400, "Bad Request", "").await?;
            return Err("missing session_id".to_string());
        }
    };

    match method {
        "GET" => {
            let has_seq = params.contains_key("seq");
            if has_seq {
                handle_upload_get(reader, &session_id, &params, session_mgr).await
            } else {
                handle_download(writer, &session_id, session_mgr, config, on_conn).await
            }
        }
        "POST" | "PUT" => {
            let body = read_body(&mut reader, &headers).await?;
            handle_upload_post(&session_id, &params, &body, session_mgr).await?;
            let mut w = writer;
            send_http_response(&mut w, 200, "OK", "").await
        }
        "OPTIONS" => {
            let mut w = writer;
            send_options_response(&mut w).await
        }
        _ => {
            let mut w = writer;
            send_http_response(&mut w, 405, "Method Not Allowed", "").await
        }
    }
}

async fn handle_download<F>(
    writer: tokio::io::WriteHalf<TcpStream>,
    session_id: &str,
    session_mgr: &SessionManager,
    _config: &Config,
    on_conn: &Arc<F>,
) -> Result<(), String>
where
    F: Fn(Conn) + Send + Sync + 'static,
{
    let mut writer = writer;
    let (_session, download_rx_opt) = session_mgr.get_or_create(session_id).await;

    let mut download_rx = match download_rx_opt {
        Some(rx) => rx,
        None => {
            send_http_response(&mut writer, 409, "Conflict", "Session already exists").await?;
            return Err("session already exists".to_string());
        }
    };

    let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nAccess-Control-Allow-Origin: *\r\nTransfer-Encoding: chunked\r\n\r\n";
    writer
        .write_all(resp.as_bytes())
        .await
        .map_err(|e| format!("write download response: {}", e))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("flush download response: {}", e))?;

    let sid = session_id.to_string();
    let mgr = session_mgr.clone();

    tokio::spawn(async move {
        if let Err(e) = stream_chunked(&mut writer, &mut download_rx).await {
            tracing::debug!("splithttp download stream ended: {}", e);
        }
        let _ = writer.shutdown().await;
        mgr.remove(&sid).await;
    });

    // On the server side:
    // - conn.read() should yield data from the upload queue (client POSTs)
    // - conn.write() should send data to download_tx (HTTP response writer)
    let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(1024);

    {
        let s = _session.lock().await;

        let sid2 = session_id.to_string();
        let mgr2 = session_mgr.clone();
        let upload_queue = s.upload_queue.clone();
        tokio::spawn(async move {
            loop {
                let data = upload_queue.pop().await;
                match data {
                    Some(bytes) => {
                        if read_tx.send(bytes).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            mgr2.remove(&sid2).await;
        });

        let download_tx = s.download_tx.clone();
        tokio::spawn(async move {
            while let Some(data) = write_rx.recv().await {
                if download_tx.send(data).await.is_err() {
                    break;
                }
            }
        });
    }

    let conn: Conn = Box::new(crate::connection::SplitConn::new(read_rx, write_tx));
    on_conn(conn);

    Ok(())
}

async fn handle_upload_get(
    mut reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    session_id: &str,
    params: &HashMap<String, String>,
    session_mgr: &SessionManager,
) -> Result<(), String> {
    let seq_str = params.get("seq").cloned().unwrap_or_default();
    let seq: u64 = seq_str.parse().unwrap_or(0);

    let (session, _) = session_mgr.get_or_create(session_id).await;
    let mut body = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|e| format!("read body: {}", e))?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }

    {
        let s = session.lock().await;
        s.upload_queue.push(seq, body).await;
    }

    Ok(())
}

async fn handle_upload_post(
    session_id: &str,
    params: &HashMap<String, String>,
    body: &[u8],
    session_mgr: &SessionManager,
) -> Result<(), String> {
    let seq_str = params.get("seq").cloned().unwrap_or_default();
    let seq: u64 = seq_str.parse().unwrap_or(0);

    let (session, _) = session_mgr.get_or_create(session_id).await;
    {
        let s = session.lock().await;
        s.upload_queue.push(seq, body.to_vec()).await;
    }

    Ok(())
}

async fn stream_chunked(
    writer: &mut tokio::io::WriteHalf<TcpStream>,
    rx: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<(), String> {
    while let Some(data) = rx.recv().await {
        let chunk_size_hex = format!("{:X}\r\n", data.len());
        writer
            .write_all(chunk_size_hex.as_bytes())
            .await
            .map_err(|e| format!("write chunk size: {}", e))?;
        writer
            .write_all(&data)
            .await
            .map_err(|e| format!("write chunk data: {}", e))?;
        writer
            .write_all(b"\r\n")
            .await
            .map_err(|e| format!("write chunk crlf: {}", e))?;
        writer
            .flush()
            .await
            .map_err(|e| format!("flush chunk: {}", e))?;
    }
    writer
        .write_all(b"0\r\n\r\n")
        .await
        .map_err(|e| format!("write final chunk: {}", e))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("flush final: {}", e))?;
    Ok(())
}

async fn send_http_response(
    writer: &mut tokio::io::WriteHalf<TcpStream>,
    code: u16,
    reason: &str,
    body: &str,
) -> Result<(), String> {
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
        code, reason, body.len(), body
    );
    writer
        .write_all(resp.as_bytes())
        .await
        .map_err(|e| format!("write response: {}", e))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("flush response: {}", e))?;
    Ok(())
}

async fn send_options_response(
    writer: &mut tokio::io::WriteHalf<TcpStream>,
) -> Result<(), String> {
    let resp = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, PUT, OPTIONS\r\nAccess-Control-Allow-Headers: *\r\nContent-Length: 0\r\n\r\n";
    writer
        .write_all(resp.as_bytes())
        .await
        .map_err(|e| format!("write options: {}", e))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("flush options: {}", e))?;
    Ok(())
}

async fn read_request_line(
    reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
) -> Result<String, String> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|e| format!("read request line: {}", e))?;
    Ok(line.trim().to_string())
}

async fn read_headers(
    reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
) -> Result<HashMap<String, String>, String> {
    let mut headers = HashMap::new();
    let mut line = String::new();
    loop {
        line.clear();
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("read header: {}", e))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(pos) = trimmed.find(':') {
            let key = trimmed[..pos].trim().to_lowercase();
            let value = trimmed[pos + 1..].trim().to_string();
            headers.insert(key, value);
        }
    }
    Ok(headers)
}

async fn read_body(
    reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
    headers: &HashMap<String, String>,
) -> Result<Vec<u8>, String> {
    if let Some(len_str) = headers.get("content-length") {
        let len: usize = len_str
            .parse()
            .map_err(|e| format!("parse content-length '{}': {}", len_str, e))?;
        let mut body = vec![0u8; len];
        reader
            .read_exact(&mut body)
            .await
            .map_err(|e| format!("read body ({} bytes): {}", len, e))?;
        Ok(body)
    } else if headers.contains_key("transfer-encoding") {
        let mut body = Vec::new();
        reader
            .read_to_end(&mut body)
            .await
            .map_err(|e| format!("read body: {}", e))?;
        Ok(body)
    } else {
        Ok(Vec::new())
    }
}

fn parse_query(path: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    if let Some(pos) = path.find('?') {
        let query = &path[pos + 1..];
        for pair in query.split('&') {
            let mut iter = pair.splitn(2, '=');
            let key = iter.next().unwrap_or("").to_string();
            let value = iter.next().unwrap_or("").to_string();
            params.insert(url_decode(&key), url_decode(&value));
        }
    }
    params
}

fn url_decode(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte as char);
            }
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    result
}
