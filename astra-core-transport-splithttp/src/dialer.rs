use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use astra_core_net::Destination;
use astra_core_proxy::{Conn, ProxyResult};

use crate::config::{Config, SplitMode};
use crate::connection::SplitConn;
use crate::session::generate_session_id;

pub async fn dial(dest: &Destination, config: &Arc<Config>) -> ProxyResult<Conn> {
    let addr_str = format!("{}:{}", dest.address, dest.port.value());
    let tcp = TcpStream::connect(&addr_str)
        .await
        .map_err(|e| format!("splithttp dial tcp {}: {}", addr_str, e))?;

    let (reader, writer) = tokio::io::split(tcp);
    let reader = BufReader::new(reader);

    let session_id = generate_session_id();
    let path = config.path.clone();
    let host = if config.host.is_empty() {
        addr_str.clone()
    } else {
        config.host.clone()
    };

    match config.mode {
        SplitMode::PacketUp => {
            dial_packet_up(reader, writer, &session_id, &path, &host, config, &addr_str).await
        }
        _ => Err(format!(
            "splithttp mode {:?} not yet implemented in dialer",
            config.mode
        )),
    }
}

async fn dial_packet_up(
    mut reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    mut writer: tokio::io::WriteHalf<TcpStream>,
    session_id: &str,
    path: &str,
    host: &str,
    config: &Config,
    addr_str: &str,
) -> ProxyResult<Conn> {
    let download_url = format!("{}?session_id={}", path, session_id);
    let get_req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",
        download_url, host
    );
    writer
        .write_all(get_req.as_bytes())
        .await
        .map_err(|e| format!("splithttp send GET: {}", e))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("splithttp flush GET: {}", e))?;
    drop(writer);

    let resp = read_http_response_line(&mut reader).await?;
    if !resp.status_ok() {
        return Err(format!("splithttp GET failed: {}", resp.status_line));
    }
    skip_headers(&mut reader).await?;

    let (download_tx, download_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (upload_tx, upload_rx) = mpsc::channel::<Vec<u8>>(1024);

    let sid = session_id.to_string();
    let p = path.to_string();
    let h = host.to_string();
    let addr = addr_str.to_string();
    let max_sz = config.max_upload_size;
    let min_int = config.min_upload_interval;

    tokio::spawn(async move {
        read_download_body(reader, download_tx).await;
    });

    tokio::spawn(async move {
        upload_loop(upload_rx, &sid, &p, &h, &addr, max_sz, min_int).await;
    });

    Ok(Box::new(SplitConn::new(download_rx, upload_tx)))
}

async fn upload_loop(
    mut upload_rx: mpsc::Receiver<Vec<u8>>,
    session_id: &str,
    path: &str,
    host: &str,
    addr_str: &str,
    max_upload_size: usize,
    min_interval: std::time::Duration,
) {
    let mut seq: u64 = 0;
    let mut buf = Vec::new();

    loop {
        tokio::select! {
            Some(data) = upload_rx.recv() => {
                buf.extend_from_slice(&data);
                while buf.len() >= max_upload_size {
                    let chunk = buf[..max_upload_size].to_vec();
                    buf = buf[max_upload_size..].to_vec();
                    if let Err(e) = send_post(session_id, path, host, addr_str, seq, &chunk).await {
                        tracing::warn!("splithttp upload post failed: {}", e);
                        return;
                    }
                    seq += 1;
                    tokio::time::sleep(min_interval).await;
                }
            }
            else => {
                if !buf.is_empty() {
                    let _ = send_post(session_id, path, host, addr_str, seq, &buf).await;
                }
                break;
            }
        }
    }
}

async fn send_post(
    session_id: &str,
    path: &str,
    host: &str,
    addr_str: &str,
    seq: u64,
    data: &[u8],
) -> Result<(), String> {
    let tcp = TcpStream::connect(addr_str)
        .await
        .map_err(|e| format!("connect: {}", e))?;
    let (mut reader, mut writer) = tokio::io::split(tcp);

    let url = format!("{}?session_id={}&seq={}", path, session_id, seq);
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        url, host, data.len()
    );
    writer
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("write req: {}", e))?;
    writer
        .write_all(data)
        .await
        .map_err(|e| format!("write body: {}", e))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("flush: {}", e))?;

    let mut buf = [0u8; 4096];
    let _ = reader.read(&mut buf).await;
    Ok(())
}

async fn read_download_body(
    mut reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    tx: mpsc::Sender<Vec<u8>>,
) {
    if let Err(e) = read_chunked_body(&mut reader, &tx).await {
        tracing::debug!("splithttp download body done: {}", e);
    }
}

async fn read_chunked_body(
    reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<(), String> {
    let mut line = String::new();
    loop {
        line.clear();
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("read chunk size: {}", e))?;
        let chunk_size_str = line.trim();
        if chunk_size_str.is_empty() {
            continue;
        }
        let chunk_size = usize::from_str_radix(chunk_size_str, 16)
            .map_err(|e| format!("parse chunk size '{}': {}", chunk_size_str, e))?;
        if chunk_size == 0 {
            let _ = reader.read_line(&mut line).await;
            break;
        }
        let mut chunk = vec![0u8; chunk_size];
        reader
            .read_exact(&mut chunk)
            .await
            .map_err(|e| format!("read chunk data: {}", e))?;
        let _ = reader.read_line(&mut line).await;
        if tx.send(chunk).await.is_err() {
            break;
        }
    }
    Ok(())
}

struct HttpResponseLine {
    status_line: String,
    code: u16,
}

impl HttpResponseLine {
    fn status_ok(&self) -> bool {
        self.code == 200
    }
}

async fn read_http_response_line(
    reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
) -> Result<HttpResponseLine, String> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|e| format!("read response line: {}", e))?;
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!("invalid HTTP response: {}", line.trim()));
    }
    let code: u16 = parts[1]
        .parse()
        .map_err(|e| format!("parse status code '{}': {}", parts[1], e))?;
    Ok(HttpResponseLine {
        status_line: line.trim().to_string(),
        code,
    })
}

async fn skip_headers(reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>) -> Result<(), String> {
    let mut line = String::new();
    loop {
        line.clear();
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("read header: {}", e))?;
        if line.trim().is_empty() {
            break;
        }
    }
    Ok(())
}
