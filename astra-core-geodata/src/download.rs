//! Download geoip.dat / geosite.dat from remote URLs (Xray-style auto-fetch).

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Default Loyalsoldier / v2fly-style release URLs (same family as common Xray setups).
pub const DEFAULT_GEOIP_URL: &str =
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat";
pub const DEFAULT_GEOSITE_URL: &str =
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat";

#[derive(Debug, Clone)]
pub struct DownloadOptions {
    pub timeout: Duration,
    /// If true, skip download when destination file already exists.
    pub skip_if_exists: bool,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        DownloadOptions {
            timeout: Duration::from_secs(120),
            skip_if_exists: true,
        }
    }
}

/// Download a single file via HTTP/HTTPS (follows one level of redirect).
pub async fn download_file(url: &str, dest: &Path, opts: &DownloadOptions) -> Result<(), String> {
    if opts.skip_if_exists && dest.exists() {
        tracing::info!(path = %dest.display(), "geo data already present, skip download");
        return Ok(());
    }

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {}", parent.display(), e))?;
    }

    let tmp = dest.with_extension("dat.tmp");
    let bytes = http_get_bytes(url, opts.timeout, 0).await?;
    if bytes.is_empty() {
        return Err(format!("empty response from {}", url));
    }

    tokio::fs::write(&tmp, &bytes)
        .await
        .map_err(|e| format!("write {}: {}", tmp.display(), e))?;
    tokio::fs::rename(&tmp, dest)
        .await
        .map_err(|e| format!("rename to {}: {}", dest.display(), e))?;

    tracing::info!(
        path = %dest.display(),
        bytes = bytes.len(),
        "downloaded geo data"
    );
    Ok(())
}

/// Ensure geoip.dat and geosite.dat exist under `dir`, downloading if missing.
pub async fn ensure_geo_files(
    dir: impl AsRef<Path>,
    geoip_url: Option<&str>,
    geosite_url: Option<&str>,
    opts: DownloadOptions,
) -> Result<(PathBuf, PathBuf), String> {
    let dir = dir.as_ref();
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {}", dir.display(), e))?;

    let geoip = dir.join("geoip.dat");
    let geosite = dir.join("geosite.dat");

    download_file(
        geoip_url.unwrap_or(DEFAULT_GEOIP_URL),
        &geoip,
        &opts,
    )
    .await?;
    download_file(
        geosite_url.unwrap_or(DEFAULT_GEOSITE_URL),
        &geosite,
        &opts,
    )
    .await?;

    Ok((geoip, geosite))
}

async fn http_get_bytes(url: &str, timeout: Duration, redirect_depth: u8) -> Result<Vec<u8>, String> {
    if redirect_depth > 5 {
        return Err("too many redirects".into());
    }

    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else {
        return Err(format!("unsupported URL: {}", url));
    };

    let (host_port, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{}", p)),
        None => (rest, "/".to_string()),
    };

    let (host, port) = parse_host_port(host_port, scheme);
    let addr = format!("{}:{}", host, port);

    let stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("connect {} timed out", addr))?
        .map_err(|e| format!("connect {}: {}", addr, e))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: astra-core-geodata/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        path, host
    );

    let raw = if scheme == "https" {
        tls_exchange(stream, &host, &request, timeout).await?
    } else {
        plain_exchange(stream, &request, timeout).await?
    };

    let (status, headers, body) = split_http_response(&raw)?;
    if (300..400).contains(&status) {
        if let Some(loc) = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.clone())
        {
            let next = if loc.starts_with("http://") || loc.starts_with("https://") {
                loc
            } else if loc.starts_with('/') {
                format!("{}://{}{}", scheme, host, loc)
            } else {
                format!("{}://{}/{}", scheme, host, loc)
            };
            return Box::pin(http_get_bytes(&next, timeout, redirect_depth + 1)).await;
        }
        return Err(format!("HTTP {} without Location", status));
    }
    if !(200..300).contains(&status) {
        return Err(format!("HTTP {} from {}", status, url));
    }
    Ok(body)
}

fn parse_host_port(host_port: &str, scheme: &str) -> (String, u16) {
    if let Some((h, p)) = host_port.rsplit_once(':') {
        if !h.contains(':') || host_port.starts_with('[') {
            let host = h.trim_matches(|c| c == '[' || c == ']').to_string();
            let port = p.parse().unwrap_or(if scheme == "https" { 443 } else { 80 });
            return (host, port);
        }
    }
    (
        host_port.to_string(),
        if scheme == "https" { 443 } else { 80 },
    )
}

async fn plain_exchange(
    mut stream: TcpStream,
    request: &str,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    tokio::time::timeout(timeout, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| "write timed out".to_string())?
        .map_err(|e| format!("write: {}", e))?;
    read_all(&mut stream, timeout).await
}

async fn tls_exchange(
    stream: TcpStream,
    host: &str,
    request: &str,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let server_name = rustls_pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| format!("SNI: {}", e))?;
    let mut tls = tokio::time::timeout(timeout, connector.connect(server_name, stream))
        .await
        .map_err(|_| "tls handshake timed out".to_string())?
        .map_err(|e| format!("tls: {}", e))?;
    tokio::time::timeout(timeout, tls.write_all(request.as_bytes()))
        .await
        .map_err(|_| "tls write timed out".to_string())?
        .map_err(|e| format!("tls write: {}", e))?;
    read_all(&mut tls, timeout).await
}

async fn read_all<R: AsyncReadExt + Unpin>(reader: &mut R, timeout: Duration) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match tokio::time::timeout(timeout, reader.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&tmp[..n]);
                // Cap at 64 MiB for geo dat files
                if buf.len() > 64 * 1024 * 1024 {
                    return Err("response too large".into());
                }
            }
            Ok(Err(e)) => return Err(format!("read: {}", e)),
            Err(_) => return Err("read timed out".into()),
        }
    }
    Ok(buf)
}

fn split_http_response(raw: &[u8]) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "incomplete HTTP response".to_string())?;
    let header_bytes = &raw[..sep];
    let body = raw[sep + 4..].to_vec();
    let header_str = String::from_utf8_lossy(header_bytes);
    let mut lines = header_str.lines();
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("bad status: {}", status_line))?;

    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((status, headers, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_port_default() {
        let (h, p) = parse_host_port("example.com", "https");
        assert_eq!(h, "example.com");
        assert_eq!(p, 443);
    }

    #[test]
    fn split_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        let (status, headers, body) = split_http_response(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"abc");
        assert_eq!(headers[0].0, "Content-Length");
    }
}
