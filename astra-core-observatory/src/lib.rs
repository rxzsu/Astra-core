use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;

pub mod burst;

/// Result of a health probe.
#[derive(Debug, Clone)]
pub struct OutboundStatus {
    pub tag: String,
    pub alive: bool,
    /// Last successful/failed probe latency in milliseconds (0 if unknown).
    pub delay_ms: u64,
    pub last_error: Option<String>,
    pub last_seen: Instant,
}

/// How to probe outbound health.
#[derive(Debug, Clone)]
pub enum ProbeMethod {
    /// Plain TCP connect to host:port.
    Tcp { host: String, port: u16 },
    /// HTTP(S) GET to a full URL; success on 2xx/3xx (incl. 204).
    Http { url: String },
}

impl ProbeMethod {
    /// Build probe method from config-style fields.
    ///
    /// - `probe_type`: `"tcp"` (default), `"http"`, or `"https"`
    /// - `probe_url`:
    ///   - for TCP: `"host:port"` or just host (port defaults to 80)
    ///   - for HTTP: full URL like `http://www.gstatic.com/generate_204`
    pub fn from_config(probe_type: &str, probe_url: Option<&str>) -> Self {
        let t = probe_type.trim().to_ascii_lowercase();
        let url = probe_url.unwrap_or("").trim();

        if t == "http" || t == "https" || url.starts_with("http://") || url.starts_with("https://")
        {
            let default = if t == "https" {
                "https://www.gstatic.com/generate_204"
            } else {
                "http://www.gstatic.com/generate_204"
            };
            let full = if url.is_empty() {
                default.to_string()
            } else if !url.starts_with("http://") && !url.starts_with("https://") {
                format!("{}://{}", if t == "https" { "https" } else { "http" }, url)
            } else {
                url.to_string()
            };
            return ProbeMethod::Http { url: full };
        }

        // TCP: parse host:port from probe_url
        let (host, port) = if url.is_empty() {
            ("1.1.1.1".to_string(), 80u16)
        } else if let Some((h, p)) = url.rsplit_once(':') {
            let port = p.parse::<u16>().unwrap_or(80);
            // Handle IPv6 [::1]:80 roughly: if host starts with '[', keep as-is
            (h.trim_matches(|c| c == '[' || c == ']').to_string(), port)
        } else {
            (url.to_string(), 80u16)
        };

        ProbeMethod::Tcp { host, port }
    }
}

/// Observatory: health checks outbounds and reports status.
pub struct Observatory {
    /// Tags under observation.
    selector: Vec<String>,
    /// Shared set of tags currently considered alive.
    alive: Arc<RwLock<HashSet<String>>>,
    /// Last probe metadata per tag.
    status: Arc<RwLock<std::collections::HashMap<String, (bool, u64, Option<String>, Instant)>>>,
    probe: ProbeMethod,
    /// Interval between probes (seconds).
    interval_secs: u64,
    /// Per-probe timeout.
    timeout: Duration,
}

impl Observatory {
    pub fn new(
        selector: Vec<String>,
        alive: Arc<RwLock<HashSet<String>>>,
        probe_host: String,
        probe_port: u16,
        interval_secs: u64,
    ) -> Self {
        Self::with_probe(
            selector,
            alive,
            ProbeMethod::Tcp {
                host: probe_host,
                port: probe_port,
            },
            interval_secs,
        )
    }

    pub fn with_probe(
        selector: Vec<String>,
        alive: Arc<RwLock<HashSet<String>>>,
        probe: ProbeMethod,
        interval_secs: u64,
    ) -> Self {
        {
            let mut a = alive.write().unwrap();
            for tag in &selector {
                a.insert(tag.clone());
            }
        }

        let mut status = std::collections::HashMap::new();
        let now = Instant::now();
        for tag in &selector {
            status.insert(tag.clone(), (true, 0, None, now));
        }

        Observatory {
            selector,
            alive,
            status: Arc::new(RwLock::new(status)),
            probe,
            interval_secs: interval_secs.max(1),
            timeout: Duration::from_secs(5),
        }
    }

    /// Start the health check loop in a background task.
    pub fn start(self) {
        tokio::spawn(async move {
            self.run().await;
        });
    }

    async fn run(&self) {
        loop {
            let start = Instant::now();
            let result = self.probe_once().await;
            let delay_ms = start.elapsed().as_millis() as u64;

            let count = {
                let mut alive = self.alive.write().unwrap();
                let mut status = self.status.write().unwrap();
                match result {
                    Ok(()) => {
                        for tag in &self.selector {
                            alive.insert(tag.clone());
                            status.insert(tag.clone(), (true, delay_ms, None, Instant::now()));
                        }
                    }
                    Err(ref err) => {
                        for tag in &self.selector {
                            alive.remove(tag);
                            status.insert(
                                tag.clone(),
                                (false, delay_ms, Some(err.clone()), Instant::now()),
                            );
                        }
                    }
                }
                alive.len()
            };

            tracing::debug!(
                "observatory: {}/{} outbounds alive (delay={}ms, probe={})",
                count,
                self.selector.len(),
                delay_ms,
                self.probe_label(),
            );

            sleep(Duration::from_secs(self.interval_secs)).await;
        }
    }

    fn probe_label(&self) -> String {
        match &self.probe {
            ProbeMethod::Tcp { host, port } => format!("tcp://{}:{}", host, port),
            ProbeMethod::Http { url } => url.clone(),
        }
    }

    async fn probe_once(&self) -> Result<(), String> {
        match &self.probe {
            ProbeMethod::Tcp { host, port } => self.probe_tcp(host, *port).await,
            ProbeMethod::Http { url } => self.probe_http(url).await,
        }
    }

    async fn probe_tcp(&self, host: &str, port: u16) -> Result<(), String> {
        let addr = format!("{}:{}", host, port);
        match tokio::time::timeout(self.timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(format!("tcp connect {}: {}", addr, e)),
            Err(_) => Err(format!("tcp connect {} timed out", addr)),
        }
    }

    /// Minimal HTTP/1.1 GET without external HTTP client crates.
    async fn probe_http(&self, url: &str) -> Result<(), String> {
        let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
            ("https", r)
        } else if let Some(r) = url.strip_prefix("http://") {
            ("http", r)
        } else {
            return Err(format!("unsupported URL scheme: {}", url));
        };

        let (host_port, path) = match rest.split_once('/') {
            Some((h, p)) => (h, format!("/{}", p)),
            None => (rest, "/".to_string()),
        };

        let (host, port) = if let Some((h, p)) = host_port.rsplit_once(':') {
            // skip IPv6 ambiguity for common cases host:port
            if h.contains(':') && !host_port.starts_with('[') {
                (host_port, if scheme == "https" { 443 } else { 80 })
            } else {
                (
                    h,
                    p.parse::<u16>()
                        .unwrap_or(if scheme == "https" { 443 } else { 80 }),
                )
            }
        } else {
            (host_port, if scheme == "https" { 443 } else { 80 })
        };

        let addr = format!("{}:{}", host, port);
        let connect = TcpStream::connect(&addr);
        let stream = tokio::time::timeout(self.timeout, connect)
            .await
            .map_err(|_| format!("connect {} timed out", addr))?
            .map_err(|e| format!("connect {}: {}", addr, e))?;

        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: astra-observatory/1.0\r\nConnection: close\r\nAccept: */*\r\n\r\n",
            path, host
        );

        let response = if scheme == "https" {
            self.http_over_tls(stream, host, &request).await?
        } else {
            self.http_plain(stream, &request).await?
        };

        parse_http_success(&response)
    }

    async fn http_plain(&self, mut stream: TcpStream, request: &str) -> Result<String, String> {
        tokio::time::timeout(self.timeout, stream.write_all(request.as_bytes()))
            .await
            .map_err(|_| "write timed out".to_string())?
            .map_err(|e| format!("write: {}", e))?;

        let mut buf = Vec::with_capacity(2048);
        let mut tmp = [0u8; 1024];
        loop {
            match tokio::time::timeout(self.timeout, stream.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.len() > 64 * 1024 {
                        break;
                    }
                    // Enough for status line
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Ok(Err(e)) => return Err(format!("read: {}", e)),
                Err(_) => return Err("read timed out".into()),
            }
        }
        String::from_utf8(buf).map_err(|e| format!("utf8: {}", e))
    }

    async fn http_over_tls(
        &self,
        stream: TcpStream,
        host: &str,
        request: &str,
    ) -> Result<String, String> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let server_name = rustls_pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| format!("invalid SNI host {}: {}", host, e))?;

        let mut tls = tokio::time::timeout(self.timeout, connector.connect(server_name, stream))
            .await
            .map_err(|_| "tls handshake timed out".to_string())?
            .map_err(|e| format!("tls handshake: {}", e))?;

        tokio::time::timeout(self.timeout, tls.write_all(request.as_bytes()))
            .await
            .map_err(|_| "tls write timed out".to_string())?
            .map_err(|e| format!("tls write: {}", e))?;

        let mut buf = Vec::with_capacity(2048);
        let mut tmp = [0u8; 1024];
        loop {
            match tokio::time::timeout(self.timeout, tls.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.len() > 64 * 1024 || buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Ok(Err(e)) => return Err(format!("tls read: {}", e)),
                Err(_) => return Err("tls read timed out".into()),
            }
        }
        String::from_utf8(buf).map_err(|e| format!("utf8: {}", e))
    }

    pub fn get_alive(&self) -> Arc<RwLock<HashSet<String>>> {
        self.alive.clone()
    }

    pub fn get_status(&self) -> Vec<OutboundStatus> {
        let status = self.status.read().unwrap();
        self.selector
            .iter()
            .map(|tag| {
                let (alive, delay_ms, last_error, last_seen) = status
                    .get(tag)
                    .cloned()
                    .unwrap_or((false, 0, None, Instant::now()));
                OutboundStatus {
                    tag: tag.clone(),
                    alive,
                    delay_ms,
                    last_error,
                    last_seen,
                }
            })
            .collect()
    }
}

fn parse_http_success(response: &str) -> Result<(), String> {
    let status_line = response.lines().next().unwrap_or("");
    // HTTP/1.1 204 No Content
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| format!("bad status line: {}", status_line))?;
    if (200..400).contains(&code) {
        Ok(())
    } else {
        Err(format!("HTTP status {}", code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_method_tcp_default() {
        match ProbeMethod::from_config("", None) {
            ProbeMethod::Tcp { host, port } => {
                assert_eq!(host, "1.1.1.1");
                assert_eq!(port, 80);
            }
            _ => panic!("expected tcp"),
        }
    }

    #[test]
    fn probe_method_tcp_host_port() {
        match ProbeMethod::from_config("tcp", Some("8.8.8.8:53")) {
            ProbeMethod::Tcp { host, port } => {
                assert_eq!(host, "8.8.8.8");
                assert_eq!(port, 53);
            }
            _ => panic!("expected tcp"),
        }
    }

    #[test]
    fn probe_method_http_url() {
        match ProbeMethod::from_config("http", Some("http://www.gstatic.com/generate_204")) {
            ProbeMethod::Http { url } => {
                assert!(url.contains("gstatic.com"));
            }
            _ => panic!("expected http"),
        }
    }

    #[test]
    fn probe_method_http_from_type() {
        match ProbeMethod::from_config("http", None) {
            ProbeMethod::Http { url } => assert!(url.starts_with("http://")),
            _ => panic!("expected http"),
        }
    }

    #[test]
    fn parse_http_204() {
        assert!(parse_http_success("HTTP/1.1 204 No Content\r\n\r\n").is_ok());
        assert!(parse_http_success("HTTP/1.1 200 OK\r\n\r\n").is_ok());
        assert!(parse_http_success("HTTP/1.1 500 Err\r\n\r\n").is_err());
    }
}
