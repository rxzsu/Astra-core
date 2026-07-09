use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::io::AsyncReadExt as _;
use tokio::io::AsyncWriteExt as _;

const MAX_HEADER_LENGTH: usize = 8192;

// ── Config types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct Header {
    pub name: String,
    pub value: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Version {
    pub value: String,
}

#[derive(Debug, Clone, Default)]
pub struct Method {
    pub value: String,
}

#[derive(Debug, Clone, Default)]
pub struct Status {
    pub code: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct RequestConfig {
    pub version: Option<Version>,
    pub method: Option<Method>,
    pub uri: Vec<String>,
    pub header: Vec<Header>,
}

impl RequestConfig {
    fn pick_uri(&self) -> &str {
        pick_str(&self.uri)
    }
    fn pick_headers(&self) -> Vec<String> {
        self.header.iter().map(|h| format!("{}: {}", h.name, pick_str(&h.value))).collect()
    }
    fn get_version_value(&self) -> &str {
        self.version.as_ref().map_or("1.1", |v| &v.value)
    }
    fn get_method_value(&self) -> &str {
        self.method.as_ref().map_or("GET", |m| &m.value)
    }
    fn get_full_version(&self) -> String {
        format!("HTTP/{}", self.get_version_value())
    }
}

#[derive(Debug, Clone, Default)]
pub struct ResponseConfig {
    pub version: Option<Version>,
    pub status: Option<Status>,
    pub header: Vec<Header>,
}

impl ResponseConfig {
    fn has_header(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.header.iter().any(|h| h.name.to_ascii_lowercase() == lower)
    }
    fn pick_headers(&self) -> Vec<String> {
        self.header.iter().map(|h| format!("{}: {}", h.name, pick_str(&h.value))).collect()
    }
    fn get_version_value(&self) -> &str {
        self.version.as_ref().map_or("1.1", |v| &v.value)
    }
    fn get_full_version(&self) -> String {
        format!("HTTP/{}", self.get_version_value())
    }
    fn get_status(&self) -> Status {
        self.status.clone().unwrap_or(Status { code: "200".into(), reason: "OK".into() })
    }
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub request: Option<RequestConfig>,
    pub response: Option<ResponseConfig>,
}

fn resp400() -> ResponseConfig {
    ResponseConfig {
        version: Some(Version { value: "1.1".into() }),
        status: Some(Status { code: "400".into(), reason: "Bad Request".into() }),
        header: vec![
            Header { name: "Connection".into(), value: vec!["close".into()] },
            Header { name: "Cache-Control".into(), value: vec!["private".into()] },
            Header { name: "Content-Length".into(), value: vec!["0".into()] },
        ],
    }
}

fn resp404() -> ResponseConfig {
    ResponseConfig {
        version: Some(Version { value: "1.1".into() }),
        status: Some(Status { code: "404".into(), reason: "Not Found".into() }),
        header: vec![
            Header { name: "Connection".into(), value: vec!["close".into()] },
            Header { name: "Cache-Control".into(), value: vec!["private".into()] },
            Header { name: "Content-Length".into(), value: vec!["0".into()] },
        ],
    }
}

fn pick_str(arr: &[String]) -> &str {
    if arr.len() <= 1 {
        return arr.first().map_or("", |s| s.as_str());
    }
    &arr[fastrand::usize(..arr.len())]
}

// ── Header reader & writer ──────────────────────────────────────────────────

/// Reads the HTTP request header from the start of a stream.
pub async fn read_header<R: AsyncRead + Unpin>(
    reader: &mut R,
    expected: Option<&RequestConfig>,
) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 1024];
        let n = reader.read(&mut chunk).await.map_err(|e| format!("header read: {}", e))?;
        if n == 0 {
            return Err("header: connection closed".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let header_bytes = &buf[..pos];
            let remaining = buf[pos + 4..].to_vec();
            if let Some(expected) = expected {
                let header_str = std::str::from_utf8(header_bytes).map_err(|_| "header: invalid utf8")?;
                let path = header_str.split_whitespace().nth(1).unwrap_or("");
                if !expected.uri.iter().any(|u| u == path) {
                    return Err("Header Mismatch.".into());
                }
            }
            return Ok(remaining);
        }
        if buf.len() > MAX_HEADER_LENGTH {
            return Err("Header too long.".into());
        }
    }
}

/// Writes a pre-built HTTP header.
pub async fn write_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    header: &[u8],
) -> Result<(), String> {
    writer.write_all(header).await.map_err(|e| format!("header write: {}", e))
}

// ── Header construction ─────────────────────────────────────────────────────

pub fn build_response_header(config: &ResponseConfig) -> Vec<u8> {
    let status = config.get_status();
    let mut out: Vec<u8> = format!("{} {} {}\r\n", config.get_full_version(), status.code, status.reason).into();
    for h in config.pick_headers() {
        out.extend_from_slice(h.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if !config.has_header("Date") {
        let now = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        out.extend_from_slice(b"Date: ");
        out.extend_from_slice(now.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

pub fn build_request_header(config: &RequestConfig) -> Vec<u8> {
    let mut out: Vec<u8> = format!("{} {} {}\r\n", config.get_method_value(), config.pick_uri(), config.get_full_version()).into();
    for h in config.pick_headers() {
        out.extend_from_slice(h.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Wraps a stream with HTTP header exchange.
/// After `handshake()`, data flows transparently.
pub struct HttpConn<T: AsyncRead + AsyncWrite + Unpin> {
    inner: T,
    read_pending: Option<Vec<u8>>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> HttpConn<T> {
    pub fn new(inner: T) -> Self {
        HttpConn {
            inner,
            read_pending: None,
        }
    }

    pub fn with_reader(mut self, _expected: Option<RequestConfig>) -> Self {
        self.read_pending = Some(Vec::new());
        self
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for HttpConn<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(ref data) = self.read_pending {
            if !data.is_empty() {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                let remaining = data[n..].to_vec();
                self.read_pending = if remaining.is_empty() { None } else { Some(remaining) };
                return Poll::Ready(Ok(()));
            }
            self.read_pending = None;
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for HttpConn<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ── Authenticator ───────────────────────────────────────────────────────────

pub struct Authenticator {
    config: Config,
}

impl Authenticator {
    pub fn new(config: Config) -> Self {
        Authenticator { config }
    }

    /// Wrap a connection for client-side use:
    /// - Writes the request header
    /// - Does NOT read a response header (server sends it as part of the response data)
    pub async fn client_handshake<T: AsyncRead + AsyncWrite + Unpin>(&self, conn: T) -> Result<HttpConn<T>, String> {
        let mut hc = HttpConn::new(conn);
        if let Some(ref req) = self.config.request {
            let header = build_request_header(req);
            hc.inner.write_all(&header).await.map_err(|e| format!("client header: {}", e))?;
        }
        Ok(hc)
    }

    /// Wrap a connection for server-side use:
    /// - Reads and validates the request header
    /// - Writes the response header
    pub async fn server_handshake<T: AsyncRead + AsyncWrite + Unpin>(&self, mut conn: T) -> Result<HttpConn<T>, String> {
        let expected = self.config.request.as_ref();
        let remaining = read_header(&mut conn, expected).await?;
        let mut hc = HttpConn::new(conn);
        hc.read_pending = Some(remaining);
        if let Some(ref resp) = self.config.response {
            let header = build_response_header(resp);
            hc.inner.write_all(&header).await.map_err(|e| format!("server header: {}", e))?;
        }
        Ok(hc)
    }
}

// ── Error response helpers ──────────────────────────────────────────────────

pub fn error_response_400() -> Vec<u8> {
    build_response_header(&resp400())
}

pub fn error_response_404() -> Vec<u8> {
    build_response_header(&resp404())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_request_header() {
        let cfg = RequestConfig {
            method: Some(Method { value: "GET".into() }),
            uri: vec!["/".into()],
            header: vec![Header { name: "Host".into(), value: vec!["example.com".into()] }],
            version: Some(Version { value: "1.1".into() }),
        };
        let h = build_request_header(&cfg);
        let s = String::from_utf8(h).unwrap();
        assert!(s.starts_with("GET / HTTP/1.1\r\n"));
        assert!(s.contains("Host: example.com"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_build_response_header() {
        let cfg = ResponseConfig {
            status: Some(Status { code: "200".into(), reason: "OK".into() }),
            header: vec![Header { name: "Content-Type".into(), value: vec!["text/plain".into()] }],
            ..Default::default()
        };
        let h = build_response_header(&cfg);
        let s = String::from_utf8(h).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Type: text/plain"));
    }

    #[test]
    fn test_pick_str_single() {
        let v = vec!["only".to_string()];
        assert_eq!(pick_str(&v), "only");
    }

    #[test]
    fn test_pick_str_empty() {
        let v: Vec<String> = vec![];
        assert_eq!(pick_str(&v), "");
    }

    #[tokio::test]
    async fn test_read_header_basic() {
        let data = b"GET /test HTTP/1.1\r\nHost: x\r\n\r\nremaining";
        let mut cur = std::io::Cursor::new(data.as_slice());
        let rem = read_header(&mut cur, None).await.unwrap();
        assert_eq!(rem, b"remaining");
    }

    #[tokio::test]
    async fn test_read_header_mismatch() {
        let data = b"GET /wrong HTTP/1.1\r\n\r\n";
        let mut cur = std::io::Cursor::new(data.as_slice());
        let expected = RequestConfig { uri: vec!["/expected".into()], ..Default::default() };
        let result = read_header(&mut cur, Some(&expected)).await;
        assert_eq!(result.unwrap_err(), "Header Mismatch.");
    }

    #[tokio::test]
    async fn test_write_header() {
        let (mut pipe, _reader) = tokio::io::duplex(1024);
        write_header(&mut pipe, b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
    }

    #[tokio::test]
    async fn test_authenticator_client_handshake() {
        let cfg = Config {
            request: Some(RequestConfig {
                method: Some(Method { value: "POST".into() }),
                uri: vec!["/proxy".into()],
                header: vec![Header { name: "X-Test".into(), value: vec!["1".into()] }],
                version: Some(Version { value: "1.1".into() }),
            }),
            response: None,
        };
        let auth = Authenticator::new(cfg);
        let (client, mut server) = tokio::io::duplex(1024);
        auth.client_handshake(client).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), server.read(&mut buf)).await.unwrap().unwrap();
        let s = String::from_utf8(buf[..n].to_vec()).unwrap();
        assert!(s.starts_with("POST /proxy HTTP/1.1\r\n"));
        assert!(s.contains("X-Test: 1"));
    }
}
