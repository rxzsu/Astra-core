use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Detected protocol for routing.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum SniffProtocol {
    #[default]
    Unknown,
    Http,
    Tls,
    BitTorrent,
    Dns,
}

impl SniffProtocol {
    pub fn as_str(&self) -> &str {
        match self {
            SniffProtocol::Http => "http",
            SniffProtocol::Tls => "tls",
            SniffProtocol::BitTorrent => "bittorrent",
            SniffProtocol::Dns => "dns",
            SniffProtocol::Unknown => "",
        }
    }
}

/// Result of sniffing.
#[derive(Debug, Clone, Default)]
pub struct SniffResult {
    pub protocol: SniffProtocol,
    pub domain: Option<String>,
}

/// A stream wrapper that returns peeked data first, then transparently reads from the inner stream.
pub struct SniffedStream<S> {
    inner: S,
    peek_buf: Vec<u8>,
    peek_pos: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> SniffedStream<S> {
    pub fn new(inner: S, peek_buf: Vec<u8>) -> Self {
        SniffedStream {
            inner,
            peek_buf,
            peek_pos: 0,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for SniffedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.peek_pos < self.peek_buf.len() {
            let n = std::cmp::min(buf.remaining(), self.peek_buf.len() - self.peek_pos);
            buf.put_slice(&self.peek_buf[self.peek_pos..self.peek_pos + n]);
            self.peek_pos += n;
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for SniffedStream<S> {
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

/// Sniff the protocol and domain from initial bytes of a connection.
pub fn sniff(data: &[u8]) -> SniffResult {
    if data.is_empty() {
        return SniffResult::default();
    }

    // Try BitTorrent
    if data.len() >= 20 && data[0] == 19 && &data[1..20] == b"BitTorrent protocol" {
        return SniffResult {
            protocol: SniffProtocol::BitTorrent,
            domain: None,
        };
    }

    // Try DNS
    if data.len() >= 12 {
        let qr = (data[2] >> 7) & 1;
        let opcode = (data[2] >> 3) & 0x0f;
        if qr == 0 && opcode == 0 {
            let qdcount = u16::from_be_bytes([data[4], data[5]]);
            if (1..=10).contains(&qdcount) {
                return SniffResult {
                    protocol: SniffProtocol::Dns,
                    domain: None,
                };
            }
        }
    }

    // Try HTTP
    if data.len() >= 4 {
        let start = &data[..4];
        if start == b"GET "
            || start == b"POST"
            || start == b"PUT "
            || start == b"HEAD"
            || start == b"PATC"
            || start == b"DELE"
            || start == b"OPTI"
            || start == b"TRAC"
            || start == b"CONN"
        {
            let host = sniff_http_host(data);
            return SniffResult {
                protocol: SniffProtocol::Http,
                domain: host,
            };
        }
    }

    // Try TLS ClientHello
    if data.len() >= 6 && data[0] == 0x16 {
        let version = u16::from_be_bytes([data[1], data[2]]);
        if version == 0x0301 || version == 0x0302 || version == 0x0303 || version == 0x0304 {
            let sni = sniff_tls_sni(data);
            return SniffResult {
                protocol: SniffProtocol::Tls,
                domain: sni,
            };
        }
    }

    SniffResult::default()
}

/// Extract the SNI hostname from a TLS ClientHello.
pub fn sniff_tls_sni(data: &[u8]) -> Option<String> {
    if data.len() < 44 || data[0] != 0x16 || data[5] != 0x01 {
        return None;
    }

    let mut pos: usize = 5 + 4 + 2 + 32;
    if pos >= data.len() {
        return None;
    }

    let session_len = data[pos] as usize;
    pos += 1 + session_len;

    if pos + 1 >= data.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cs_len;

    if pos >= data.len() {
        return None;
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;

    if pos + 1 >= data.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_len;
    while pos + 4 <= ext_end.min(data.len()) {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            if pos + 2 > data.len() {
                return None;
            }
            let _list_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;

            if pos + 3 > data.len() {
                return None;
            }
            let name_type = data[pos];
            let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
            pos += 3;

            if name_type == 0x00 && pos + name_len <= data.len() {
                return String::from_utf8(data[pos..pos + name_len].to_vec()).ok();
            }
            return None;
        }
        pos += ext_data_len;
    }
    None
}

/// Extract the Host header from an HTTP request.
pub fn sniff_http_host(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if let Some(host_val) = line.strip_prefix("Host:") {
            let host = host_val.trim();
            let host = host.split(':').next().unwrap_or(host);
            if !host.is_empty() {
                return Some(host.to_lowercase());
            }
        }
        if line.is_empty() {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sniff_http_get() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = sniff(data);
        assert_eq!(result.protocol, SniffProtocol::Http);
        assert_eq!(result.domain, Some("example.com".into()));
    }

    #[test]
    fn test_sniff_http_post() {
        let data = b"POST /api HTTP/1.1\r\nHost: api.example.com\r\n\r\nbody";
        let result = sniff(data);
        assert_eq!(result.protocol, SniffProtocol::Http);
        assert_eq!(result.domain, Some("api.example.com".into()));
    }

    #[test]
    fn test_sniff_tls_with_sni() {
        let sni_host = b"example.com";
        let hello = build_tls_client_hello(sni_host);
        let result = sniff(&hello);
        assert_eq!(result.protocol, SniffProtocol::Tls);
    }

    #[test]
    fn test_sniff_bittorrent() {
        let mut data = vec![19];
        data.extend_from_slice(b"BitTorrent protocol");
        let result = sniff(&data);
        assert_eq!(result.protocol, SniffProtocol::BitTorrent);
    }

    #[test]
    fn test_sniff_dns() {
        let mut query = vec![0x00, 0x01];
        query.extend_from_slice(&[0x01, 0x00]);
        query.extend_from_slice(&[0x00, 0x01]);
        query.extend_from_slice(&[0x00, 0x00]);
        query.extend_from_slice(&[0x00, 0x00]);
        query.extend_from_slice(&[0x00, 0x00]);
        query.push(3);
        query.extend_from_slice(b"www");
        query.push(7);
        query.extend_from_slice(b"example");
        query.push(3);
        query.extend_from_slice(b"com");
        query.push(0);
        query.extend_from_slice(&[0x00, 0x01]);
        query.extend_from_slice(&[0x00, 0x01]);
        let result = sniff(&query);
        assert_eq!(result.protocol, SniffProtocol::Dns);
    }

    fn build_tls_client_hello(sni: &[u8]) -> Vec<u8> {
        let sni_len = sni.len() as u16;
        let name_list_len = 3 + sni.len();
        let ext_data_len = 2 + name_list_len;

        let mut hello = Vec::new();
        hello.push(0x16);
        hello.extend_from_slice(&[0x03, 0x03, 0x00, 0x00]);
        hello.push(0x01);
        hello.extend_from_slice(&[0x00, 0x00, 0x00]);
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0x00);
        hello.extend_from_slice(&[0x00, 0x00]);
        hello.push(0x01);
        hello.push(0x00);

        hello.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
        hello.extend_from_slice(&[0x00, 0x00]);
        hello.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
        hello.extend_from_slice(&(name_list_len as u16).to_be_bytes());
        hello.push(0x00);
        hello.extend_from_slice(&sni_len.to_be_bytes());
        hello.extend_from_slice(sni);

        let msg_len = (hello.len() - 5) as u16;
        hello[3..5].copy_from_slice(&msg_len.to_be_bytes());
        let hm_len = (hello.len() - 5 - 4) as u32;
        hello[6..9].copy_from_slice(&hm_len.to_be_bytes()[1..4]);
        hello
    }
}
