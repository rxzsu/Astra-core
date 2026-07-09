use tokio::io::AsyncReadExt;

/// Parse a PROXY protocol v1 header from a connection.
/// Returns the source address if successful.
/// Go equivalent: `proxyproto.HeaderProxyFromAddrs`
pub async fn accept_proxy_protocol(
    conn: &mut tokio::net::TcpStream,
) -> Result<Option<String>, String> {
    // PROXY protocol v1: "PROXY TCP4/AF_UNSPEC src_ip dst_ip src_port dst_port\r\n"
    let mut buf = [0u8; 108]; // Max PROXY v1 header size
    let n = conn
        .peek(&mut buf)
        .await
        .map_err(|e| format!("proxy peek: {}", e))?;

    if n < 8 || &buf[..5] != b"PROXY" {
        return Ok(None); // Not a PROXY protocol connection
    }

    // Find the end of the line
    let header_end = buf[..n]
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| "proxy protocol: no CRLF found".to_string())?
        + 2;

    let header = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| "proxy protocol: invalid utf8".to_string())?;

    // Consume the header from the stream
    let mut temp = vec![0u8; header_end];
    conn.read_exact(&mut temp)
        .await
        .map_err(|e| format!("proxy read: {}", e))?;

    tracing::debug!("PROXY protocol header: {}", header);

    // Parse "PROXY TCP4 1.2.3.4 5.6.7.8 12345 443"
    let parts: Vec<&str> = header.split_whitespace().collect();
    if parts.len() >= 5 && (parts[1] == "TCP4" || parts[1] == "TCP6" || parts[1] == "TCP") {
        Ok(Some(format!("{}:{}", parts[2], parts[4])))
    } else {
        Ok(Some("UNKNOWN".to_string()))
    }
}
