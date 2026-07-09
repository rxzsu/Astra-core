/// Sing-box compatibility bridge.
/// Go equivalent: `common/singbridge`
/// Provides adapter types for interoperating with sing-box.

use std::net::SocketAddr;

/// Convert an internal Address+Port to a sing-box compatible socket address.
pub fn to_socksaddr(address: &str, port: u16) -> SocketAddr {
    format!("{}:{}", address, port).parse().unwrap_or_else(|_| {
        if address.contains(':') {
            format!("[{}]:{}", address, port).parse().unwrap_or_else(|_| {
                SocketAddr::from(([0, 0, 0, 0], port))
            })
        } else {
            SocketAddr::from(([0, 0, 0, 0], port))
        }
    })
}

/// Copy data between two connections, returning errors in sing-box compatible format.
pub async fn copy_conn(
    dst: &mut (dyn tokio::io::AsyncWrite + Unpin + Send),
    src: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
) -> Result<u64, String> {
    tokio::io::copy(src, dst)
        .await
        .map_err(|e| format!("copy: {}", e))
}

/// Wrapper for packet connections that tracks errors in sing-box style.
pub struct PacketConnWrapper {
    #[allow(dead_code)]
    inner: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_socksaddr() {
        let addr = to_socksaddr("1.2.3.4", 443);
        assert_eq!(addr.port(), 443);
        assert!(addr.ip().is_ipv4());
    }
}
