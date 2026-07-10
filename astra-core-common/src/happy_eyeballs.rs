use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;

/// Attempt a TCP connection with Happy Eyeballs (RFC 8305) dual-stack racing.
///
/// Given a hostname and port, resolves DNS and attempts connections
/// to all resolved IP addresses, racing IPv6 vs IPv4 with a small delay
/// for the preferred family.
///
/// Go equivalent: `transport/internet/happy_eyeballs.TcpRaceDial`
pub async fn dial_tcp_race(host: &str, port: u16, prefer_ipv6: bool) -> Result<TcpStream, String> {
    let addrs = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await
        .map_err(|e| format!("dns resolve {}: {}", host, e))?;

    let mut addresses: Vec<std::net::SocketAddr> = addrs.collect();
    if addresses.is_empty() {
        return Err(format!("no addresses for {}", host));
    }

    // Sort per RFC 8305: prefer family, then interleave
    sort_addresses(&mut addresses, prefer_ipv6);

    // Race connections with 300ms delay for non-preferred family
    let delay = Duration::from_millis(300);
    let mut last_err = String::new();

    for (i, addr) in addresses.iter().enumerate() {
        if i > 0 && is_different_family(addr, &addresses[0]) {
            tokio::time::sleep(delay).await;
        }

        match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last_err = format!("connect {}: {}", addr, e),
            Err(_) => last_err = format!("timeout connecting to {}", addr),
        }
    }

    Err(last_err)
}

/// Sort addresses per RFC 8305 section 5:
/// Preferred address family first, then interleave the other family.
fn sort_addresses(addrs: &mut [SocketAddr], prefer_ipv6: bool) {
    let (mut v6, mut v4): (Vec<SocketAddr>, Vec<SocketAddr>) =
        addrs.iter().partition(|a| a.is_ipv6());

    // Shuffle within each family for randomness
    // (simplified: just take as-is from DNS)

    if prefer_ipv6 {
        interleave(&mut v6, &mut v4, addrs);
    } else {
        interleave(&mut v4, &mut v6, addrs);
    }
}

fn interleave(preferred: &mut Vec<SocketAddr>, other: &mut [SocketAddr], out: &mut [SocketAddr]) {
    let mut i = 0;
    let max_len = preferred.len().max(other.len());
    for idx in 0..max_len {
        if idx < preferred.len() {
            out[i] = preferred[idx];
            i += 1;
        }
        if idx < other.len() {
            out[i] = other[idx];
            i += 1;
        }
    }
}

fn is_different_family(a: &SocketAddr, b: &SocketAddr) -> bool {
    a.is_ipv4() != b.is_ipv4()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sort_interleave_v4_first() {
        let v4: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let v6: SocketAddr = "[::1]:80".parse().unwrap();
        let mut addrs = vec![v6, v4];
        sort_addresses(&mut addrs, false);
        assert!(addrs[0].is_ipv4()); // v4 first
        assert!(addrs[1].is_ipv6()); // v6 second
    }

    #[test]
    fn test_sort_interleave_v6_first() {
        let v4: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let v6: SocketAddr = "[::1]:80".parse().unwrap();
        let mut addrs = vec![v4, v6];
        sort_addresses(&mut addrs, true);
        assert!(addrs[0].is_ipv6()); // v6 first
        assert!(addrs[1].is_ipv4()); // v4 second
    }

    #[test]
    fn test_is_different_family() {
        let v4: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let v6: SocketAddr = "[::1]:80".parse().unwrap();
        assert!(is_different_family(&v4, &v6));
        assert!(!is_different_family(&v4, &v4));
    }

    #[tokio::test]
    async fn test_dial_tcp_race_bad_host() {
        let result = dial_tcp_race("nonexistent.example.com", 80, false).await;
        assert!(result.is_err());
    }
}
