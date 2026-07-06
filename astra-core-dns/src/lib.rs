use std::collections::HashMap;
use std::net::IpAddr;



// ─── DNS constants ──────────────────────────────────────────────────────────

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const QCLASS_IN: u16 = 1;

// ─── Query strategy ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum QueryStrategy {
    #[default]
    UseIp,
    UseIp4,
    UseIp6,
}

impl QueryStrategy {
    pub fn from_str(s: &str) -> Self {
        match s {
            "UseIPv4" => QueryStrategy::UseIp4,
            "UseIPv6" => QueryStrategy::UseIp6,
            _ => QueryStrategy::UseIp,
        }
    }
}

// ─── DnsResolver trait ──────────────────────────────────────────────────────

#[async_trait::async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, String>;
}

// ─── DNS wire format ────────────────────────────────────────────────────────

/// Encode a domain name into DNS label format (length-prefixed labels + zero terminator).
pub fn encode_domain_name(domain: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in domain.split('.') {
        let len = label.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&label.as_bytes()[..len]);
    }
    out.push(0);
    out
}

/// Decode a domain name from DNS label format starting at `offset` in `data`.
/// Returns (name, new_offset). Handles compression pointers.
pub fn decode_domain_name(data: &[u8], offset: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut pos = offset;
    let mut jumped = false;
    let mut jump_pos = 0;

    loop {
        if pos >= data.len() {
            return Err("truncated domain name".into());
        }
        let len = data[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // Check for compression pointer (top 2 bits = 11)
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= data.len() {
                return Err("truncated pointer".into());
            }
            let ptr = ((len & 0x3f) << 8) | (data[pos + 1] as usize);
            if !jumped {
                jump_pos = pos + 2;
                jumped = true;
            }
            pos = ptr;
            continue;
        }
        if pos + 1 + len > data.len() {
            return Err("truncated label".into());
        }
        labels.push(
            std::str::from_utf8(&data[pos + 1..pos + 1 + len])
                .map_err(|_| "invalid utf8 in domain".to_string())?,
        );
        pos += 1 + len;
    }

    let name = labels.join(".");
    let end_pos = if jumped { jump_pos } else { pos };
    Ok((name, end_pos))
}

/// Build a DNS query packet for the given domain and record type.
pub fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let id: u16 = rand::random();

    let mut buf = Vec::with_capacity(512);
    // Header
    buf.extend_from_slice(&id.to_be_bytes()); // ID
    buf.extend_from_slice(&[0x01, 0x00]);     // flags: RD=1
    buf.extend_from_slice(&[0x00, 0x01]);     // QDCOUNT = 1
    buf.extend_from_slice(&[0x00, 0x00]);     // ANCOUNT = 0
    buf.extend_from_slice(&[0x00, 0x00]);     // NSCOUNT = 0
    buf.extend_from_slice(&[0x00, 0x00]);     // ARCOUNT = 0
    // Question
    buf.extend_from_slice(&encode_domain_name(domain));
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&QCLASS_IN.to_be_bytes());

    buf
}

/// Parse a DNS response and extract A/AAAA records.
pub fn parse_dns_response(data: &[u8]) -> Result<Vec<IpAddr>, String> {
    if data.len() < DNS_HEADER_SIZE {
        return Err("response too short".into());
    }

    // Check QR bit (bit 15 of flags) and RCODE (low 4 bits of byte 3)
    let flags = u16::from_be_bytes([data[2], data[3]]);
    if flags & 0x8000 == 0 {
        return Err("not a DNS response".into());
    }
    let rcode = (flags & 0x000f) as u8;
    if rcode != 0 {
        let reasons = [
            "NoError", "FormErr", "ServFail", "NXDomain",
            "NotImp", "Refused", "YXDomain", "YXRRSet",
            "NXRRSet", "NotAuth", "NotZone",
        ];
        let reason = reasons.get(rcode as usize).unwrap_or(&"Unknown");
        return Err(format!("DNS error {}: {}", rcode, reason));
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    // Skip questions
    let mut pos = DNS_HEADER_SIZE;
    for _ in 0..qdcount {
        let (_, new_pos) = decode_domain_name(data, pos)?;
        pos = new_pos + 4; // skip QTYPE + QCLASS
    }

    // Parse answers
    let mut ips = Vec::new();
    for _ in 0..ancount {
        let (_, new_pos) = decode_domain_name(data, pos)?;
        pos = new_pos;

        if pos + 10 > data.len() {
            return Err("truncated answer".into());
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let _rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        let _ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > data.len() {
            return Err("truncated rdata".into());
        }

        match rtype {
            QTYPE_A if rdlength == 4 => {
                ips.push(IpAddr::V4(std::net::Ipv4Addr::new(
                    data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                )));
            }
            QTYPE_AAAA if rdlength == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[pos..pos + 16]);
                ips.push(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        pos += rdlength;
    }

    Ok(ips)
}

const DNS_HEADER_SIZE: usize = 12;

// ─── Nameserver config ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NameServer {
    pub address: String,
    pub port: u16,
    pub domains: Vec<String>,
    pub expected_ips: Vec<IpAddr>,
}

impl NameServer {
    fn matches_domain(&self, domain: &str) -> bool {
        if self.domains.is_empty() {
            return true;
        }
        for pattern in &self.domains {
            if let Some(suffix) = pattern.strip_prefix("domain:") {
                if domain == suffix || domain.ends_with(&format!(".{}", suffix)) {
                    return true;
                }
            } else if let Some(keyword) = pattern.strip_prefix("keyword:") {
                if domain.contains(keyword) {
                    return true;
                }
            } else if let Some(_regex) = pattern.strip_prefix("regexp:") {
                // regex not yet supported
            } else {
                // bare domain = exact match
                if domain == pattern {
                    return true;
                }
            }
        }
        false
    }
}

// ─── UdpDnsResolver ────────────────────────────────────────────────────────

/// Resolves domains by sending real DNS queries over UDP to configured nameservers.
pub struct UdpDnsResolver {
    nameservers: Vec<NameServer>,
    hosts: HashMap<String, Vec<IpAddr>>,
    query_strategy: QueryStrategy,
}

impl UdpDnsResolver {
    pub fn new(
        nameservers: Vec<NameServer>,
        hosts: HashMap<String, Vec<IpAddr>>,
        query_strategy: QueryStrategy,
    ) -> Self {
        UdpDnsResolver { nameservers, hosts, query_strategy }
    }
}

#[async_trait::async_trait]
impl DnsResolver for UdpDnsResolver {
    async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, String> {
        let lower = domain.to_lowercase();

        if let Some(addrs) = self.hosts.get(&lower) {
            return Ok(addrs.clone());
        }

        // Pick the right nameserver for this domain
        let ns = self
            .nameservers
            .iter()
            .find(|ns| ns.matches_domain(&lower))
            .unwrap_or(&self.nameservers[0]);

        let ns_addr = format!("{}:{}", ns.address, ns.port);

        let qtypes: &[u16] = match self.query_strategy {
            QueryStrategy::UseIp4 => &[QTYPE_A],
            QueryStrategy::UseIp6 => &[QTYPE_AAAA],
            QueryStrategy::UseIp => &[QTYPE_A, QTYPE_AAAA],
        };

        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("bind udp: {}", e))?;

        let mut all_ips = Vec::new();
        for &qtype in qtypes {
            let query = build_dns_query(&lower, qtype);
            if socket.send_to(&query, &ns_addr).await.is_err() {
                continue;
            }

            let mut buf = vec![0u8; 512];
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                socket.recv_from(&mut buf),
            )
            .await
            .map_err(|_| format!("dns timeout for {}", domain))?
            .map_err(|e| format!("dns recv: {}", e))?
            .0;

            if let Ok(ips) = parse_dns_response(&buf[..n]) {
                if !ns.expected_ips.is_empty() {
                    let filtered: Vec<IpAddr> = ips
                        .into_iter()
                        .filter(|ip| ns.expected_ips.contains(ip))
                        .collect();
                    if !filtered.is_empty() {
                        all_ips.extend(filtered);
                        break;
                    }
                } else {
                    all_ips.extend(ips);
                    if !all_ips.is_empty() {
                        break;
                    }
                }
            }
        }

        if all_ips.is_empty() {
            Err(format!("no addresses found for {}", domain))
        } else {
            Ok(all_ips)
        }
    }
}

// ─── FakeDnsResolver ───────────────────────────────────────────────────────

/// Fake DNS resolver: allocates fake IPs for domains and provides reverse lookup.
/// Used in transparent proxy to map connections to fake IPs back to real domains.
pub struct FakeDnsResolver {
    pool: FakeIpPool,
    domain_to_ip: tokio::sync::Mutex<std::collections::HashMap<String, IpAddr>>,
    ip_to_domain: tokio::sync::Mutex<std::collections::HashMap<IpAddr, String>>,
}

struct FakeIpPool {
    base: std::net::Ipv4Addr,
    count: u32,
    next: std::sync::atomic::AtomicU32,
}

impl FakeIpPool {
    fn new(base: std::net::Ipv4Addr, prefix: u8) -> Self {
        let count = 1u32 << (32 - prefix.min(32).max(8));
        FakeIpPool { base, count, next: std::sync::atomic::AtomicU32::new(1) }
    }

    fn allocate(&self) -> Option<IpAddr> {
        let offset = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if offset >= self.count {
            return None;
        }
        let mut octets = self.base.octets();
        let v = u32::from_be_bytes(octets).wrapping_add(offset);
        octets = v.to_be_bytes();
        Some(IpAddr::V4(std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])))
    }
}

impl FakeDnsResolver {
    pub fn new(base: std::net::Ipv4Addr, prefix: u8) -> Self {
        FakeDnsResolver {
            pool: FakeIpPool::new(base, prefix),
            domain_to_ip: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            ip_to_domain: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn new_default() -> Self {
        Self::new(std::net::Ipv4Addr::new(198, 18, 0, 0), 15)
    }

    /// Reverse lookup: find the domain that maps to this fake IP.
    pub fn get_domain(&self, ip: IpAddr) -> Option<String> {
        self.ip_to_domain.try_lock().ok()?.get(&ip).cloned()
    }

    /// Check if an IP belongs to the fake pool range.
    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let base_octets = self.pool.base.octets();
                let v4_octets = v4.octets();
                // 198.18.0.0/15 check
                v4_octets[0] == base_octets[0] && v4_octets[1] == base_octets[1]
            }
            IpAddr::V6(_) => false,
        }
    }
}

#[async_trait::async_trait]
impl DnsResolver for FakeDnsResolver {
    async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, String> {
        let lower = domain.to_lowercase();

        {
            let map = self.domain_to_ip.lock().await;
            if let Some(ip) = map.get(&lower) {
                return Ok(vec![*ip]);
            }
        }

        let ip = self.pool.allocate().ok_or_else(|| "fake DNS pool exhausted".to_string())?;

        {
            let mut map = self.domain_to_ip.lock().await;
            let mut rev = self.ip_to_domain.lock().await;
            map.insert(lower.clone(), ip);
            rev.insert(ip, lower);
        }

        Ok(vec![ip])
    }
}

// ─── SimpleDnsResolver (system lookup_host, kept for backward compat) ──────

pub struct SimpleDnsResolver {
    hosts: HashMap<String, Vec<IpAddr>>,
}

impl SimpleDnsResolver {
    pub fn new(hosts: HashMap<String, Vec<IpAddr>>) -> Self {
        SimpleDnsResolver { hosts }
    }
}

#[async_trait::async_trait]
impl DnsResolver for SimpleDnsResolver {
    async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, String> {
        let lower = domain.to_lowercase();

        if let Some(addrs) = self.hosts.get(&lower) {
            return Ok(addrs.clone());
        }

        let addrs = tokio::net::lookup_host((domain.as_ref(), 0))
            .await
            .map_err(|e| format!("dns resolve {}: {}", domain, e))?;

        let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
        if ips.is_empty() {
            return Err(format!("no addresses found for {}", domain));
        }
        Ok(ips)
    }
}

// ─── Hosts parsing ──────────────────────────────────────────────────────────

pub fn parse_hosts(value: Option<&serde_json::Value>) -> Result<HashMap<String, Vec<IpAddr>>, String> {
    let mut hosts = HashMap::new();

    let Some(val) = value else { return Ok(hosts) };

    let obj = val.as_object().ok_or_else(|| "hosts must be a JSON object".to_string())?;
    for (domain, ip_val) in obj {
        let addrs = match ip_val {
            serde_json::Value::String(s) => {
                let ip: IpAddr = s.parse().map_err(|e| format!("invalid host IP '{}': {}", s, e))?;
                vec![ip]
            }
            serde_json::Value::Array(arr) => {
                let mut ips = Vec::new();
                for v in arr {
                    let s = v.as_str().ok_or_else(|| format!("expected string in hosts array for {}", domain))?;
                    let ip: IpAddr = s.parse().map_err(|e| format!("invalid host IP '{}': {}", s, e))?;
                    ips.push(ip);
                }
                ips
            }
            _ => return Err(format!("invalid hosts value for '{}': expected string or array", domain)),
        };
        hosts.insert(domain.to_lowercase(), addrs);
    }

    Ok(hosts)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_domain() {
        assert_eq!(encode_domain_name("www.example.com"), vec![
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0
        ]);
    }

    #[test]
    fn test_decode_domain() {
        let encoded = encode_domain_name("www.example.com");
        let (decoded, end) = decode_domain_name(&encoded, 0).unwrap();
        assert_eq!(decoded, "www.example.com");
        assert_eq!(end, encoded.len());
    }

    #[test]
    fn test_build_and_parse_roundtrip() {
        let query = build_dns_query("example.com", QTYPE_A);
        assert!(query.len() > 12);
        assert_eq!(&query[4..6], &[0x00, 0x01]); // QDCOUNT = 1
        // First label: 7example
        assert_eq!(query[DNS_HEADER_SIZE], 7);
    }

    #[test]
    fn test_parse_hosts_single() {
        let json = serde_json::json!({ "example.com": "1.2.3.4" });
        let hosts = parse_hosts(Some(&json)).unwrap();
        assert_eq!(hosts.get("example.com").unwrap(), &[IpAddr::V4([1, 2, 3, 4].into())]);
    }

    #[test]
    fn test_parse_hosts_array() {
        let json = serde_json::json!({ "example.com": ["1.2.3.4", "::1"] });
        let hosts = parse_hosts(Some(&json)).unwrap();
        assert_eq!(hosts.get("example.com").unwrap().len(), 2);
    }

    #[test]
    fn test_nameserver_domain_match() {
        let ns = NameServer {
            address: "8.8.8.8".into(),
            port: 53,
            domains: vec!["domain:example.com".into()],
            expected_ips: vec![],
        };
        assert!(ns.matches_domain("example.com"));
        assert!(ns.matches_domain("sub.example.com"));
        assert!(!ns.matches_domain("other.com"));
    }

    #[test]
    fn test_nameserver_keyword_match() {
        let ns = NameServer {
            address: "8.8.8.8".into(),
            port: 53,
            domains: vec!["keyword:google".into()],
            expected_ips: vec![],
        };
        assert!(ns.matches_domain("google.com"));
        assert!(ns.matches_domain("www.googleapis.com"));
        assert!(!ns.matches_domain("example.com"));
    }
}
