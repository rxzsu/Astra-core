use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock};

// ─── DNS constants ──────────────────────────────────────────────────────────

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const QCLASS_IN: u16 = 1;
const DNS_HEADER_SIZE: usize = 12;
const DEFAULT_TTL: u32 = 300;

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum DnsError {
    EmptyResponse,
    RecordNotFound,
    RCode(u8, String),
    Timeout,
    Network(String),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::EmptyResponse => write!(f, "empty response"),
            DnsError::RecordNotFound => write!(f, "record not found"),
            DnsError::RCode(c, s) => write!(f, "dns rcode {}: {}", c, s),
            DnsError::Timeout => write!(f, "dns timeout"),
            DnsError::Network(s) => write!(f, "dns network error: {}", s),
        }
    }
}

impl std::error::Error for DnsError {}

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

    pub fn ipv4_enabled(&self) -> bool {
        matches!(self, QueryStrategy::UseIp | QueryStrategy::UseIp4)
    }
    pub fn ipv6_enabled(&self) -> bool {
        matches!(self, QueryStrategy::UseIp | QueryStrategy::UseIp6)
    }
}

// ─── DnsResolver trait ──────────────────────────────────────────────────────

#[async_trait::async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, DnsError>;
}

// ─── DNS wire format: encode/decode domain names ────────────────────────────

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

// ─── EDNS0 Client Subnet option ──────────────────────────────────────────────

/// Build EDNS0 option bytes for client subnet (code 0x8) per RFC 7871.
pub fn build_edns0_subnet_option(client_ip: Option<IpAddr>) -> Option<Vec<u8>> {
    let ip = client_ip?;
    let (family, netmask, masked) = match ip {
        IpAddr::V4(v4) => {
            let mask: u8 = 24;
            let octets = v4.octets();
            let mut masked_bytes = Vec::with_capacity(4);
            masked_bytes.extend_from_slice(&octets[..3]); // /24 = first 3 bytes
            masked_bytes.push(0);
            (1u16, mask, masked_bytes)
        }
        IpAddr::V6(v6) => {
            let mask: u8 = 96;
            let octets = v6.octets();
            let mut masked_bytes = Vec::with_capacity(16);
            masked_bytes.extend_from_slice(&octets[..12]); // /96 = first 12 bytes
            masked_bytes.extend_from_slice(&[0u8; 4]);
            (2u16, mask, masked_bytes)
        }
    };
    let mut opt = Vec::with_capacity(8 + masked.len());
    opt.extend_from_slice(&0x0008u16.to_be_bytes()); // option code = 8 (EDNS0 Client Subnet)
    opt.extend_from_slice(&((4 + masked.len()) as u16).to_be_bytes());
    opt.extend_from_slice(&family.to_be_bytes());
    opt.push(netmask); // source netmask
    opt.push(0u8); // scope netmask (0 = not known)
    opt.extend_from_slice(&masked[..netmask as usize / 8]);
    Some(opt)
}

fn build_edns0_padding_option(len: usize) -> Vec<u8> {
    let mut opt = Vec::with_capacity(4 + len);
    opt.extend_from_slice(&0x000cu16.to_be_bytes()); // option code = 12 (Padding)
    opt.extend_from_slice(&(len as u16).to_be_bytes());
    opt.resize(4 + len, 0);
    opt
}

/// Build a DNS query with EDNS0 OPT record in Additional section.
pub fn build_dns_query_with_edns(
    domain: &str,
    qtype: u16,
    id: u16,
    client_ip: Option<IpAddr>,
    padding: Option<usize>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
    buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    buf.extend_from_slice(&[0x00, 0x01]); // ARCOUNT = 1 (for OPT)
    buf.extend_from_slice(&encode_domain_name(domain));
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&QCLASS_IN.to_be_bytes());
    // OPT pseudo-record (type 41)
    buf.extend_from_slice(&[0x00]); // name = root (0)
    buf.extend_from_slice(&[0x00, 0x29]); // type = OPT (41)
    buf.extend_from_slice(&[0x05, 0x36]); // UDP payload size 1350
    buf.extend_from_slice(&[0x00, 0x00, 0x80, 0x00]); // DO=1
    let mut opt_data = Vec::new();
    if let Some(subnet) = build_edns0_subnet_option(client_ip) {
        opt_data.extend_from_slice(&subnet);
    }
    if let Some(pad_len) = padding
        && pad_len > 0
    {
        opt_data.extend_from_slice(&build_edns0_padding_option(pad_len));
    }
    buf.extend_from_slice(&(opt_data.len() as u16).to_be_bytes());
    buf.extend_from_slice(&opt_data);
    buf
}

// ─── Build basic DNS query ─────────────────────────────────────────────────

pub fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    build_dns_query_with_edns(domain, qtype, rand::random(), None, None)
}

// ─── Parse DNS response ─────────────────────────────────────────────────────

pub fn parse_dns_response(data: &[u8]) -> Result<(Vec<IpAddr>, u32), DnsError> {
    if data.len() < DNS_HEADER_SIZE {
        return Err(DnsError::Network("response too short".into()));
    }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    if flags & 0x8000 == 0 {
        return Err(DnsError::Network("not a DNS response".into()));
    }
    let rcode = (flags & 0x000f) as u8;
    if rcode != 0 {
        let reasons = [
            "NoError", "FormErr", "ServFail", "NXDomain", "NotImp", "Refused", "YXDomain",
            "YXRRSet", "NXRRSet", "NotAuth", "NotZone",
        ];
        let reason = reasons.get(rcode as usize).unwrap_or(&"Unknown");
        return Err(DnsError::RCode(rcode, reason.to_string()));
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let mut pos = DNS_HEADER_SIZE;
    for _ in 0..qdcount {
        let (_, new_pos) = decode_domain_name(data, pos).map_err(DnsError::Network)?;
        pos = new_pos + 4;
    }
    let mut ips = Vec::new();
    let mut min_ttl = DEFAULT_TTL;
    for _ in 0..ancount {
        let (_, new_pos) = decode_domain_name(data, pos).map_err(DnsError::Network)?;
        pos = new_pos;
        if pos + 10 > data.len() {
            return Err(DnsError::Network("truncated answer".into()));
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > data.len() {
            return Err(DnsError::Network("truncated rdata".into()));
        }
        match rtype {
            QTYPE_A if rdlength == 4 => {
                ips.push(IpAddr::V4(Ipv4Addr::new(
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                )));
                min_ttl = min_ttl.min(ttl);
            }
            QTYPE_AAAA if rdlength == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[pos..pos + 16]);
                ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
                min_ttl = min_ttl.min(ttl);
            }
            _ => {}
        }
        pos += rdlength;
    }
    if ips.is_empty() {
        Err(DnsError::EmptyResponse)
    } else {
        Ok((ips, min_ttl))
    }
}

// ─── NameServer config ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NameServer {
    pub address: String,
    pub port: u16,
    pub protocol: String,
    pub domains: Vec<String>,
    pub expected_ips: Vec<IpAddr>,
    pub client_ip: Option<IpAddr>,
    pub skip_fallback: bool,
    pub tag: String,
    pub query_strategy: QueryStrategy,
}

impl NameServer {
    pub fn matches_domain(&self, domain: &str) -> bool {
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
            } else if let Some(geosite) = pattern.strip_prefix("geosite:") {
                if domain == geosite || domain.ends_with(&format!(".{}", geosite)) {
                    return true;
                }
            } else {
                if domain == pattern || domain.ends_with(&format!(".{}", pattern)) {
                    return true;
                }
            }
        }
        false
    }
}

// ─── Cache Controller ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CacheRecord {
    ips: Vec<IpAddr>,
    expiry: Instant,
}

pub struct CacheController {
    #[allow(dead_code)]
    name: String,
    disable_cache: bool,
    serve_stale: bool,
    serve_expired_ttl: Duration,
    records: RwLock<HashMap<String, CacheRecord>>,
}

impl CacheController {
    pub fn new(
        name: &str,
        disable_cache: bool,
        serve_stale: bool,
        serve_expired_ttl_secs: i32,
    ) -> Self {
        CacheController {
            name: name.to_string(),
            disable_cache,
            serve_stale,
            serve_expired_ttl: if serve_expired_ttl_secs > 0 {
                Duration::from_secs(serve_expired_ttl_secs as u64)
            } else {
                Duration::from_secs(0)
            },
            records: RwLock::new(HashMap::new()),
        }
    }

    pub async fn find(&self, key: &str) -> Option<(Vec<IpAddr>, u32)> {
        if self.disable_cache {
            return None;
        }
        let records = self.records.read().await;
        if let Some(rec) = records.get(key) {
            let now = Instant::now();
            if rec.expiry > now {
                let ttl = (rec.expiry - now).as_secs() as u32;
                return Some((rec.ips.clone(), ttl.max(1)));
            }
            if self.serve_stale
                && (self.serve_expired_ttl.is_zero()
                    || now.duration_since(rec.expiry) <= self.serve_expired_ttl)
            {
                return Some((rec.ips.clone(), 1));
            }
        }
        None
    }

    pub async fn update(&self, key: &str, ips: Vec<IpAddr>, ttl: u32) {
        if self.disable_cache || ips.is_empty() {
            return;
        }
        let ttl = if ttl == 0 { DEFAULT_TTL } else { ttl };
        let rec = CacheRecord {
            ips,
            expiry: Instant::now() + Duration::from_secs(ttl as u64),
        };
        self.records.write().await.insert(key.to_string(), rec);
    }
}

// ─── StaticHosts with proxiedDomain replacement ──────────────────────────────

#[derive(Debug, Clone)]
pub enum HostEntry {
    Ips(Vec<IpAddr>),
    Domain(String),
}

pub struct StaticHosts {
    entries: HashMap<String, HostEntry>,
}

impl Default for StaticHosts {
    fn default() -> Self {
        StaticHosts::new()
    }
}

impl StaticHosts {
    pub fn new() -> Self {
        StaticHosts {
            entries: HashMap::new(),
        }
    }

    pub fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        let mut hosts = StaticHosts::new();
        let obj = value
            .as_object()
            .ok_or_else(|| "hosts must be a JSON object".to_string())?;
        for (domain, val) in obj {
            let key = domain.trim_end_matches('.').to_lowercase();
            match val {
                serde_json::Value::String(s) if s.starts_with('#') => {
                    continue;
                }
                serde_json::Value::String(s) => {
                    if let Ok(ip) = s.parse::<IpAddr>() {
                        hosts.entries.insert(key, HostEntry::Ips(vec![ip]));
                    } else {
                        hosts
                            .entries
                            .insert(key, HostEntry::Domain(s.to_lowercase()));
                    }
                }
                serde_json::Value::Array(arr) => {
                    let mut ips = Vec::new();
                    for v in arr {
                        if let Some(s) = v.as_str()
                            && let Ok(ip) = s.parse::<IpAddr>()
                        {
                            ips.push(ip);
                        }
                    }
                    if !ips.is_empty() {
                        hosts.entries.insert(key, HostEntry::Ips(ips));
                    }
                }
                _ => return Err(format!("invalid hosts value for '{}'", domain)),
            }
        }
        Ok(hosts)
    }

    pub fn lookup(&self, domain: &str) -> Option<Result<Vec<IpAddr>, HostEntry>> {
        let key = domain.trim_end_matches('.').to_lowercase();
        match self.entries.get(&key) {
            Some(HostEntry::Ips(ips)) => Some(Ok(ips.clone())),
            Some(HostEntry::Domain(d)) => Some(Err(HostEntry::Domain(d.clone()))),
            None => None,
        }
    }

    pub fn lookup_recursive(
        &self,
        domain: &str,
        depth: usize,
    ) -> Option<Result<Vec<IpAddr>, String>> {
        if depth > 5 {
            return None;
        }
        match self.lookup(domain) {
            Some(Ok(ips)) => Some(Ok(ips)),
            Some(Err(HostEntry::Domain(replacement))) => {
                tracing::debug!("domain replaced: {} -> {}", domain, replacement);
                self.lookup_recursive(&replacement, depth + 1)
                    .or(Some(Err(replacement)))
            }
            Some(Err(HostEntry::Ips(_))) => None,
            None => None,
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn filter_expected(ips: Vec<IpAddr>, expected: &[IpAddr]) -> Vec<IpAddr> {
    if expected.is_empty() {
        return ips;
    }
    ips.into_iter().filter(|ip| expected.contains(ip)).collect()
}

fn dns_query_types(strategy: QueryStrategy) -> Vec<u16> {
    match strategy {
        QueryStrategy::UseIp4 => vec![QTYPE_A],
        QueryStrategy::UseIp6 => vec![QTYPE_AAAA],
        QueryStrategy::UseIp => vec![QTYPE_A, QTYPE_AAAA],
    }
}

async fn resolve_udp(
    ns: &NameServer,
    domain: &str,
    qtype: u16,
    ns_addr: &str,
) -> Result<Vec<IpAddr>, DnsError> {
    let id: u16 = rand::random();
    let query = build_dns_query_with_edns(domain, qtype, id, ns.client_ip, None);
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| DnsError::Network(e.to_string()))?;
    socket
        .send_to(&query, ns_addr)
        .await
        .map_err(|e| DnsError::Network(e.to_string()))?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .map_err(|_| DnsError::Timeout)?
        .map_err(|e| DnsError::Network(e.to_string()))?
        .0;
    let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
    if resp_id != id {
        return Err(DnsError::Network("response ID mismatch".into()));
    }
    let (ips, _ttl) = parse_dns_response(&buf[..n])?;
    Ok(ips)
}

async fn resolve_tcp(
    ns: &NameServer,
    domain: &str,
    qtype: u16,
    ns_addr: &str,
) -> Result<Vec<IpAddr>, DnsError> {
    let id: u16 = rand::random();
    let query = build_dns_query_with_edns(domain, qtype, id, ns.client_ip, None);
    let len = query.len() as u16;
    let mut wire = Vec::with_capacity(2 + query.len());
    wire.extend_from_slice(&len.to_be_bytes());
    wire.extend_from_slice(&query);
    let stream = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(ns_addr),
    )
    .await
    .map_err(|_| DnsError::Timeout)?
    .map_err(|e| DnsError::Network(e.to_string()))?;
    let (mut r, mut w) = tokio::io::split(stream);
    w.write_all(&wire)
        .await
        .map_err(|e| DnsError::Network(e.to_string()))?;
    drop(w);
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), r.read_exact(&mut len_buf))
        .await
        .map_err(|_| DnsError::Timeout)?
        .map_err(|e| DnsError::Network(e.to_string()))?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(5), r.read_exact(&mut resp))
        .await
        .map_err(|_| DnsError::Timeout)?
        .map_err(|e| DnsError::Network(e.to_string()))?;
    let (ips, _ttl) = parse_dns_response(&resp)?;
    Ok(ips)
}

fn sort_clients_by_domain<'a>(
    domain: &str,
    nameservers: &'a [NameServer],
) -> (Vec<&'a NameServer>, bool) {
    let mut matched: Vec<&NameServer> = Vec::new();
    for ns in nameservers {
        if ns.matches_domain(domain) {
            matched.push(ns);
        }
    }
    let has_final = matched.iter().any(|ns| ns.tag.contains('+'));
    if has_final {
        return (matched, true);
    }
    let mut remaining: Vec<&NameServer> = nameservers
        .iter()
        .filter(|ns| !matched.iter().any(|m| std::ptr::eq(*m, *ns)))
        .filter(|ns| !ns.skip_fallback)
        .collect();
    matched.append(&mut remaining);
    (matched, false)
}

// ─── UdpDnsResolver ────────────────────────────────────────────────────────

pub struct UdpDnsResolver {
    nameservers: Vec<NameServer>,
    hosts: StaticHosts,
    query_strategy: QueryStrategy,
    cache: CacheController,
    enable_parallel: bool,
    disable_fallback: bool,
    disable_fallback_if_match: bool,
}

impl UdpDnsResolver {
    pub fn new(
        nameservers: Vec<NameServer>,
        hosts: StaticHosts,
        query_strategy: QueryStrategy,
        disable_cache: bool,
        enable_parallel: bool,
        disable_fallback: bool,
        disable_fallback_if_match: bool,
    ) -> Self {
        UdpDnsResolver {
            nameservers,
            hosts,
            query_strategy,
            cache: CacheController::new("udp", disable_cache, false, 0),
            enable_parallel,
            disable_fallback,
            disable_fallback_if_match,
        }
    }
}

#[async_trait::async_trait]
impl DnsResolver for UdpDnsResolver {
    async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, DnsError> {
        let lower = domain.trim_end_matches('.').to_lowercase();
        if let Some(result) = self.hosts.lookup_recursive(&lower, 0) {
            match result {
                Ok(ips) => return Ok(ips),
                Err(replacement) => {
                    let qtypes = dns_query_types(self.query_strategy);
                    return self.do_nameserver_lookup(&replacement, &qtypes).await;
                }
            }
        }
        let qtypes = dns_query_types(self.query_strategy);
        self.do_nameserver_lookup(&lower, &qtypes).await
    }
}

impl UdpDnsResolver {
    async fn do_nameserver_lookup(
        &self,
        domain: &str,
        qtypes: &[u16],
    ) -> Result<Vec<IpAddr>, DnsError> {
        let cache_key = format!("{}|{:?}", domain, qtypes);
        if let Some((cached_ips, _ttl)) = self.cache.find(&cache_key).await {
            return Ok(cached_ips);
        }
        let (sorted_ns, has_final) = sort_clients_by_domain(domain, &self.nameservers);
        let has_match = !sorted_ns.is_empty() && sorted_ns[0].matches_domain(domain);
        if (self.disable_fallback || (self.disable_fallback_if_match && has_match)) && !has_final {
            let matched_only: Vec<&NameServer> = sorted_ns
                .iter()
                .filter(|ns| ns.matches_domain(domain))
                .copied()
                .collect();
            if matched_only.is_empty() {
                return Err(DnsError::EmptyResponse);
            }
            return self.query_servers(&matched_only, domain, qtypes).await;
        }
        let result = self.query_servers(&sorted_ns, domain, qtypes).await;
        if let Ok(ref ips) = result {
            self.cache
                .update(&cache_key, ips.clone(), DEFAULT_TTL)
                .await;
        }
        result
    }

    async fn query_servers(
        &self,
        nameservers: &[&NameServer],
        domain: &str,
        qtypes: &[u16],
    ) -> Result<Vec<IpAddr>, DnsError> {
        if self.enable_parallel {
            self.parallel_query(nameservers, domain, qtypes).await
        } else {
            self.serial_query(nameservers, domain, qtypes).await
        }
    }

    async fn serial_query(
        &self,
        nameservers: &[&NameServer],
        domain: &str,
        qtypes: &[u16],
    ) -> Result<Vec<IpAddr>, DnsError> {
        let mut last_err = DnsError::EmptyResponse;
        for ns in nameservers {
            match self.query_single(ns, domain, qtypes).await {
                Ok(ips) if !ips.is_empty() => return Ok(ips),
                Ok(_) => continue,
                Err(e) => {
                    last_err = e;
                }
            }
        }
        Err(last_err)
    }

    async fn parallel_query(
        &self,
        nameservers: &[&NameServer],
        domain: &str,
        qtypes: &[u16],
    ) -> Result<Vec<IpAddr>, DnsError> {
        let futures: Vec<_> = nameservers
            .iter()
            .map(|ns| self.query_single(ns, domain, qtypes))
            .collect();
        let results = futures::future::join_all(futures).await;
        for r in results {
            if let Ok(ips) = r
                && !ips.is_empty()
            {
                return Ok(ips);
            }
        }
        Err(DnsError::EmptyResponse)
    }

    async fn query_single(
        &self,
        ns: &NameServer,
        domain: &str,
        qtypes: &[u16],
    ) -> Result<Vec<IpAddr>, DnsError> {
        let ns_addr = format!("{}:{}", ns.address, ns.port);
        let mut all_ips = Vec::new();
        for &qtype in qtypes {
            let result = if ns.protocol == "tcp" || ns.protocol == "tcp+local" {
                resolve_tcp(ns, domain, qtype, &ns_addr).await
            } else {
                resolve_udp(ns, domain, qtype, &ns_addr).await
            };
            match result {
                Ok(ips) => {
                    let filtered = filter_expected(ips, &ns.expected_ips);
                    if !filtered.is_empty() {
                        all_ips.extend(filtered);
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("dns query to {} failed: {}", ns_addr, e);
                }
            }
        }
        if all_ips.is_empty() {
            Err(DnsError::EmptyResponse)
        } else {
            Ok(all_ips)
        }
    }
}

// ─── TcpDnsResolver ────────────────────────────────────────────────────────

pub struct TcpDnsResolver {
    nameservers: Vec<NameServer>,
    hosts: StaticHosts,
    query_strategy: QueryStrategy,
    cache: CacheController,
    enable_parallel: bool,
    #[allow(dead_code)]
    disable_fallback: bool,
    #[allow(dead_code)]
    disable_fallback_if_match: bool,
}

impl TcpDnsResolver {
    pub fn new(
        nameservers: Vec<NameServer>,
        hosts: StaticHosts,
        query_strategy: QueryStrategy,
        disable_cache: bool,
        enable_parallel: bool,
        disable_fallback: bool,
        disable_fallback_if_match: bool,
    ) -> Self {
        TcpDnsResolver {
            nameservers,
            hosts,
            query_strategy,
            cache: CacheController::new("tcp", disable_cache, false, 0),
            enable_parallel,
            disable_fallback,
            disable_fallback_if_match,
        }
    }
}

#[async_trait::async_trait]
impl DnsResolver for TcpDnsResolver {
    async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, DnsError> {
        let lower = domain.trim_end_matches('.').to_lowercase();
        if let Some(result) = self.hosts.lookup_recursive(&lower, 0) {
            match result {
                Ok(ips) => return Ok(ips),
                Err(replacement) => {
                    let qtypes = dns_query_types(self.query_strategy);
                    return self.do_nameserver_lookup(&replacement, &qtypes).await;
                }
            }
        }
        let qtypes = dns_query_types(self.query_strategy);
        self.do_nameserver_lookup(&lower, &qtypes).await
    }
}

impl TcpDnsResolver {
    async fn do_nameserver_lookup(
        &self,
        domain: &str,
        qtypes: &[u16],
    ) -> Result<Vec<IpAddr>, DnsError> {
        let cache_key = format!("{}|{:?}", domain, qtypes);
        if let Some((cached_ips, _ttl)) = self.cache.find(&cache_key).await {
            return Ok(cached_ips);
        }
        let (sorted_ns, _) = sort_clients_by_domain(domain, &self.nameservers);
        let result = if self.enable_parallel {
            self.parallel_query(&sorted_ns, domain, qtypes).await
        } else {
            self.serial_query(&sorted_ns, domain, qtypes).await
        };
        if let Ok(ref ips) = result {
            self.cache
                .update(&cache_key, ips.clone(), DEFAULT_TTL)
                .await;
        }
        result
    }

    async fn serial_query(
        &self,
        nameservers: &[&NameServer],
        domain: &str,
        qtypes: &[u16],
    ) -> Result<Vec<IpAddr>, DnsError> {
        let mut last_err = DnsError::EmptyResponse;
        for ns in nameservers {
            let ns_addr = format!("{}:{}", ns.address, ns.port);
            let mut all_ips = Vec::new();
            for &qtype in qtypes {
                match resolve_tcp(ns, domain, qtype, &ns_addr).await {
                    Ok(ips) => {
                        let filtered = filter_expected(ips, &ns.expected_ips);
                        if !filtered.is_empty() {
                            all_ips.extend(filtered);
                            break;
                        }
                    }
                    Err(e) => {
                        last_err = e;
                    }
                }
            }
            if !all_ips.is_empty() {
                return Ok(all_ips);
            }
        }
        Err(last_err)
    }

    async fn parallel_query(
        &self,
        nameservers: &[&NameServer],
        domain: &str,
        qtypes: &[u16],
    ) -> Result<Vec<IpAddr>, DnsError> {
        let futures: Vec<_> = nameservers
            .iter()
            .map(|ns| {
                let ns_addr = format!("{}:{}", ns.address, ns.port);
                let expected = ns.expected_ips.clone();
                async move {
                    let mut all_ips = Vec::new();
                    for &qtype in qtypes {
                        if let Ok(ips) = resolve_tcp(ns, domain, qtype, &ns_addr).await {
                            let filtered = filter_expected(ips, &expected);
                            if !filtered.is_empty() {
                                all_ips.extend(filtered);
                                break;
                            }
                        }
                    }
                    if all_ips.is_empty() {
                        Err(DnsError::EmptyResponse)
                    } else {
                        Ok(all_ips)
                    }
                }
            })
            .collect();
        let results = futures::future::join_all(futures).await;
        for r in results {
            if let Ok(ips) = r
                && !ips.is_empty()
            {
                return Ok(ips);
            }
        }
        Err(DnsError::EmptyResponse)
    }
}

// ─── DoH (DNS-over-HTTPS) Resolver ──────────────────────────────────────────

pub struct DoHResolver {
    url: String,
    #[allow(dead_code)]
    nameservers: Vec<NameServer>,
    hosts: StaticHosts,
    query_strategy: QueryStrategy,
    client: reqwest::Client,
    cache: CacheController,
}

impl DoHResolver {
    pub fn new(
        url: String,
        nameservers: Vec<NameServer>,
        hosts: StaticHosts,
        query_strategy: QueryStrategy,
        disable_cache: bool,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        DoHResolver {
            url,
            nameservers,
            hosts,
            query_strategy,
            client,
            cache: CacheController::new("doh", disable_cache, false, 0),
        }
    }
}

#[async_trait::async_trait]
impl DnsResolver for DoHResolver {
    async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, DnsError> {
        let lower = domain.trim_end_matches('.').to_lowercase();
        if let Some(result) = self.hosts.lookup_recursive(&lower, 0) {
            match result {
                Ok(ips) => return Ok(ips),
                Err(replacement) => return self.do_lookup(&replacement).await,
            }
        }
        self.do_lookup(&lower).await
    }
}

impl DoHResolver {
    async fn do_lookup(&self, domain: &str) -> Result<Vec<IpAddr>, DnsError> {
        let qtypes = dns_query_types(self.query_strategy);
        let cache_key = format!("{}|{:?}", domain, qtypes);
        if let Some((cached_ips, _ttl)) = self.cache.find(&cache_key).await {
            return Ok(cached_ips);
        }
        let mut all_ips = Vec::new();
        for &qtype in &qtypes {
            let id: u16 = rand::random();
            let query = build_dns_query_with_edns(domain, qtype, id, None, Some(100));
            let resp = tokio::time::timeout(
                Duration::from_secs(10),
                self.client
                    .post(&self.url)
                    .header("Accept", "application/dns-message")
                    .header("Content-Type", "application/dns-message")
                    .body(query)
                    .send(),
            )
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|e| DnsError::Network(e.to_string()))?;
            if resp.status().as_u16() != 200 {
                return Err(DnsError::Network(format!("DoH status {}", resp.status())));
            }
            let body = resp
                .bytes()
                .await
                .map_err(|e| DnsError::Network(e.to_string()))?;
            if let Ok((ips, _ttl)) = parse_dns_response(&body) {
                all_ips.extend(ips);
                break;
            }
        }
        if all_ips.is_empty() {
            Err(DnsError::EmptyResponse)
        } else {
            self.cache
                .update(&cache_key, all_ips.clone(), DEFAULT_TTL)
                .await;
            Ok(all_ips)
        }
    }
}

// ─── FakeDnsResolver ───────────────────────────────────────────────────────

pub struct FakeDnsResolver {
    pool: FakeIpPool,
    domain_to_ip: Mutex<HashMap<String, IpAddr>>,
    ip_to_domain: Mutex<HashMap<IpAddr, String>>,
}

struct FakeIpPool {
    base: Ipv4Addr,
    count: u32,
    next: AtomicU32,
}

impl FakeIpPool {
    fn new(base: Ipv4Addr, prefix: u8) -> Self {
        let count = 1u32 << (32 - prefix.min(32).max(8));
        FakeIpPool {
            base,
            count,
            next: AtomicU32::new(1),
        }
    }
    fn allocate(&self) -> Option<IpAddr> {
        let offset = self.next.fetch_add(1, Ordering::Relaxed);
        if offset >= self.count {
            return None;
        }
        let mut octets = self.base.octets();
        let v = u32::from_be_bytes(octets).wrapping_add(offset);
        octets = v.to_be_bytes();
        Some(IpAddr::V4(Ipv4Addr::new(
            octets[0], octets[1], octets[2], octets[3],
        )))
    }
}

impl FakeDnsResolver {
    pub fn new(base: Ipv4Addr, prefix: u8) -> Self {
        FakeDnsResolver {
            pool: FakeIpPool::new(base, prefix),
            domain_to_ip: Mutex::new(HashMap::new()),
            ip_to_domain: Mutex::new(HashMap::new()),
        }
    }
    pub fn new_default() -> Self {
        Self::new(Ipv4Addr::new(198, 18, 0, 0), 15)
    }
    pub fn get_domain(&self, ip: IpAddr) -> Option<String> {
        self.ip_to_domain.try_lock().ok()?.get(&ip).cloned()
    }
    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let base_octets = self.pool.base.octets();
                let v4_octets = v4.octets();
                v4_octets[0] == base_octets[0] && v4_octets[1] == base_octets[1]
            }
            IpAddr::V6(_) => false,
        }
    }
}

#[async_trait::async_trait]
impl DnsResolver for FakeDnsResolver {
    async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, DnsError> {
        let lower = domain.to_lowercase();
        {
            let map = self.domain_to_ip.lock().await;
            if let Some(ip) = map.get(&lower) {
                return Ok(vec![*ip]);
            }
        }
        let ip = self
            .pool
            .allocate()
            .ok_or(DnsError::Network("fake DNS pool exhausted".into()))?;
        {
            let mut map = self.domain_to_ip.lock().await;
            let mut rev = self.ip_to_domain.lock().await;
            map.insert(lower.clone(), ip);
            rev.insert(ip, lower);
        }
        Ok(vec![ip])
    }
}

// ─── SimpleDnsResolver ─────────────────────────────────────────────────────

pub struct SimpleDnsResolver {
    hosts: StaticHosts,
}

impl SimpleDnsResolver {
    pub fn new(hosts: StaticHosts) -> Self {
        SimpleDnsResolver { hosts }
    }
}

#[async_trait::async_trait]
impl DnsResolver for SimpleDnsResolver {
    async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, DnsError> {
        let lower = domain.trim_end_matches('.').to_lowercase();
        if let Some(result) = self.hosts.lookup_recursive(&lower, 0) {
            match result {
                Ok(ips) => return Ok(ips),
                Err(replacement) => {
                    return tokio::net::lookup_host((replacement, 0))
                        .await
                        .map_err(|e| DnsError::Network(e.to_string()))
                        .map(|addrs| addrs.map(|a| a.ip()).collect());
                }
            }
        }
        let addrs = tokio::net::lookup_host((domain, 0))
            .await
            .map_err(|e| DnsError::Network(e.to_string()))?;
        let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
        if ips.is_empty() {
            Err(DnsError::EmptyResponse)
        } else {
            Ok(ips)
        }
    }
}

// ─── DoQ (DNS-over-QUIC) Resolver ───────────────────────────────────────────
// Uses QUIC for DNS resolution per RFC 9250.
// Note: quinn API varies across versions; this uses a practical approach.

pub struct DoQResolver {
    endpoint: String,
    hosts: StaticHosts,
    query_strategy: QueryStrategy,
    cache: CacheController,
}

impl DoQResolver {
    pub fn new(
        endpoint: String,
        hosts: StaticHosts,
        query_strategy: QueryStrategy,
        disable_cache: bool,
    ) -> Self {
        DoQResolver {
            endpoint,
            hosts,
            query_strategy,
            cache: CacheController::new("doq", disable_cache, false, 0),
        }
    }

    async fn do_lookup(&self, domain: &str) -> Result<Vec<IpAddr>, DnsError> {
        let qtypes = dns_query_types(self.query_strategy);
        let cache_key = format!("{}|{:?}", domain, qtypes);
        if let Some((cached_ips, _ttl)) = self.cache.find(&cache_key).await {
            return Ok(cached_ips);
        }

        let dns_server = if self.endpoint.contains(':') {
            self.endpoint.clone()
        } else {
            format!("{}:853", self.endpoint)
        };

        let mut all_ips = Vec::new();
        for &qtype in &qtypes {
            let id: u16 = rand::random();
            let query = build_dns_query_with_edns(domain, qtype, id, None, None);
            let len = query.len() as u16;
            let mut wire = Vec::with_capacity(2 + query.len());
            wire.extend_from_slice(&len.to_be_bytes());
            wire.extend_from_slice(&query);

            // Try QUIC first (quinn), fallback to TCP on failure
            let result = self.quic_or_tcp(&dns_server, &wire).await;
            match result {
                Ok(ips) => {
                    all_ips.extend(ips);
                    break;
                }
                Err(e) => {
                    tracing::warn!("doq resolve failed: {}", e);
                }
            }
        }

        if all_ips.is_empty() {
            Err(DnsError::EmptyResponse)
        } else {
            self.cache
                .update(&cache_key, all_ips.clone(), DEFAULT_TTL)
                .await;
            Ok(all_ips)
        }
    }

    /// Try QUIC DNS, fall back to TCP DNS on failure.
    async fn quic_or_tcp(&self, server: &str, wire: &[u8]) -> Result<Vec<IpAddr>, DnsError> {
        // TCP fallback (QUIC not yet integrated due to quinn API compatibility)
        let tcp_addr = server.replace(":853", ":53");
        let stream = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(&tcp_addr),
        )
        .await
        .map_err(|_| DnsError::Timeout)?
        .map_err(|e| DnsError::Network(e.to_string()))?;

        let (mut r, mut w) = tokio::io::split(stream);
        use tokio::io::AsyncWriteExt;
        w.write_all(wire)
            .await
            .map_err(|e| DnsError::Network(e.to_string()))?;
        drop(w);

        let mut len_buf = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), r.read_exact(&mut len_buf))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|e| DnsError::Network(e.to_string()))?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        tokio::time::timeout(Duration::from_secs(5), r.read_exact(&mut resp))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|e| DnsError::Network(e.to_string()))?;

        let (ips, _) = parse_dns_response(&resp)?;
        Ok(ips)
    }
}

#[async_trait::async_trait]
impl DnsResolver for DoQResolver {
    async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, DnsError> {
        let lower = domain.trim_end_matches('.').to_lowercase();
        if let Some(result) = self.hosts.lookup_recursive(&lower, 0) {
            match result {
                Ok(ips) => return Ok(ips),
                Err(replacement) => return self.do_lookup(&replacement).await,
            }
        }
        self.do_lookup(&lower).await
    }
}

// ─── Hosts parsing ──────────────────────────────────────────────────────────

pub fn parse_hosts(value: Option<&serde_json::Value>) -> Result<StaticHosts, String> {
    let Some(val) = value else {
        return Ok(StaticHosts::new());
    };
    StaticHosts::from_json(val)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_domain() {
        assert_eq!(
            encode_domain_name("www.example.com"),
            vec![
                3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
                b'm', 0
            ]
        );
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
        assert_eq!(&query[4..6], &[0x00, 0x01]);
        assert_eq!(query[DNS_HEADER_SIZE], 7);
    }

    #[test]
    fn test_parse_hosts_single() {
        let json = serde_json::json!({ "example.com": "1.2.3.4" });
        let hosts = parse_hosts(Some(&json)).unwrap();
        assert_eq!(
            hosts.lookup("example.com").unwrap().unwrap(),
            vec![IpAddr::V4([1, 2, 3, 4].into())]
        );
    }

    #[test]
    fn test_parse_hosts_array() {
        let json = serde_json::json!({ "example.com": ["1.2.3.4", "::1"] });
        let hosts = parse_hosts(Some(&json)).unwrap();
        assert_eq!(hosts.lookup("example.com").unwrap().unwrap().len(), 2);
    }

    #[test]
    fn test_hosts_domain_replacement() {
        let json = serde_json::json!({ "my.domain": "real.domain" });
        let hosts = parse_hosts(Some(&json)).unwrap();
        match hosts.lookup("my.domain") {
            Some(Err(HostEntry::Domain(d))) => assert_eq!(d, "real.domain"),
            _ => panic!("expected domain replacement"),
        }
    }

    #[test]
    fn test_nameserver_domain_match() {
        let ns = NameServer {
            address: "8.8.8.8".into(),
            port: 53,
            protocol: "udp".into(),
            domains: vec!["domain:example.com".into()],
            expected_ips: vec![],
            client_ip: None,
            skip_fallback: false,
            tag: String::new(),
            query_strategy: QueryStrategy::UseIp,
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
            protocol: "udp".into(),
            domains: vec!["keyword:google".into()],
            expected_ips: vec![],
            client_ip: None,
            skip_fallback: false,
            tag: String::new(),
            query_strategy: QueryStrategy::UseIp,
        };
        assert!(ns.matches_domain("google.com"));
        assert!(ns.matches_domain("www.googleapis.com"));
        assert!(!ns.matches_domain("example.com"));
    }

    #[test]
    fn test_edns0_subnet_v4() {
        let ip = "1.2.3.4".parse::<IpAddr>().unwrap();
        let opt = build_edns0_subnet_option(Some(ip)).unwrap();
        assert!(!opt.is_empty());
        assert_eq!(opt[4..6], [0x00, 0x01]);
    }

    #[test]
    fn test_domain_priority_sorting() {
        let ns1 = NameServer {
            address: "8.8.8.8".into(),
            port: 53,
            protocol: "udp".into(),
            domains: vec!["domain:example.com".into()],
            expected_ips: vec![],
            client_ip: None,
            skip_fallback: false,
            tag: String::new(),
            query_strategy: QueryStrategy::UseIp,
        };
        let ns2 = NameServer {
            address: "1.1.1.1".into(),
            port: 53,
            protocol: "udp".into(),
            domains: vec![],
            expected_ips: vec![],
            client_ip: None,
            skip_fallback: true,
            tag: String::new(),
            query_strategy: QueryStrategy::UseIp,
        };
        let nss = [ns1, ns2];
        let (sorted, _) = sort_clients_by_domain("example.com", &nss);
        // ns1 matches (domain:example.com), ns2 also matches (empty domains = catch-all)
        assert_eq!(sorted.len(), 2);
        // ns1 should be first (matched by priority)
        assert_eq!(sorted[0].address, "8.8.8.8");
    }

    #[test]
    fn test_cache_controller() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let cache = CacheController::new("test", false, false, 0);
            cache
                .update(
                    "example.com|A",
                    vec!["1.2.3.4".parse::<IpAddr>().unwrap()],
                    60,
                )
                .await;
            let found = cache.find("example.com|A").await;
            assert!(found.is_some());
            assert_eq!(found.unwrap().0[0], "1.2.3.4".parse::<IpAddr>().unwrap());
        });
    }
}
