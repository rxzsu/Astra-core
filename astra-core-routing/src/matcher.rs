use std::net::IpAddr;

use ipnetwork::IpNetwork;

use crate::context::RoutingContext;

pub trait Matcher: Send + Sync {
    fn matches(&self, ctx: &RoutingContext) -> bool;
}

pub struct DomainMatcher {
    patterns: Vec<DomainPattern>,
}

enum DomainPattern {
    Exact(String),
    Subdomain(String),
    Keyword(String),
    Regex(regex::Regex),
}

impl DomainMatcher {
    pub fn new(domains: &[String]) -> Self {
        let patterns = domains.iter().map(|d| {
            if let Some(keyword) = d.strip_prefix("keyword:") {
                DomainPattern::Keyword(keyword.to_lowercase())
            } else if let Some(re_str) = d.strip_prefix("regexp:") {
                DomainPattern::Regex(regex::Regex::new(re_str).unwrap_or_else(|_| regex::Regex::new("").unwrap()))
            } else if let Some(plain) = d.strip_prefix("domain:") {
                if plain.starts_with('.') {
                    DomainPattern::Subdomain(plain.to_lowercase())
                } else {
                    DomainPattern::Exact(plain.to_lowercase())
                }
            } else if d.starts_with('.') {
                DomainPattern::Subdomain(d.to_lowercase())
            } else {
                DomainPattern::Exact(d.to_lowercase())
            }
        }).collect();
        DomainMatcher { patterns }
    }
}

impl Matcher for DomainMatcher {
    fn matches(&self, ctx: &RoutingContext) -> bool {
        let domain = match &ctx.target_domain {
            Some(d) => d,
            None => return false,
        };
        let domain = domain.to_lowercase();

        for p in &self.patterns {
            match p {
                DomainPattern::Exact(d) => {
                    if &domain == d || format!("{}.", domain) == *d || domain == d.trim_end_matches('.') {
                        return true;
                    }
                }
                DomainPattern::Subdomain(s) => {
                    let s = s.trim_start_matches('.');
                    if domain == s || domain.ends_with(&format!(".{}", s)) {
                        return true;
                    }
                }
                DomainPattern::Keyword(k) => {
                    if domain.contains(k.as_str()) {
                        return true;
                    }
                }
                DomainPattern::Regex(re) => {
                    if re.is_match(&domain) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

pub struct IpMatcher {
    networks: Vec<IpNetwork>,
}

impl IpMatcher {
    pub fn new(ips: &[String]) -> Result<Self, String> {
        let networks: Vec<IpNetwork> = ips.iter()
            .map(|s| {
                if s.contains('/') {
                    s.parse::<IpNetwork>().map_err(|e| format!("invalid CIDR {}: {}", s, e))
                } else {
                    let ip: IpAddr = s.parse().map_err(|e| format!("invalid IP {}: {}", s, e))?;
                    Ok(IpNetwork::from(ip))
                }
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(IpMatcher { networks })
    }
}

impl Matcher for IpMatcher {
    fn matches(&self, ctx: &RoutingContext) -> bool {
        let ip = match &ctx.target_ip {
            Some(ip) => ip,
            None => return false,
        };
        self.networks.iter().any(|n| n.contains(*ip))
    }
}

pub struct PortMatcher {
    ports: Vec<(u16, u16)>,
}

impl PortMatcher {
    pub fn new(ranges: &[(u16, u16)]) -> Self {
        PortMatcher { ports: ranges.to_vec() }
    }
}

impl Matcher for PortMatcher {
    fn matches(&self, ctx: &RoutingContext) -> bool {
        self.ports.iter().any(|(from, to)| ctx.target_port >= *from && ctx.target_port <= *to)
    }
}

pub struct NetworkMatcher {
    networks: Vec<String>,
}

impl NetworkMatcher {
    pub fn new(networks: &[String]) -> Self {
        NetworkMatcher { networks: networks.to_vec() }
    }
}

impl Matcher for NetworkMatcher {
    fn matches(&self, ctx: &RoutingContext) -> bool {
        self.networks.iter().any(|n| n == &ctx.network)
    }
}

pub struct InboundTagMatcher {
    tags: Vec<String>,
}

impl InboundTagMatcher {
    pub fn new(tags: &[String]) -> Self {
        InboundTagMatcher { tags: tags.to_vec() }
    }
}

impl Matcher for InboundTagMatcher {
    fn matches(&self, ctx: &RoutingContext) -> bool {
        self.tags.iter().any(|t| t == &ctx.inbound_tag)
    }
}

pub struct ProtocolMatcher {
    protocols: Vec<String>,
}

impl ProtocolMatcher {
    pub fn new(protocols: &[String]) -> Self {
        ProtocolMatcher { protocols: protocols.to_vec() }
    }
}

impl Matcher for ProtocolMatcher {
    fn matches(&self, ctx: &RoutingContext) -> bool {
        match &ctx.protocol {
            Some(p) => self.protocols.iter().any(|proto| p.contains(proto.as_str())),
            None => false,
        }
    }
}

pub struct SourceIpMatcher {
    networks: Vec<IpNetwork>,
}

impl SourceIpMatcher {
    pub fn new(ips: &[String]) -> Result<Self, String> {
        let networks: Vec<IpNetwork> = ips.iter()
            .map(|s| {
                if s.contains('/') {
                    s.parse::<IpNetwork>().map_err(|e| format!("invalid CIDR {}: {}", s, e))
                } else {
                    let ip: IpAddr = s.parse().map_err(|e| format!("invalid IP {}: {}", s, e))?;
                    Ok(IpNetwork::from(ip))
                }
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(SourceIpMatcher { networks })
    }
}

impl Matcher for SourceIpMatcher {
    fn matches(&self, ctx: &RoutingContext) -> bool {
        let ip = match &ctx.source_ip {
            Some(ip) => ip,
            None => return false,
        };
        self.networks.iter().any(|n| n.contains(*ip))
    }
}

pub struct SourcePortMatcher {
    ports: Vec<(u16, u16)>,
}

impl SourcePortMatcher {
    pub fn new(ranges: &[(u16, u16)]) -> Self {
        SourcePortMatcher { ports: ranges.to_vec() }
    }
}

impl Matcher for SourcePortMatcher {
    fn matches(&self, ctx: &RoutingContext) -> bool {
        self.ports.iter().any(|(from, to)| ctx.source_port >= *from && ctx.source_port <= *to)
    }
}

pub struct UserMatcher {
    emails: Vec<String>,
}

impl UserMatcher {
    pub fn new(emails: &[String]) -> Self {
        UserMatcher { emails: emails.to_vec() }
    }
}

impl Matcher for UserMatcher {
    fn matches(&self, ctx: &RoutingContext) -> bool {
        match &ctx.user {
            Some(u) => self.emails.iter().any(|e| e == u),
            None => false,
        }
    }
}

// ─── ProcessNameMatcher (Go: app/router/condition.go ProcessNameMatcher) ─────

pub struct ProcessNameMatcher {
    process_names: Vec<String>,
    abs_paths: Vec<String>,
    folders: Vec<String>,
    match_self: bool,
}

impl ProcessNameMatcher {
    pub fn new(names: &[String]) -> Self {
        let mut process_names = Vec::new();
        let mut abs_paths = Vec::new();
        let mut folders = Vec::new();
        let mut match_self = false;

        for name in names {
            if name == "self/" {
                match_self = true;
                continue;
            }
            let name = name.replace('\\', "/");
            if name.ends_with('/') {
                folders.push(name);
            } else if name.contains('/') {
                abs_paths.push(name);
            } else {
                process_names.push(name.trim_end_matches(".exe").to_string());
            }
        }

        ProcessNameMatcher { process_names, abs_paths, folders, match_self }
    }
}

impl Matcher for ProcessNameMatcher {
    fn matches(&self, ctx: &RoutingContext) -> bool {
        // In Rust, process lookup is platform-specific and complex.
        // This is a simplified implementation that checks the attributes hashmap
        // which can be populated by the dispatcher with process info.
        let process_name = match ctx.attributes.get("process_name") {
            Some(n) => n,
            None => return false,
        };

        if self.match_self {
            // No os.Getpid() equivalent readily available in a cross-platform way
            // Assume "self" doesn't match by default
        }

        if self.process_names.iter().any(|n| n == process_name) {
            return true;
        }
        if self.abs_paths.iter().any(|p| p == process_name) {
            return true;
        }
        if self.folders.iter().any(|f| process_name.starts_with(f)) {
            return true;
        }
        false
    }
}

// ─── AttributeMatcher (Go: app/router/condition.go AttributeMatcher) ────────

pub struct AttributeMatcher {
    patterns: Vec<(String, regex::Regex)>,
}

impl AttributeMatcher {
    pub fn new(attrs: &std::collections::HashMap<String, String>) -> Self {
        let patterns = attrs.iter()
            .map(|(key, value)| {
                let pattern = regex::Regex::new(value).unwrap_or_else(|_| regex::Regex::new("").unwrap());
                (key.to_lowercase(), pattern)
            })
            .collect();
        AttributeMatcher { patterns }
    }
}

impl Matcher for AttributeMatcher {
    fn matches(&self, ctx: &RoutingContext) -> bool {
        for (key, regex) in &self.patterns {
            match ctx.attributes.get(key) {
                Some(value) => {
                    if !regex.is_match(value) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }
}
