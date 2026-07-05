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
            } else if d == "geosite:google" || d.starts_with("geosite:") {
                // Simplified: treat geosite as exact domain match
                DomainPattern::Keyword(d.to_lowercase())
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
                    if &domain == d || format!("{}.", &domain) == *d || domain == d.trim_end_matches('.') {
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
