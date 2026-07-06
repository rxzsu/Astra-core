use std::collections::HashMap;
use std::net::IpAddr;

/// DNS resolution strategy for routing decisions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QueryStrategy {
    UseIp,
    UseIp4,
    UseIp6,
}

/// Trait for asynchronous DNS resolution.
#[async_trait::async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, String>;
}

/// A simple DNS resolver using the system's `lookup_host`.
/// Supports static hosts entries.
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

/// Parse static hosts from serde_json::Value.
/// Expected format: { "domain.com": "1.2.3.4" } or { "domain.com": ["1.2.3.4", "::1"] }
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
