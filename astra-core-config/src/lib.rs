pub mod dns;
pub mod json_reader;
pub mod log;
pub mod policy;
pub mod protobuf;
pub mod proxy;
pub mod router;
pub mod transport;
pub mod types;

use std::io::Read;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Root Xray config, mirrors Go `infra/conf.Config`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    #[serde(default)]
    pub log: Option<log::LogConfig>,
    #[serde(default)]
    pub routing: Option<router::RouterConfig>,
    #[serde(default)]
    pub dns: Option<dns::DNSConfig>,
    #[serde(default)]
    pub inbounds: Vec<InboundDetourConfig>,
    #[serde(default)]
    pub outbounds: Vec<OutboundDetourConfig>,
    #[serde(default)]
    pub policy: Option<policy::PolicyConfig>,
    #[serde(default)]
    pub api: Option<APIConfig>,
    #[serde(default)]
    pub stats: Option<Value>,
    #[serde(default)]
    pub reverse: Option<ReverseConfig>,
    #[serde(default)]
    pub observatory: Option<ObservatoryConfig>,
    #[serde(default, rename = "fakeDns")]
    pub fake_dns: Option<serde_json::Value>,
}

/// API config.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct APIConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tag: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub listen: String,
    #[serde(default)]
    pub services: Vec<String>,
}

/// Observatory config (health check).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ObservatoryConfig {
    #[serde(default)]
    pub selector: Vec<String>,
    #[serde(default = "default_probe_interval")]
    pub probe_interval: u32,
    #[serde(default)]
    pub probe_type: String,
    #[serde(default)]
    pub probe_url: Option<String>,
    #[serde(default)]
    pub enable: bool,
}

fn default_probe_interval() -> u32 {
    10
}

/// Reverse proxy config.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ReverseConfig {
    #[serde(default)]
    pub bridges: Vec<BridgeConfig>,
    #[serde(default)]
    pub portals: Vec<PortalConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BridgeConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tag: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PortalConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tag: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
}

// ─── Inbound Detour Config ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct InboundDetourConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<types::PortList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<types::Address>,
    #[serde(default)]
    pub settings: Option<Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tag: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_settings: Option<transport::StreamConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sniffing: Option<SniffingConfig>,
}

// ─── Outbound Detour Config ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OutboundDetourConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_through: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tag: String,
    #[serde(default)]
    pub settings: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_settings: Option<transport::StreamConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_settings: Option<ProxyConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mux: Option<MuxConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProxyConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tag: String,
    #[serde(default)]
    pub transport_layer: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MuxConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub concurrency: i16,
    #[serde(default)]
    pub xudp_concurrency: i16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub xudp_proxy_udp443: String,
}

// ─── Sniffing ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SniffingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub dest_override: types::StringList,
    #[serde(default)]
    pub metadata_only: bool,
    #[serde(default)]
    pub route_only: bool,
}

// ─── Config format auto-detection ─────────────────────────────────────────────

/// Detect config format from file extension.
pub fn detect_format(path: &str) -> &'static str {
    let lower = path.to_lowercase();
    if lower.ends_with(".yaml") || lower.ends_with(".yml") {
        "yaml"
    } else if lower.ends_with(".toml") {
        "toml"
    } else if lower.ends_with(".pb") || lower.ends_with(".protobuf") {
        "protobuf"
    } else {
        "json"
    }
}

/// Load config from a reader with format auto-detection (defaults to JSON).
pub fn load_config<R: Read>(reader: R, format: &str) -> Result<Config, String> {
    match format {
        "yaml" => Config::from_yaml_reader(reader),
        "toml" => Config::from_toml_reader(reader),
        _ => Config::from_json_reader(reader),
    }
}

// ─── Config Merge/Override ────────────────────────────────────────────────────

/// Merge a list of config sources into one by applying override rules.
/// First source is the base, subsequent sources override/append/prepend.
/// `filenames` are used to determine override behavior (e.g. "tail" in name => append outbounds).
pub fn merge_configs(configs: Vec<(Config, String)>) -> Config {
    let mut iter = configs.into_iter();
    let Some((mut base, _)) = iter.next() else {
        return Config::default();
    };
    for (override_cfg, filename) in iter {
        base.override_with(&override_cfg, &filename);
    }
    base
}

// ─── Helper: parse from JSON string ──────────────────────────────────────────

fn use_strict_json() -> bool {
    std::env::var("XRAY_JSON_STRICT").unwrap_or_default() == "true"
}

impl Config {
    /// Parse Xray config from a JSON string.
    /// If XRAY_JSON_STRICT=true, parsing is strict (no comments).
    pub fn from_json(json: &str) -> Result<Self, String> {
        if use_strict_json() {
            serde_json::from_str(json).map_err(|e| format!("config parse error: {}", e))
        } else {
            let mut stripped = String::new();
            json_reader::JsonCommentReader::new(json.as_bytes())
                .read_to_string(&mut stripped)
                .map_err(|e| format!("read config: {}", e))?;
            serde_json::from_str(&stripped).map_err(|e| format!("config parse error: {}", e))
        }
    }

    /// Parse Xray config from JSON bytes.
    pub fn from_slice(json: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(json).map_err(|e| format!("config parse error: {}", e))
    }

    /// Parse Xray config from a reader with JSON comment stripping.
    pub fn from_json_reader<R: Read>(reader: R) -> Result<Self, String> {
        let mut stripped = String::new();
        json_reader::JsonCommentReader::new(reader)
            .read_to_string(&mut stripped)
            .map_err(|e| format!("read config: {}", e))?;
        serde_json::from_str(&stripped).map_err(|e| format!("config parse error: {}", e))
    }

    /// Parse Xray config from a YAML string.

    /// Parse Xray config from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        let json_value: serde_json::Value =
            serde_yaml::from_str(yaml).map_err(|e| format!("yaml parse error: {}", e))?;
        serde_json::from_value(json_value)
            .map_err(|e| format!("config parse from yaml error: {}", e))
    }

    /// Parse Xray config from a YAML reader (with comment stripping).
    pub fn from_yaml_reader<R: Read>(reader: R) -> Result<Self, String> {
        let mut raw = String::new();
        json_reader::JsonCommentReader::new(reader)
            .read_to_string(&mut raw)
            .map_err(|e| format!("read yaml: {}", e))?;
        Self::from_yaml(&raw)
    }

    /// Parse Xray config from a TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, String> {
        let config_map: serde_json::Value =
            toml::from_str(toml_str).map_err(|e| format!("toml parse error: {}", e))?;
        serde_json::from_value(config_map)
            .map_err(|e| format!("config parse from toml error: {}", e))
    }

    /// Parse Xray config from a TOML reader.
    pub fn from_toml_reader<R: Read>(mut reader: R) -> Result<Self, String> {
        let mut raw = String::new();
        reader
            .read_to_string(&mut raw)
            .map_err(|e| format!("read toml: {}", e))?;
        Self::from_toml(&raw)
    }

    /// Override this config with another. Follows Go conventions:
    /// - Top-level scalars: replaced if non-None in override
    /// - Inbounds: matched by tag → replace; unmatched → append
    /// - Outbounds: matched by tag → replace; unmatched → prepend (unless filename has "tail" → append)
    pub fn override_with(&mut self, other: &Config, filename: &str) {
        if other.log.is_some() {
            self.log = other.log.clone();
        }
        if other.routing.is_some() {
            self.routing = other.routing.clone();
        }
        if other.dns.is_some() {
            self.dns = other.dns.clone();
        }
        if other.policy.is_some() {
            self.policy = other.policy.clone();
        }
        if other.api.is_some() {
            self.api = other.api.clone();
        }
        if other.stats.is_some() {
            self.stats = other.stats.clone();
        }
        if other.reverse.is_some() {
            self.reverse = other.reverse.clone();
        }
        if other.observatory.is_some() {
            self.observatory = other.observatory.clone();
        }
        if other.fake_dns.is_some() {
            self.fake_dns = other.fake_dns.clone();
        }

        // Inbounds: match by tag → replace; else append
        for ob in &other.inbounds {
            if let Some(idx) = self
                .inbounds
                .iter()
                .position(|x| x.tag == ob.tag && !ob.tag.is_empty())
            {
                self.inbounds[idx] = ob.clone();
            } else {
                self.inbounds.push(ob.clone());
            }
        }

        // Outbounds: match by tag → replace; else prepend (default) or append (if "tail" in filename)
        let is_tail = filename.to_lowercase().contains("tail");
        for ob in &other.outbounds {
            if let Some(idx) = self
                .outbounds
                .iter()
                .position(|x| x.tag == ob.tag && !ob.tag.is_empty())
            {
                self.outbounds[idx] = ob.clone();
            } else if is_tail {
                self.outbounds.push(ob.clone());
            } else {
                self.outbounds.insert(0, ob.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_config() {
        let json = r#"{
            "log": { "loglevel": "debug" },
            "inbounds": [{
                "protocol": "vless",
                "port": 443,
                "settings": {}
            }],
            "outbounds": [{
                "protocol": "freedom",
                "settings": {}
            }]
        }"#;
        let cfg = Config::from_json(json).unwrap();
        assert_eq!(cfg.log.unwrap().loglevel, "debug");
        assert_eq!(cfg.inbounds.len(), 1);
        assert_eq!(cfg.inbounds[0].protocol, "vless");
        assert_eq!(cfg.outbounds.len(), 1);
        assert_eq!(cfg.outbounds[0].protocol, "freedom");
    }

    #[test]
    fn test_vless_outbound_config() {
        let json = r#"{
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": "example.com",
                        "port": 443,
                        "users": [{"id": "uuid-here", "flow": "xtls-rprx-vision"}]
                    }]
                },
                "streamSettings": {
                    "network": "ws",
                    "wsSettings": {
                        "path": "/ws",
                        "host": "example.com"
                    }
                }
            }]
        }"#;
        let cfg = Config::from_json(json).unwrap();
        let ob = &cfg.outbounds[0];
        assert_eq!(ob.protocol, "vless");

        let settings = ob.settings.as_ref().unwrap();
        let vless: proxy::VLessOutboundConfig = serde_json::from_value(settings.clone()).unwrap();
        assert_eq!(vless.vnext.len(), 1);
        assert_eq!(vless.vnext[0].address.0, "example.com");
        assert_eq!(vless.vnext[0].port, 443);
        assert_eq!(vless.vnext[0].users[0].id, "uuid-here");

        let stream = ob.stream_settings.as_ref().unwrap();
        assert!(stream.network.is_ws());
        let ws = stream.ws_settings.as_ref().unwrap();
        assert_eq!(ws.path, "/ws");
        assert_eq!(ws.host, "example.com");
    }

    #[test]
    fn test_vmess_outbound_config() {
        let json = r#"{
            "outbounds": [{
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": "1.2.3.4",
                        "port": 12345,
                        "users": [{"id": "uuid-vmess", "security": "auto"}]
                    }]
                }
            }]
        }"#;
        let cfg = Config::from_json(json).unwrap();
        let settings = cfg.outbounds[0].settings.as_ref().unwrap();
        let vmess: proxy::VMessOutboundConfig = serde_json::from_value(settings.clone()).unwrap();
        assert_eq!(vmess.vnext[0].address.0, "1.2.3.4");
        assert_eq!(vmess.vnext[0].users[0].id, "uuid-vmess");
        assert_eq!(vmess.vnext[0].users[0].security, "auto");
    }

    #[test]
    fn test_dokodemo_inbound() {
        let json = r#"{
            "inbounds": [{
                "protocol": "dokodemo-door",
                "port": 1080,
                "settings": {
                    "network": "tcp,udp",
                    "followRedirect": true
                }
            }]
        }"#;
        let cfg = Config::from_json(json).unwrap();
        let settings = cfg.inbounds[0].settings.as_ref().unwrap();
        let dok: proxy::DokodemoConfig = serde_json::from_value(settings.clone()).unwrap();
        assert!(dok.follow_redirect);
    }

    #[test]
    fn test_shadowsocks_inbound() {
        let json = r#"{
            "inbounds": [{
                "protocol": "shadowsocks",
                "settings": {
                    "method": "aes-256-gcm",
                    "password": "secret",
                    "users": [{"method": "chacha20-poly1305", "password": "userpass"}]
                }
            }]
        }"#;
        let cfg = Config::from_json(json).unwrap();
        let settings = cfg.inbounds[0].settings.as_ref().unwrap();
        let ss: proxy::ShadowsocksInboundConfig = serde_json::from_value(settings.clone()).unwrap();
        assert_eq!(ss.method, "aes-256-gcm");
        assert_eq!(ss.users.len(), 1);
    }

    #[test]
    fn test_routing_config() {
        let json = r#"{
            "routing": {
                "domainStrategy": "IpIfNonMatch",
                "rules": [
                    {
                        "type": "field",
                        "domain": ["google.com", "youtube.com"],
                        "outboundTag": "proxy"
                    },
                    {
                        "type": "field",
                        "ip": ["1.2.3.4"],
                        "port": "80,443",
                        "outboundTag": "direct"
                    }
                ]
            }
        }"#;
        let cfg = Config::from_json(json).unwrap();
        let routing = cfg.routing.unwrap();
        assert_eq!(routing.domain_strategy, "IpIfNonMatch");
        assert_eq!(routing.rules.len(), 2);
        assert_eq!(routing.rules[0].outbound_tag, "proxy");
    }

    #[test]
    fn test_tls_config() {
        let json = r#"{
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{"address": "x.com", "port": 443, "users": [{"id": "x"}]}]},
                "streamSettings": {
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "x.com",
                        "fingerprint": "chrome",
                        "allowInsecure": false
                    }
                }
            }]
        }"#;
        let cfg = Config::from_json(json).unwrap();
        let stream = cfg.outbounds[0].stream_settings.as_ref().unwrap();
        assert_eq!(stream.security, "tls");
        let tls = stream.tls_settings.as_ref().unwrap();
        assert_eq!(tls.server_name, "x.com");
        assert_eq!(tls.fingerprint, "chrome");
    }

    #[test]
    fn test_socks_inbound() {
        let json = r#"{
            "inbounds": [{
                "protocol": "socks",
                "settings": {
                    "auth": "password",
                    "accounts": [{"user": "test", "pass": "secret"}],
                    "udp": true
                }
            }]
        }"#;
        let cfg = Config::from_json(json).unwrap();
        let settings = cfg.inbounds[0].settings.as_ref().unwrap();
        let socks: proxy::SocksInboundConfig = serde_json::from_value(settings.clone()).unwrap();
        assert_eq!(socks.auth, "password");
        assert_eq!(socks.accounts[0].user, "test");
        assert!(socks.udp);
    }

    #[test]
    fn test_full_config_roundtrip() {
        let json = r#"{
            "log": {"loglevel": "info", "access": "/var/log/access.log"},
            "dns": {
                "servers": [
                    {"address": "1.1.1.1", "port": 53, "domains": ["geosite:google"]},
                    {"address": "8.8.8.8"}
                ]
            },
            "inbounds": [
                {
                    "protocol": "vless",
                    "port": 443,
                    "listen": "0.0.0.0",
                    "tag": "in-vless",
                    "settings": {"clients": [{"id": "uuid123", "flow": "xtls-rprx-vision"}]},
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "dest": "www.example.com:443",
                            "serverNames": ["example.com"],
                            "privateKey": "abc",
                            "shortIds": ["123"]
                        }
                    }
                }
            ],
            "outbounds": [
                {
                    "protocol": "vless",
                    "tag": "out-vless",
                    "settings": {
                        "vnext": [{"address": "server.com", "port": 443, "users": [{"id": "uuid456"}]}]
                    },
                    "mux": {"enabled": true, "concurrency": 8}
                },
                {"protocol": "freedom", "tag": "out-direct", "settings": {}}
            ]
        }"#;
        let cfg = Config::from_json(json).unwrap();
        assert_eq!(cfg.inbounds.len(), 1);
        assert_eq!(cfg.outbounds.len(), 2);

        let ib = &cfg.inbounds[0];
        assert_eq!(ib.tag, "in-vless");
        assert_eq!(ib.protocol, "vless");

        let stream = ib.stream_settings.as_ref().unwrap();
        assert!(stream.network.is_tcp());
        assert_eq!(stream.security, "reality");
        assert!(stream.reality_settings.is_some());

        let ob = &cfg.outbounds[0];
        assert_eq!(ob.tag, "out-vless");
        let mux = ob.mux.as_ref().unwrap();
        assert!(mux.enabled);
        assert_eq!(mux.concurrency, 8);

        let ob2 = &cfg.outbounds[1];
        assert_eq!(ob2.protocol, "freedom");
    }
}
