use serde::{Deserialize, Serialize};

use crate::types::{Address, StringList};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DNSConfig {
    #[serde(default)]
    pub servers: Vec<NameServerConfig>,
    #[serde(default)]
    pub hosts: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<Address>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tag: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub query_strategy: String,
    #[serde(default)]
    pub disable_cache: bool,
    #[serde(default)]
    pub disable_fallback: bool,
    #[serde(default)]
    pub disable_fallback_if_match: bool,
    #[serde(default)]
    pub enable_parallel_query: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct NameServerConfig {
    pub address: Address,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<Address>,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub skip_fallback: bool,
    #[serde(default)]
    pub domains: StringList,
    #[serde(default)]
    pub expected_ips: StringList,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub query_strategy: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tag: String,
}
