use serde::{Deserialize, Serialize};

use crate::types::{PortList, NetworkList, StringList};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RouterConfig {
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
    #[serde(default)]
    pub domain_strategy: String,
    #[serde(default)]
    pub balancers: Vec<BalancingRule>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub geoip_dat_path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub geosite_dat_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RoutingRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<StringList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domains: Option<StringList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<StringList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<PortList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkList>,
    #[serde(default, rename = "source", skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<StringList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_port: Option<PortList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<StringList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_tag: Option<StringList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<StringList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attrs: Option<serde_json::Value>,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub outbound_tag: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub balancer_tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BalancingRule {
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub selector: StringList,
    #[serde(default)]
    pub strategy: StrategyConfig,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fallback_tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StrategyConfig {
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub settings: Option<serde_json::Value>,
}
