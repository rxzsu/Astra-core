use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PolicyConfig {
    #[serde(default)]
    pub levels: HashMap<u32, Policy>,
    #[serde(default)]
    pub system: Option<SystemPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conn_idle: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uplink_only: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub downlink_only: Option<u32>,
    #[serde(default)]
    pub stats_user_uplink: bool,
    #[serde(default)]
    pub stats_user_downlink: bool,
    #[serde(default)]
    pub stats_user_online: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buffer_size: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SystemPolicy {
    #[serde(default)]
    pub stats_inbound_uplink: bool,
    #[serde(default)]
    pub stats_inbound_downlink: bool,
    #[serde(default)]
    pub stats_outbound_uplink: bool,
    #[serde(default)]
    pub stats_outbound_downlink: bool,
}
