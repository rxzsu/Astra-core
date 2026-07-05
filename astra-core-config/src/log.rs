use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LogConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub access: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub loglevel: String,
    #[serde(default)]
    pub dns_log: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mask_address: String,
}
