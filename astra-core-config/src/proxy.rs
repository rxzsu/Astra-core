use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::types::Address;

// ─── VLESS ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VLessInboundConfig {
    #[serde(default)]
    pub clients: Vec<VLessUser>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub decryption: String,
    #[serde(default)]
    pub fallbacks: Vec<VLessInboundFallback>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub flow: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VLessUser {
    pub id: String,
    #[serde(default)]
    pub level: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub encryption: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub flow: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VLessInboundFallback {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub alpn: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub r#type: String,
    pub dest: Option<Value>,
    #[serde(default)]
    pub xver: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VLessOutboundConfig {
    #[serde(default)]
    pub vnext: Vec<VLessOutboundVnext>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VLessOutboundVnext {
    pub address: Address,
    pub port: u16,
    #[serde(default)]
    pub users: Vec<VLessUser>,
}

// ─── VMess ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VMessInboundConfig {
    #[serde(default)]
    pub clients: Vec<VMessUser>,
    #[serde(default)]
    pub default: Option<VMessDefaultConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VMessUser {
    pub id: String,
    #[serde(default)]
    pub level: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub security: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VMessDefaultConfig {
    #[serde(default)]
    pub level: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VMessOutboundConfig {
    #[serde(default)]
    pub vnext: Vec<VMessOutboundVnext>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VMessOutboundVnext {
    pub address: Address,
    pub port: u16,
    #[serde(default)]
    pub users: Vec<VMessUser>,
}

// ─── Freedom (Direct) ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FreedomConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain_strategy: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub redirect: String,
    #[serde(default)]
    pub user_level: u32,
    #[serde(default)]
    pub fragment: Option<FreedomFragment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FreedomFragment {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub packets: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<crate::types::Int32Range>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<crate::types::Int32Range>,
    #[serde(default)]
    pub max_split_min: u64,
    #[serde(default)]
    pub max_split_max: u64,
}

// ─── Dokodemo-door ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DokodemoConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<crate::types::NetworkList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub follow_redirect: bool,
    #[serde(default)]
    pub user_level: u32,
}

// ─── Blackhole ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BlackholeConfig {
    #[serde(default)]
    pub response: Option<Value>,
}

// ─── SOCKS ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SocksInboundConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub auth: String,
    #[serde(default)]
    pub accounts: Vec<SocksAccount>,
    #[serde(default)]
    pub udp: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<Address>,
    #[serde(default)]
    pub user_level: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SocksAccount {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pass: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SocksOutboundConfig {
    pub address: Address,
    pub port: u16,
    #[serde(default)]
    pub user_level: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pass: String,
}

// ─── HTTP ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HTTPInboundConfig {
    #[serde(default)]
    pub accounts: Vec<HTTPAccount>,
    #[serde(default)]
    pub allow_transparent: bool,
    #[serde(default)]
    pub user_level: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HTTPAccount {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pass: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HTTPOutboundConfig {
    pub address: Address,
    pub port: u16,
    #[serde(default)]
    pub user_level: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pass: String,
    #[serde(default)]
    pub headers: Option<serde_json::Value>,
}

// ─── Trojan ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TrojanInboundConfig {
    #[serde(default)]
    pub clients: Vec<TrojanUser>,
    #[serde(default)]
    pub fallbacks: Vec<TrojanFallback>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TrojanUser {
    pub password: String,
    #[serde(default)]
    pub level: u8,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub flow: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TrojanFallback {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub alpn: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub r#type: String,
    pub dest: Option<Value>,
    #[serde(default)]
    pub xver: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TrojanOutboundConfig {
    pub address: Address,
    pub port: u16,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub level: u8,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub flow: String,
}

// ─── Shadowsocks ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ShadowsocksInboundConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(default)]
    pub level: u8,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email: String,
    #[serde(default)]
    pub users: Vec<ShadowsocksUser>,
    #[serde(default)]
    pub network: Option<crate::types::NetworkList>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ShadowsocksUser {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(default)]
    pub level: u8,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ShadowsocksOutboundConfig {
    pub address: Address,
    pub port: u16,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub level: u8,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email: String,
}

// ─── Loopback ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LoopbackConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub inbound_tag: String,
}

// ─── DNS Outbound ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DNSOutboundConfig {
    #[serde(default)]
    pub address: Option<Address>,
    #[serde(default)]
    pub port: u16,
}
