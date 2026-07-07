use serde::{Deserialize, Serialize};

use crate::types::{Address, TransportProtocol};

/// Top-level stream settings, maps to Go's `StreamConfig`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub network: TransportProtocol,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub security: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_settings: Option<TLSConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality_settings: Option<REALITYConfig>,

    // Transport-specific settings
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_settings: Option<TCPConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_settings: Option<WebSocketConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kcp_settings: Option<KCPConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_settings: Option<GRPCConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub httpupgrade_settings: Option<HttpUpgradeConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub splithttp_settings: Option<SplitHTTPConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_settings: Option<QUICConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_settings: Option<HttpConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sockopt: Option<SocketConfig>,
}

// ─── WebSocket ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WebSocketConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<serde_json::Value>,
    #[serde(default)]
    pub accept_proxy_protocol: bool,
    #[serde(default)]
    pub heartbeat_period: u32,
}

// ─── TCP ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TCPConfig {
    #[serde(default)]
    pub header: Option<serde_json::Value>,
    #[serde(default)]
    pub accept_proxy_protocol: bool,
}

// ─── KCP / mKCP ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct KCPConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tti: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uplink_capacity: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub downlink_capacity: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub congestion: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_buffer_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_buffer_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<String>,
}

// ─── gRPC ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GRPCConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub authority: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub service_name: String,
    #[serde(default)]
    pub multi_mode: bool,
    #[serde(default)]
    pub idle_timeout: i32,
    #[serde(default)]
    pub health_check_timeout: i32,
    #[serde(default)]
    pub permit_without_stream: bool,
    #[serde(default)]
    pub initial_windows_size: i32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user_agent: String,
}

// ─── HTTPUpgrade ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HttpUpgradeConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default)]
    pub headers: Option<serde_json::Value>,
    #[serde(default)]
    pub accept_proxy_protocol: bool,
}

// ─── SplitHTTP (XHTTP) ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SplitHTTPConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mode: String,
    #[serde(default)]
    pub headers: Option<serde_json::Value>,
    #[serde(default)]
    pub max_upload_size: i64,
    #[serde(default)]
    pub min_upload_interval_ms: i32,
    #[serde(default)]
    pub download_settings: Option<Box<StreamConfig>>,
}

// ─── QUIC ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct QUICConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub security: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<serde_json::Value>,
}

// ─── HTTP/2 (h2) ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HttpConfig {
    #[serde(default)]
    pub host: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
}

// ─── TLS ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TLSConfig {
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default)]
    pub certificates: Vec<TLSCertConfig>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub alpn: String,
    #[serde(default)]
    pub enable_session_resumption: bool,
    #[serde(default)]
    pub disable_system_root: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub min_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub max_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cipher_suites: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
    #[serde(default)]
    pub reject_unknown_sni: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TLSCertConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub certificate_file: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_file: String,
    #[serde(default)]
    pub certificate: Vec<String>,
    #[serde(default)]
    pub key: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<String>,
}

// ─── REALITY ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct REALITYConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub master_key_log: String,
    #[serde(default)]
    pub show: bool,
    #[serde(default)]
    pub target: Option<serde_json::Value>,
    #[serde(default)]
    pub dest: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub r#type: String,
    #[serde(default)]
    pub xver: u64,
    #[serde(default)]
    pub server_names: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub private_key: String,
    #[serde(default)]
    pub short_ids: Vec<String>,

    // Client-side fields
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub public_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub short_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub spider_x: String,
}

// ─── Socket (sockopt) ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SocketConfig {
    #[serde(default)]
    pub mark: i32,
    #[serde(default)]
    pub tcp_fast_open: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tproxy: String,
    #[serde(default)]
    pub accept_proxy_protocol: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain_strategy: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub dialer_proxy: String,
    #[serde(default)]
    pub tcp_keep_alive_interval: i32,
    #[serde(default)]
    pub tcp_keep_alive_idle: i32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tcp_congestion: String,
    #[serde(default)]
    pub tcp_window_clamp: i32,
    #[serde(default)]
    pub tcp_max_seg: i32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub interface: String,
    #[serde(default)]
    pub v6only: bool,
}
