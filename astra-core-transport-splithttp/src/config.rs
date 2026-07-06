use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub path: String,
    pub mode: SplitMode,
    pub headers: HashMap<String, String>,
    pub max_upload_size: usize,
    pub min_upload_interval: std::time::Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitMode {
    PacketUp,
    StreamUp,
    StreamOne,
}

impl Default for SplitMode {
    fn default() -> Self {
        Self::PacketUp
    }
}

impl Config {
    pub fn from_stream_config(stream: &astra_core_config::transport::SplitHTTPConfig) -> Self {
        let path = if stream.path.is_empty() {
            "/".to_string()
        } else {
            stream.path.clone()
        };

        let mode = match stream.mode.as_str() {
            "stream-up" => SplitMode::StreamUp,
            "stream-one" => SplitMode::StreamOne,
            _ => SplitMode::PacketUp,
        };

        let headers = stream
            .headers
            .as_ref()
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let max_upload_size = if stream.max_upload_size > 0 {
            stream.max_upload_size as usize
        } else {
            1_000_000
        };

        let min_upload_interval = if stream.min_upload_interval_ms > 0 {
            std::time::Duration::from_millis(stream.min_upload_interval_ms as u64)
        } else {
            std::time::Duration::from_millis(30)
        };

        Self {
            host: stream.host.clone(),
            path,
            mode,
            headers,
            max_upload_size,
            min_upload_interval,
        }
    }
}
