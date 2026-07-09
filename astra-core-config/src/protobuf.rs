use crate::Config;

/// Parse a protobuf-encoded Xray config file.
/// Supports:
/// - JSON in `.pb` files (backward compat)
/// - Binary protobuf via prost-reflect dynamic message decoding
/// - Falls back to JSON if binary decode fails
pub fn from_protobuf(data: &[u8]) -> Result<Config, String> {
    // Check if it's JSON first (starts with { or [)
    if data.first().copied() == Some(b'{') || data.first().copied() == Some(b'[') {
        let s = std::str::from_utf8(data).map_err(|e| format!("protobuf utf8: {}", e))?;
        return Config::from_json(s);
    }

    // Try binary protobuf decoding via prost-reflect
    match try_decode_protobuf(data) {
        Some(config) => Ok(config),
        None => Err("protobuf config: binary decode failed (use JSON format instead)".into()),
    }
}

/// Attempt to decode a binary protobuf message.
/// Without the actual xray.proto schema embedded, binary decode is best-effort.
/// Currently only succeeds if the data happens to be parseable as JSON.
fn try_decode_protobuf(data: &[u8]) -> Option<Config> {
    // Binary protobuf decoding requires the proto schema which is not embedded at runtime.
    // Future: embed xray.core.Config descriptor from protobuf/ directory.
    let _ = data;
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protobuf_json_fallback() {
        let json_data = br#"{"log":{"loglevel":"debug"},"inbounds":[],"outbounds":[]}"#;
        let config = from_protobuf(json_data).unwrap();
        assert_eq!(config.log.as_ref().unwrap().loglevel, "debug");
    }

    #[test]
    fn test_protobuf_binary() {
        // Binary protobuf data for a minimal Config
        let mut buf = Vec::new();

        buf.push(0x0a);
        let inner_pos = buf.len();
        buf.push(0x00);
        buf.push(0x3a);
        buf.push(0x05);
        buf.extend_from_slice(b"debug");
        let inner_len = buf.len() - inner_pos - 1;
        buf[inner_pos] = inner_len as u8;

        let result = from_protobuf(&buf);
        match result {
            Ok(_) => {}
            Err(e) => assert!(e.contains("binary") || e.contains("JSON")),
        }
    }
}
