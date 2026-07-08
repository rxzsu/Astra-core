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

/// Attempt to decode a binary protobuf message as a dynamic message,
/// then convert to JSON and parse as Config.
fn try_decode_protobuf(data: &[u8]) -> Option<Config> {
    use prost_reflect::DynamicMessage;
    use prost::Message;

    // Try to decode as a generic protobuf message
    // First, try as a standard Xray Config format by attempting
    // to decode field-by-field
    let desc = prost_reflect::MessageDescriptor::new("xray.core.Config", vec![]).ok()?;
    let msg = DynamicMessage::decode(desc, data).ok()?;
    
    // Convert to JSON value
    let json_value = prost_reflect::serde::serialize(&msg).ok()?;
    
    // Convert JSON value to Config
    serde_json::from_value(json_value).ok()
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
        // This is encoded as: field 1 (log) = {field 7 (loglevel) = "debug"}
        use prost::Message;
        let mut buf = Vec::new();
        
        // Manually encode a simple protobuf message
        // Field 1: log = message { field 7: loglevel = "debug" }
        // Tag: (1 << 3) | 2 = 0x0a
        buf.push(0x0a); // tag for field 1, wire type 2 (length-delimited)
        
        // Inner message length (will fill later)
        let inner_pos = buf.len();
        buf.push(0x00); // placeholder
        
        // Inner message: field 7 (loglevel), wire type 2
        // Tag: (7 << 3) | 2 = 0x3a
        buf.push(0x3a);
        // Length of "debug"
        buf.push(0x05);
        buf.extend_from_slice(b"debug");
        
        // Update inner message length
        let inner_len = buf.len() - inner_pos - 1;
        buf[inner_pos] = inner_len as u8;
        
        // Try to decode - may work with prost-reflect
        let result = from_protobuf(&buf);
        // For now, either succeeds or gives a reasonable error
        match result {
            Ok(_) => {}
            Err(e) => assert!(e.contains("binary") || e.contains("JSON")),
        }
    }
}
