use crate::Config;

/// Parse a protobuf-encoded Xray config.
/// Go equivalent: loading `.pb` config files via protobuf.
pub fn from_protobuf(data: &[u8]) -> Result<Config, String> {
    // Protobuf deserialization requires generated types.
    // For now, provide a stub that attempts JSON round-trip.
    let s = std::str::from_utf8(data).map_err(|e| format!("protobuf utf8: {}", e))?;
    // If it looks like JSON, parse as JSON
    if s.trim_start().starts_with('{') || s.trim_start().starts_with('[') {
        return Config::from_json(s);
    }
    Err("protobuf config: binary protobuf not yet supported (use JSON)".into())
}
