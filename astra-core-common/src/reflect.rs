use serde_json::Value;

/// Marshal any type to JSON with optional type info injection.
/// Go equivalent: `common/reflect.MarshalToJson()`
pub fn marshal_to_json<T: serde::Serialize>(val: &T, inject_type: bool) -> Option<String> {
    if inject_type {
        let json_val = serde_json::to_value(val).ok()?;
        let type_name = std::any::type_name::<T>();
        let obj = serde_json::json!({
            "type": type_name,
            "value": json_val,
        });
        serde_json::to_string_pretty(&obj).ok()
    } else {
        serde_json::to_string_pretty(val).ok()
    }
}

/// Convert a `serde_json::Value` to a formatted JSON string.
pub fn value_to_json(val: &Value, pretty: bool) -> Option<String> {
    if pretty {
        serde_json::to_string_pretty(val).ok()
    } else {
        serde_json::to_string(val).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_marshal_to_json() {
        let data = vec![1, 2, 3];
        let json = marshal_to_json(&data, false).unwrap();
        assert!(json.contains("[1,2,3]") || json.contains("[\n  1,\n  2,\n  3\n]"));
    }

    #[test]
    fn test_marshal_with_type() {
        let data = "hello";
        let json = marshal_to_json(&data, true).unwrap();
        assert!(json.contains("type"));
        assert!(json.contains("hello"));
    }
}
