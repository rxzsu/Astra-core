use std::collections::HashMap;

const CHARSET_BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const VALIDATION_TOLERANCE: i32 = 2;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PaddingMethod {
    RepeatX,
    Tokenish,
}

/// Generate random padding string.
pub fn generate_padding(method: PaddingMethod, length: usize) -> String {
    if length == 0 {
        return String::new();
    }
    match method {
        PaddingMethod::RepeatX => "X".repeat(length),
        PaddingMethod::Tokenish => generate_tokenish_padding(length),
    }
}

fn generate_tokenish_padding(target_huffman_bytes: usize) -> String {
    let n = (target_huffman_bytes as f64 / 0.8).ceil() as usize;
    if n < 1 {
        return "X".to_string();
    }
    let mut s: Vec<u8> = (0..n).map(|_| CHARSET_BASE62[fastrand::usize(..CHARSET_BASE62.len())]).collect();
    let mut iter = 0u32;
    loop {
        let current_len = approx_hpack_len(&s);
        let diff = current_len as i32 - target_huffman_bytes as i32;
        if diff.abs() <= VALIDATION_TOLERANCE || iter > 150 {
            break;
        }
        if diff < 0 {
            s.push(b'X');
        } else {
            s.pop();
            if s.is_empty() { s.push(b'X'); break; }
        }
        iter += 1;
    }
    String::from_utf8(s).unwrap_or_else(|_| "X".repeat(n))
}

fn approx_hpack_len(data: &[u8]) -> usize {
    (data.len() * 7 + 7) / 8
}

/// Apply padding string to a URL query string.
pub fn apply_padding_to_query(url: &str, key: &str, value: &str) -> String {
    if let Some(query_start) = url.find('?') {
        let base = &url[..query_start];
        let query = &url[query_start + 1..];
        let mut params: HashMap<String, String> = query
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|s| {
                let mut parts = s.splitn(2, '=');
                let k = parts.next().unwrap_or("");
                let v = parts.next().unwrap_or("");
                (k.to_string(), v.to_string())
            })
            .collect();
        params.insert(key.to_string(), value.to_string());
        let new_query: Vec<String> = params.into_iter().map(|(k, v)| format!("{k}={v}")).collect();
        format!("{}?{}", base, new_query.join("&"))
    } else {
        format!("{}?{}={}", url, key, value)
    }
}

/// Validate padding value is within expected range.
pub fn is_padding_valid(padding: &str, from: usize, to: usize, method: PaddingMethod) -> bool {
    if padding.is_empty() {
        return false;
    }
    let n = padding.len();
    let effective_len = match method {
        PaddingMethod::RepeatX => n,
        PaddingMethod::Tokenish => approx_hpack_len(padding.as_bytes()),
    };
    effective_len >= from && effective_len <= to
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_repeat_x() {
        let s = generate_padding(PaddingMethod::RepeatX, 10);
        assert_eq!(s.len(), 10);
        assert!(s.chars().all(|c| c == 'X'));
    }

    #[test]
    fn test_generate_tokenish() {
        let s = generate_padding(PaddingMethod::Tokenish, 100);
        assert!(!s.is_empty());
    }

    #[test]
    fn test_is_padding_valid() {
        assert!(is_padding_valid("XXXXX", 5, 10, PaddingMethod::RepeatX));
        assert!(!is_padding_valid("XXXXX", 10, 20, PaddingMethod::RepeatX));
    }

    #[test]
    fn test_apply_padding_to_query() {
        let result = apply_padding_to_query("https://example.com/path", "pad", "abc");
        assert_eq!(result, "https://example.com/path?pad=abc");
    }
}
