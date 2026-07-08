/// IP address masking in logs.
/// Go equivalent: `common/log` with `mask_address` config.

/// Mask an IP address for logging.
/// - "half": masks the second half (e.g., 192.168.xxx.xxx)
/// - "quarter": masks the last quarter
/// - "full": masks the entire IP
/// - "none" or empty: no masking
pub fn mask_ip(ip: &str, mode: &str) -> String {
    match mode {
        "half" => {
            if let Some(pos) = ip.rfind('.') {
                let prefix = &ip[..pos];
                let last_dot = prefix.rfind('.');
                if let Some(dot) = last_dot {
                    format!("{}.xxx.xxx", &prefix[..dot])
                } else {
                    format!("{}.xxx", prefix)
                }
            } else if let Some(pos) = ip.rfind(':') {
                let prefix = &ip[..pos];
                let last_colon = prefix.rfind(':');
                if let Some(col) = last_colon {
                    format!("{}:xxxx:xxxx", &prefix[..col])
                } else {
                    format!("{}:xxxx", prefix)
                }
            } else {
                "xxx".to_string()
            }
        }
        "quarter" => {
            if let Some(pos) = ip.rfind('.') {
                format!("{}.xxx", &ip[..pos])
            } else if let Some(pos) = ip.rfind(':') {
                format!("{}:xxxx", &ip[..pos])
            } else {
                "xxx".to_string()
            }
        }
        "full" => "xxx".to_string(),
        _ => ip.to_string(),
    }
}

/// Mask all IPs in a log message.
pub fn mask_ips_in_message(msg: &str, mode: &str) -> String {
    if mode.is_empty() || mode == "none" {
        return msg.to_string();
    }
    // Simple IP pattern matching
    let mut result = msg.to_string();
    // Match IPv4 addresses
    let ip_pattern = regex_lite::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
    for ip in ip_pattern.find_iter(msg) {
        let masked = mask_ip(ip.as_str(), mode);
        result = result.replace(ip.as_str(), &masked);
    }
    // Match IPv6 addresses (simplified)
    let ip6_pattern = regex_lite::Regex::new(r"\b[0-9a-fA-F:]+:[0-9a-fA-F:]+\b").unwrap();
    for ip in ip6_pattern.find_iter(msg) {
        let masked = mask_ip(ip.as_str(), mode);
        result = result.replace(ip.as_str(), &masked);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_ip_none() {
        assert_eq!(mask_ip("1.2.3.4", ""), "1.2.3.4");
    }

    #[test]
    fn test_mask_ip_quarter() {
        assert_eq!(mask_ip("1.2.3.4", "quarter"), "1.2.3.xxx");
    }

    #[test]
    fn test_mask_ip_half() {
        assert_eq!(mask_ip("1.2.3.4", "half"), "1.2.xxx.xxx");
    }

    #[test]
    fn test_mask_ip_full() {
        assert_eq!(mask_ip("1.2.3.4", "full"), "xxx");
    }

    #[test]
    fn test_mask_ips_in_message() {
        let msg = "connect from 1.2.3.4 to 5.6.7.8";
        let masked = mask_ips_in_message(msg, "quarter");
        assert_eq!(masked, "connect from 1.2.3.xxx to 5.6.7.xxx");
    }
}
