use std::sync::RwLock;

use astra_core_common::log::{AccessMessage, LogHandler, LogMessage, Severity};
#[allow(unused_imports)]
use astra_core_common::log::AccessStatus;

// ── Config ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct LogConfig {
    pub access_log_type: LogType,
    pub access_log_path: String,
    pub error_log_type: LogType,
    pub error_log_path: String,
    pub error_log_level: Severity,
    pub mask_address: String,
    pub enable_dns_log: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogType {
    #[default]
    None,
    Console,
    File,
}

impl LogType {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "console" | "stdout" => LogType::Console,
            "file" => LogType::File,
            _ => LogType::None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            LogType::None => "none",
            LogType::Console => "console",
            LogType::File => "file",
        }
    }
}

// ── IP Masking ──────────────────────────────────────────────────────────────

lazy_static::lazy_static! {
    static ref IPV4_RE: regex_lite::Regex = regex_lite::Regex::new(r"(\d{1,3}\.){3}\d{1,3}").unwrap();
    static ref IPV6_RE: regex_lite::Regex = regex_lite::Regex::new(r"(?:[\da-fA-F]{0,4}:[\da-fA-F]{0,4}){2,7}").unwrap();
}

fn parse_mask_address(c: &str) -> (usize, usize) {
    match c {
        "half" => (16, 32),
        "quarter" => (8, 16),
        "full" => (0, 0),
        "" => (32, 128),
        _ => {
            let parts: Vec<&str> = c.split('+').collect();
            let m4 = parts.first().and_then(|p| {
                p.trim_start_matches('/').parse::<usize>().ok()
            }).unwrap_or(32).min(32);
            let m6 = parts.get(1).and_then(|p| {
                p.trim_start_matches('/').parse::<usize>().ok()
            }).unwrap_or(128).min(128);
            (m4, m6)
        }
    }
}

fn mask_ipv4(s: &str, mask_bits: usize) -> String {
    if mask_bits >= 32 {
        return s.to_string();
    }
    IPV4_RE.replace_all(s, |caps: &regex_lite::Captures| {
        let ip = caps.get(0).unwrap().as_str();
        if mask_bits == 0 {
            return "[Masked IPv4]".to_string();
        }
        let parts: Vec<&str> = ip.split('.').collect();
        let keep = mask_bits / 8;
        parts.iter().enumerate().map(|(i, p)| {
            if i < keep { (*p).to_string() } else { "*".to_string() }
        }).collect::<Vec<_>>().join(".")
    }).into_owned()
}

fn mask_ipv6(s: &str, mask_bits: usize) -> String {
    if mask_bits >= 128 {
        return s.to_string();
    }
    IPV6_RE.replace_all(s, |caps: &regex_lite::Captures| {
        let ip_str = caps.get(0).unwrap().as_str();
        if mask_bits == 0 {
            return "[Masked IPv6]".to_string();
        }
        if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
            if let std::net::IpAddr::V6(v6) = ip {
                let masked = v6.mask(mask_bits as u32).unwrap_or(v6);
                format!("{}/{}", masked, mask_bits)
            } else {
                ip_str.to_string()
            }
        } else {
            ip_str.to_string()
        }
    }).into_owned()
}

fn mask_message(msg: &str, mask4: usize, mask6: usize) -> String {
    let s = mask_ipv6(msg, mask6);
    mask_ipv4(&s, mask4)
}

// ── Logger Instance ─────────────────────────────────────────────────────────

/// App-level log manager. Routes log messages to access/error loggers based on config.
/// Go equivalent: `app/log.Instance`
pub struct LoggerInstance {
    config: LogConfig,
    access_logger: Option<Box<dyn LogHandler>>,
    error_logger: Option<Box<dyn LogHandler>>,
    active: RwLock<bool>,
    mask4: usize,
    mask6: usize,
}

impl LoggerInstance {
    pub fn new(config: LogConfig) -> Self {
        let (mask4, mask6) = parse_mask_address(&config.mask_address);
        LoggerInstance {
            access_logger: None,
            error_logger: None,
            active: RwLock::new(false),
            mask4,
            mask6,
            config,
        }
    }

    pub fn start(&mut self) -> Result<(), String> {
        let mut active = self.active.write().unwrap();
        if *active {
            return Ok(());
        }
        *active = true;

        self.access_logger = create_handler(self.config.access_log_type, &self.config.access_log_path)?;
        self.error_logger = create_handler(self.config.error_log_type, &self.config.error_log_path)?;

        Ok(())
    }

    pub fn close(&mut self) {
        *self.active.write().unwrap() = false;
        self.access_logger = None;
        self.error_logger = None;
    }
}

impl LogHandler for LoggerInstance {
    fn handle_access(&self, msg: &AccessMessage) {
        if !*self.active.read().unwrap() {
            return;
        }
        let msg_str = format_access(msg);
        let masked = if !self.config.mask_address.is_empty() {
            mask_message(&msg_str, self.mask4, self.mask6)
        } else {
            msg_str
        };
        if let Some(ref logger) = self.access_logger {
            logger.handle_access(&AccessMessage {
                from: msg.from.clone(),
                to: msg.to.clone(),
                status: msg.status,
                reason: msg.reason.clone(),
                email: msg.email.clone(),
                protocol: msg.protocol.clone(),
                outbound_tag: msg.outbound_tag.clone(),
                timestamp: msg.timestamp,
            });
            tracing::info!("{}", masked);
        }
    }

    fn handle_log(&self, msg: &LogMessage) {
        if !*self.active.read().unwrap() {
            return;
        }
        if msg.severity > self.config.error_log_level {
            return;
        }
        let masked = if !self.config.mask_address.is_empty() {
            mask_message(&msg.message, self.mask4, self.mask6)
        } else {
            msg.message.clone()
        };
        match msg.severity {
            Severity::Debug => tracing::debug!("{}", masked),
            Severity::Info => tracing::info!("{}", masked),
            Severity::Warning => tracing::warn!("{}", masked),
            Severity::Error => tracing::error!("{}", masked),
        }
    }
}

fn format_access(msg: &AccessMessage) -> String {
    format!(
        "{} {} -> {} [{}] {}",
        chrono::Utc::now().format("%Y/%m/%d %H:%M:%S"),
        msg.from,
        msg.to,
        msg.status.as_str(),
        msg.reason,
    )
}

// ── Handlers ────────────────────────────────────────────────────────────────

fn create_handler(log_type: LogType, path: &str) -> Result<Option<Box<dyn LogHandler>>, String> {
    match log_type {
        LogType::None => Ok(None),
        LogType::Console => Ok(Some(Box::new(ConsoleHandler))),
        LogType::File => {
            if path.is_empty() {
                return Err("file log type requires a path".into());
            }
            Ok(Some(Box::new(FileHandler { path: path.to_string() })))
        }
    }
}

struct ConsoleHandler;

impl LogHandler for ConsoleHandler {
    fn handle_access(&self, msg: &AccessMessage) {
        println!("[Access] {} {} -> {} {}", msg.status.as_str(), msg.from, msg.to, msg.reason);
    }

    fn handle_log(&self, msg: &LogMessage) {
        eprintln!("[{}] {}", msg.severity.as_str(), msg.message);
    }
}

struct FileHandler {
    path: String,
}

impl LogHandler for FileHandler {
    fn handle_access(&self, msg: &AccessMessage) {
        let line = format!(
            "[Access] {} {} -> {} {}\n",
            msg.status.as_str(),
            msg.from,
            msg.to,
            msg.reason
        );
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            use std::io::Write;
            let _ = f.write_all(line.as_bytes());
        }
    }

    fn handle_log(&self, msg: &LogMessage) {
        let line = format!("[{}] {}\n", msg.severity.as_str(), msg.message);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            use std::io::Write;
            let _ = f.write_all(line.as_bytes());
        }
    }
}

impl Drop for FileHandler {
    fn drop(&mut self) {}
}

// ── Mask helpers for IPv6 ───────────────────────────────────────────────────

trait Ipv6MaskExt {
    fn mask(self, bits: u32) -> Option<std::net::Ipv6Addr>;
}

impl Ipv6MaskExt for std::net::Ipv6Addr {
    fn mask(self, bits: u32) -> Option<std::net::Ipv6Addr> {
        if bits > 128 {
            return None;
        }
        let octets = self.octets();
        let mut masked = [0u8; 16];
        let full_bytes = (bits / 8) as usize;
        let remaining_bits = bits % 8;
        for i in 0..full_bytes {
            masked[i] = octets[i];
        }
        if full_bytes < 16 {
            let mask = !0u8 << (8 - remaining_bits);
            masked[full_bytes] = octets[full_bytes] & mask;
        }
        Some(std::net::Ipv6Addr::from(masked))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mask() {
        assert_eq!(parse_mask_address("half"), (16, 32));
        assert_eq!(parse_mask_address("quarter"), (8, 16));
        assert_eq!(parse_mask_address("full"), (0, 0));
        assert_eq!(parse_mask_address(""), (32, 128));
    }

    #[test]
    fn test_mask_ipv4_half() {
        let result = mask_ipv4("192.168.1.1", 16);
        assert_eq!(result, "192.168.*.*");
    }

    #[test]
    fn test_mask_ipv4_full() {
        let result = mask_ipv4("192.168.1.1", 0);
        assert_eq!(result, "[Masked IPv4]");
    }

    #[test]
    fn test_mask_ipv4_none() {
        let result = mask_ipv4("192.168.1.1", 32);
        assert_eq!(result, "192.168.1.1");
    }

    #[test]
    fn test_log_type_from_str() {
        assert_eq!(LogType::from_str("console"), LogType::Console);
        assert_eq!(LogType::from_str("stdout"), LogType::Console);
        assert_eq!(LogType::from_str("file"), LogType::File);
        assert_eq!(LogType::from_str("none"), LogType::None);
        assert_eq!(LogType::from_str(""), LogType::None);
    }

    #[test]
    fn test_format_access() {
        let msg = AccessMessage {
            from: "1.2.3.4".into(),
            to: "example.com".into(),
            status: AccessStatus::Accepted,
            reason: "proxy".into(),
            email: None,
            protocol: None,
            outbound_tag: None,
            timestamp: 0,
        };
        let s = format_access(&msg);
        assert!(s.contains("accepted"));
        assert!(s.contains("1.2.3.4"));
        assert!(s.contains("example.com"));
    }
}
