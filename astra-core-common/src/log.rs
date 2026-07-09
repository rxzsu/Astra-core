use std::sync::Arc;

/// Xray-style severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Severity {
    #[default]
    Debug,
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Debug => "Debug",
            Severity::Info => "Info",
            Severity::Warning => "Warning",
            Severity::Error => "Error",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "debug" => Severity::Debug,
            "warning" | "warn" => Severity::Warning,
            "error" | "err" => Severity::Error,
            _ => Severity::Info,
        }
    }
}

/// Access log entry (Go: `common/log.AccessMessage`).
#[derive(Debug, Clone)]
pub struct AccessMessage {
    pub from: String,
    pub to: String,
    pub status: AccessStatus,
    pub reason: String,
    pub email: Option<String>,
    pub protocol: Option<String>,
    pub outbound_tag: Option<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessStatus {
    Accepted,
    Rejected,
    Dropped,
}

impl AccessStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AccessStatus::Accepted => "accepted",
            AccessStatus::Rejected => "rejected",
            AccessStatus::Dropped => "dropped",
        }
    }
}

/// General log message with severity.
#[derive(Debug, Clone)]
pub struct LogMessage {
    pub severity: Severity,
    pub message: String,
}

/// Log handler trait — can be implemented to route logs to files, syslog, etc.
pub trait LogHandler: Send + Sync {
    fn handle_access(&self, msg: &AccessMessage);
    fn handle_log(&self, msg: &LogMessage);
}

/// Default log handler that prints to stdout via tracing.
pub struct DefaultLogHandler;

impl LogHandler for DefaultLogHandler {
    fn handle_access(&self, msg: &AccessMessage) {
        tracing::info!(
            "[access] {} {} -> {} reason=\"{}\"",
            msg.status.as_str(), msg.from, msg.to, msg.reason
        );
    }

    fn handle_log(&self, msg: &LogMessage) {
        match msg.severity {
            Severity::Debug => tracing::debug!("{}", msg.message),
            Severity::Info => tracing::info!("{}", msg.message),
            Severity::Warning => tracing::warn!("{}", msg.message),
            Severity::Error => tracing::error!("{}", msg.message),
        }
    }
}

lazy_static::lazy_static! {
    static ref GLOBAL_HANDLER: std::sync::RwLock<Option<Arc<dyn LogHandler>>> =
        std::sync::RwLock::new(Some(Arc::new(DefaultLogHandler) as Arc<dyn LogHandler>));
}

/// Set the global log handler.
pub fn set_handler(handler: Arc<dyn LogHandler>) {
    *GLOBAL_HANDLER.write().unwrap() = Some(handler);
}

/// Log an access message.
pub fn access(msg: &AccessMessage) {
    if let Some(handler) = GLOBAL_HANDLER.read().unwrap().as_ref() {
        handler.handle_access(msg);
    }
}

/// Log a message with severity.
pub fn log(severity: Severity, message: &str) {
    if let Some(handler) = GLOBAL_HANDLER.read().unwrap().as_ref() {
        handler.handle_log(&LogMessage {
            severity,
            message: message.to_string(),
        });
    }
}

/// Convenience functions.
pub fn debug(msg: &str) { log(Severity::Debug, msg); }
pub fn info(msg: &str) { log(Severity::Info, msg); }
pub fn warn(msg: &str) { log(Severity::Warning, msg); }
pub fn error(msg: &str) { log(Severity::Error, msg); }

// ─── IP address masking (kept from original) ────────────────────────────────

/// Mask an IP address for logging.
pub fn mask_ip(ip: &str, mode: &str) -> String {
    match mode {
        "half" => {
            if let Some(pos) = ip.rfind('.') {
                let prefix = &ip[..pos];
                if let Some(dot) = prefix.rfind('.') {
                    format!("{}.xxx.xxx", &prefix[..dot])
                } else {
                    format!("{}.xxx", prefix)
                }
            } else if let Some(pos) = ip.rfind(':') {
                let prefix = &ip[..pos];
                if let Some(col) = prefix.rfind(':') {
                    format!("{}:xxxx:xxxx", &prefix[..col])
                } else {
                    format!("{}:xxxx", prefix)
                }
            } else { "xxx".into() }
        }
        "quarter" => {
            if let Some(pos) = ip.rfind('.') {
                format!("{}.xxx", &ip[..pos])
            } else if let Some(pos) = ip.rfind(':') {
                format!("{}:xxxx", &ip[..pos])
            } else { "xxx".into() }
        }
        "full" => "xxx".into(),
        _ => ip.to_string(),
    }
}

pub fn mask_ips_in_message(msg: &str, mode: &str) -> String {
    if mode.is_empty() || mode == "none" { return msg.to_string(); }
    let mut result = msg.to_string();
    let ip_re = regex_lite::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
    for ip in ip_re.find_iter(msg) {
        result = result.replace(ip.as_str(), &mask_ip(ip.as_str(), mode));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity() {
        assert_eq!(Severity::from_str("debug"), Severity::Debug);
        assert_eq!(Severity::from_str("INFO"), Severity::Info);
        assert_eq!(Severity::from_str("warn"), Severity::Warning);
    }

    #[test]
    fn test_access_message() {
        let msg = AccessMessage {
            from: "1.2.3.4:12345".into(),
            to: "5.6.7.8:443".into(),
            status: AccessStatus::Accepted,
            reason: "matched rule".into(),
            email: Some("user@test".into()),
            protocol: Some("vless".into()),
            outbound_tag: Some("proxy".into()),
            timestamp: 1234567890,
        };
        assert_eq!(msg.status.as_str(), "accepted");
        assert_eq!(msg.email.unwrap(), "user@test");
    }

    #[test]
    fn test_log_handler() {
        struct TestHandler {
            messages: std::sync::Mutex<Vec<String>>,
        }
        impl LogHandler for TestHandler {
            fn handle_access(&self, msg: &AccessMessage) {
                self.messages.lock().unwrap().push(format!("access: {}", msg.from));
            }
            fn handle_log(&self, msg: &LogMessage) {
                self.messages.lock().unwrap().push(format!("{}: {}", msg.severity.as_str(), msg.message));
            }
        }

        let handler = Arc::new(TestHandler { messages: std::sync::Mutex::new(Vec::new()) });
        let handler_clone = handler.clone();
        set_handler(handler_clone);

        info("test message");
        access(&AccessMessage {
            from: "1.2.3.4".into(), to: "5.6.7.8".into(),
            status: AccessStatus::Accepted, reason: "ok".into(),
            email: None, protocol: None, outbound_tag: None, timestamp: 0,
        });

        let msgs = handler.messages.lock().unwrap();
        assert_eq!(msgs.len(), 2);
        assert!(msgs[0].contains("Info: test"));
        assert!(msgs[1].contains("access: 1.2.3.4"));
    }

    #[test]
    fn test_mask_ip() {
        assert_eq!(mask_ip("1.2.3.4", ""), "1.2.3.4");
        assert_eq!(mask_ip("1.2.3.4", "quarter"), "1.2.3.xxx");
        assert_eq!(mask_ip("1.2.3.4", "half"), "1.2.xxx.xxx");
        assert_eq!(mask_ip("1.2.3.4", "full"), "xxx");
    }
}
