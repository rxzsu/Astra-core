use std::fmt;

/// Error severity levels matching Go's `common/errors.Severity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Debug,
    Info,
    Warning,
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Debug => write!(f, "Debug"),
            Severity::Info => write!(f, "Info"),
            Severity::Warning => write!(f, "Warning"),
            Severity::Error => write!(f, "Error"),
        }
    }
}

/// Xray-style error with severity and chaining.
/// Go equivalent: `common/errors.Error` with `.Base()`, `.AtWarning()`, etc.
#[derive(Debug)]
pub struct XrayError {
    message: String,
    severity: Severity,
    cause: Option<Box<XrayError>>,
}

impl XrayError {
    pub fn new(message: impl Into<String>) -> Self {
        XrayError {
            message: message.into(),
            severity: Severity::Error,
            cause: None,
        }
    }

    pub fn at_warning(mut self) -> Self {
        self.severity = Severity::Warning;
        self
    }

    pub fn at_info(mut self) -> Self {
        self.severity = Severity::Info;
        self
    }

    pub fn at_debug(mut self) -> Self {
        self.severity = Severity::Debug;
        self
    }

    pub fn base(mut self, cause: XrayError) -> Self {
        self.cause = Some(Box::new(cause));
        self
    }

    pub fn severity(&self) -> Severity {
        self.severity
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    /// Format error chain: "message: caused by: inner"
    pub fn full_message(&self) -> String {
        match &self.cause {
            Some(cause) => format!("{}: {}", self.message, cause.full_message()),
            None => self.message.clone(),
        }
    }
}

impl fmt::Display for XrayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.severity, self.full_message())
    }
}

impl std::error::Error for XrayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .as_ref()
            .map(|c| c.as_ref() as &(dyn std::error::Error + 'static))
    }
}

/// Combine multiple errors into one.
pub fn combine(errors: Vec<XrayError>) -> XrayError {
    let mut iter = errors.into_iter();
    let first = iter
        .next()
        .unwrap_or_else(|| XrayError::new("unknown error"));
    iter.fold(first, |acc, e| acc.base(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_severity() {
        let err = XrayError::new("test error").at_warning();
        assert_eq!(err.severity(), Severity::Warning);
    }

    #[test]
    fn test_error_chaining() {
        let inner = XrayError::new("inner error").at_debug();
        let outer = XrayError::new("outer error").base(inner);
        assert_eq!(outer.full_message(), "outer error: inner error");
    }

    #[test]
    fn test_combine_errors() {
        let errs = vec![XrayError::new("err1"), XrayError::new("err2")];
        let combined = combine(errs);
        assert!(combined.full_message().contains("err1"));
    }
}
