use std::time::Duration;

/// Error returned when all retry attempts failed.
#[derive(Debug)]
pub struct RetryError {
    pub errors: Vec<String>,
}

impl std::fmt::Display for RetryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "all retry attempts failed: {:?}", self.errors)
    }
}

impl std::error::Error for RetryError {}

/// Retry strategy.
pub trait Strategy {
    /// Execute the given function with retries.
    fn on(&self, method: &mut dyn FnMut() -> Result<(), String>) -> Result<(), RetryError>;
}

/// Retry with a fixed interval between attempts.
pub fn timed(attempts: usize, delay_ms: u64) -> impl Strategy {
    FixedDelayRetry {
        total_attempts: attempts,
        delay_ms,
    }
}

/// Retry with exponential backoff.
pub fn exponential_backoff(attempts: usize, delay_ms: u64) -> impl Strategy {
    ExponentialBackoffRetry {
        total_attempts: attempts,
        base_delay_ms: delay_ms,
    }
}

struct FixedDelayRetry {
    total_attempts: usize,
    delay_ms: u64,
}

impl Strategy for FixedDelayRetry {
    fn on(&self, method: &mut dyn FnMut() -> Result<(), String>) -> Result<(), RetryError> {
        let mut errors = Vec::new();
        for _ in 0..self.total_attempts {
            match method() {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let last = errors.last().map(|s: &String| s.as_str());
                    if last != Some(&e) {
                        errors.push(e);
                    }
                    std::thread::sleep(Duration::from_millis(self.delay_ms));
                }
            }
        }
        Err(RetryError { errors })
    }
}

struct ExponentialBackoffRetry {
    total_attempts: usize,
    base_delay_ms: u64,
}

impl Strategy for ExponentialBackoffRetry {
    fn on(&self, method: &mut dyn FnMut() -> Result<(), String>) -> Result<(), RetryError> {
        let mut errors = Vec::new();
        let mut delay = 0u64;
        for _ in 0..self.total_attempts {
            if delay > 0 {
                std::thread::sleep(Duration::from_millis(delay));
            }
            match method() {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let last = errors.last().map(|s: &String| s.as_str());
                    if last != Some(&e) {
                        errors.push(e);
                    }
                    delay += self.base_delay_ms;
                }
            }
        }
        Err(RetryError { errors })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timed_retry_success() {
        let mut count = 0;
        let result = timed(3, 1).on(&mut || {
            count += 1;
            if count < 2 {
                Err("not yet".into())
            } else {
                Ok(())
            }
        });
        assert!(result.is_ok());
        assert_eq!(count, 2);
    }

    #[test]
    fn test_timed_retry_failure() {
        let result = timed(2, 1).on(&mut || Err("always fail".into()));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().errors.len(), 1);
    }

    #[test]
    fn test_exponential_backoff() {
        let mut count = 0;
        let result = exponential_backoff(3, 1).on(&mut || {
            count += 1;
            if count < 3 {
                Err(format!("attempt {}", count))
            } else {
                Ok(())
            }
        });
        assert!(result.is_ok());
        assert_eq!(count, 3);
    }
}
