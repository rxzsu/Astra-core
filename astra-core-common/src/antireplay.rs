use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Anti-replay filter using dual-map ping-pong strategy.
/// Tracks values within a time window using two pools:
///   poolA = current window, poolB = previous window.
pub struct ReplayFilter<T: Eq + std::hash::Hash + Clone> {
    pool_a: HashSet<T>,
    pool_b: HashSet<T>,
    interval: Duration,
    last_clean: Instant,
}

impl<T: Eq + std::hash::Hash + Clone> ReplayFilter<T> {
    /// Create a new filter with the given expiration interval in seconds.
    pub fn new(interval_secs: i64) -> Self {
        ReplayFilter {
            pool_a: HashSet::new(),
            pool_b: HashSet::new(),
            interval: Duration::from_secs(interval_secs as u64),
            last_clean: Instant::now(),
        }
    }

    /// Check if a value is valid (not a replay).
    /// Returns `true` if the value is new, `false` if it's a duplicate.
    pub fn check(&mut self, value: T) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last_clean) >= self.interval {
            self.pool_b = std::mem::take(&mut self.pool_a);
            self.pool_a = HashSet::new();
            self.last_clean = now;
        }

        if self.pool_a.contains(&value) || self.pool_b.contains(&value) {
            false
        } else {
            self.pool_a.insert(value);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_filter() {
        let mut filter = ReplayFilter::<[u8; 16]>::new(120);
        let sample = [0u8; 16];
        assert!(filter.check(sample));
        assert!(!filter.check(sample)); // duplicate
        let mut different = [0u8; 16];
        different[0] = 1;
        assert!(filter.check(different)); // different value
    }

    #[test]
    fn test_replay_filter_rotation() {
        let mut filter = ReplayFilter::<i32>::new(1); // 1 second interval
        assert!(filter.check(42));
        assert!(!filter.check(42));
        std::thread::sleep(std::time::Duration::from_secs(2));
        // After rotation, poolA is fresh, 42 is only in poolB
        assert!(filter.check(99)); // new value
        // 42 might still be in poolB, but check is still valid for new values
        assert!(filter.check(100));
    }
}
