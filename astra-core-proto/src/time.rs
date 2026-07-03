use std::time::{SystemTime, UNIX_EPOCH};

/// Timestamp type (Unix seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub i64);

impl Timestamp {
    pub fn as_i64(self) -> i64 {
        self.0
    }

    pub fn from_i64(v: i64) -> Self {
        Timestamp(v)
    }
}

/// A function that generates timestamps.
pub type TimestampGenerator = Box<dyn Fn() -> Timestamp>;

/// Returns the current Unix timestamp.
pub fn now_time() -> Timestamp {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp(dur.as_secs() as i64)
}

/// Creates a timestamp generator with jitter: generates timestamps
/// starting from `base`, incrementing by a random offset within `[-delta, +delta]`.
pub fn new_timestamp_generator(base: Timestamp, delta: i64) -> TimestampGenerator {
    Box::new(move || {
        let offset = if delta > 0 {
            // simple pseudo-random offset: use time-based seed
            let seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as i64;
            (seed % (2 * delta + 1)) - delta
        } else {
            0
        };
        Timestamp(base.0 + offset)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_now_time() {
        let t = now_time();
        // Unix timestamp should be > 0 (year 2000+)
        assert!(t.0 > 946684800);
    }

    #[test]
    fn test_timestamp_generator_no_delta() {
        let generator = new_timestamp_generator(Timestamp(1000), 0);
        let t = generator();
        assert_eq!(t.0, 1000);
    }

    #[test]
    fn test_timestamp_generator_with_delta() {
        let generator = new_timestamp_generator(Timestamp(1000), 10);
        let t = generator();
        // Should be within [990, 1010]
        assert!(t.0 >= 990 && t.0 <= 1010);
    }

    #[test]
    fn test_timestamp_roundtrip() {
        let t = Timestamp(42);
        assert_eq!(Timestamp::from_i64(t.as_i64()), t);
    }
}
