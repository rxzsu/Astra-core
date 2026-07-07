use std::io::Read;

/// Drainer interface for draining connection data after protocol detection failure.
pub trait Drainer: Send + Sync {
    fn acknowledge_receive(&mut self, size: usize);
    fn drain(&mut self, reader: &mut dyn Read) -> Result<(), String>;
}

/// BehaviorSeedLimitedDrainer drains a fixed number of bytes determined by a seed.
/// Used for traffic obfuscation — after detecting a non-matching protocol,
/// drain a predictable amount of data before closing.
pub struct BehaviorSeedLimitedDrainer {
    drain_size: i32,
}

impl BehaviorSeedLimitedDrainer {
    /// Create a new drainer with the given parameters.
    /// - behavior_seed: seed for deterministic drain size
    /// - drain_foundation: base drain amount
    /// - max_base_drain_size: max additional base drain
    /// - max_rand_drain: max random additional drain
    pub fn new(
        behavior_seed: i64,
        drain_foundation: i32,
        max_base_drain_size: i32,
        max_rand_drain: i32,
    ) -> Self {
        let base_drain = if max_base_drain_size > 0 {
            (behavior_seed % max_base_drain_size as i64) as i32
        } else {
            0
        };
        let rand_drain_max = if max_rand_drain > 0 {
            (behavior_seed % max_rand_drain as i64) as i32 + 1
        } else {
            1
        };
        let rand_rolled = if rand_drain_max > 0 {
            rand::random::<i32>().abs() % rand_drain_max
        } else {
            0
        };
        let drain_size = drain_foundation + base_drain + rand_rolled;
        BehaviorSeedLimitedDrainer { drain_size }
    }
}

impl Drainer for BehaviorSeedLimitedDrainer {
    fn acknowledge_receive(&mut self, size: usize) {
        self.drain_size -= size as i32;
    }

    fn drain(&mut self, reader: &mut dyn Read) -> Result<(), String> {
        if self.drain_size > 0 {
            let mut buf = vec![0u8; self.drain_size as usize];
            match reader.read_exact(&mut buf) {
                Ok(_) => Err("drained connection".to_string()),
                Err(e) => Err(format!("unable to drain connection: {}", e)),
            }
        } else {
            Ok(())
        }
    }
}

/// A no-op drainer that does nothing.
pub struct NopDrainer;

impl Drainer for NopDrainer {
    fn acknowledge_receive(&mut self, _size: usize) {}
    fn drain(&mut self, _reader: &mut dyn Read) -> Result<(), String> {
        Ok(())
    }
}

/// Helper to drain and wrap an error.
pub fn with_error(drainer: &mut dyn Drainer, reader: &mut dyn Read, err: String) -> String {
    match drainer.drain(reader) {
        Ok(()) => err,
        Err(drain_err) => format!("{} (drain: {})", err, drain_err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_nop_drainer() {
        let mut d = NopDrainer;
        assert!(d.drain(&mut Cursor::new(vec![])).is_ok());
    }

    #[test]
    fn test_behavior_seed_drainer() {
        let mut d = BehaviorSeedLimitedDrainer::new(42, 10, 20, 5);
        assert!(d.drain_size > 0);
        let data = vec![0u8; d.drain_size as usize + 10];
        let mut cursor = Cursor::new(data);
        let result = d.drain(&mut cursor);
        assert!(result.is_err()); // "drained connection"
        assert!(result.unwrap_err().contains("drained"));
    }

    #[test]
    fn test_with_error() {
        let mut d = NopDrainer;
        let err = with_error(&mut d, &mut Cursor::new(vec![]), "original error".into());
        assert_eq!(err, "original error");
    }
}
