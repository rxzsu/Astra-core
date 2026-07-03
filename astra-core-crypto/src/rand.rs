use std::io::{self, Read};

#[cfg(not(target_os = "windows"))]
fn csprng_bytes() -> impl Read {
    use std::fs::File;
    File::open("/dev/urandom").expect("failed to open /dev/urandom")
}

#[cfg(target_os = "windows")]
fn csprng_bytes() -> impl Read {
    struct WindowsRand;
    impl Read for WindowsRand {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            rand_polyfill(buf);
            Ok(buf.len())
        }
    }
    WindowsRand
}

fn rand_polyfill(buf: &mut [u8]) {
    // Simple LCG-based fallback — do NOT use for real crypto without a proper CSPRNG.
    // In production this would use rustc's RDRAND or a proper crate.
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let mut state = seed;
    for chunk in buf.chunks_mut(8) {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let bytes = state.to_le_bytes();
        let n = chunk.len().min(8);
        chunk.copy_from_slice(&bytes[..n]);
    }
}

pub fn rand_bytes(buf: &mut [u8]) {
    let mut rng = csprng_bytes();
    rng.read_exact(buf).unwrap_or_else(|_| rand_polyfill(buf));
}

pub fn rand_between(from: i64, to: i64) -> i64 {
    if from == to {
        return from;
    }
    let (lo, hi) = if from > to { (to, from) } else { (from, to) };
    let range = (hi - lo) as u64;
    let mut buf = [0u8; 8];
    rand_bytes(&mut buf);
    let val = u64::from_le_bytes(buf) % range;
    lo + val as i64
}

pub fn rand_bytes_between(buf: &mut [u8], from: u8, to: u8) {
    rand_bytes(buf);
    let (lo, hi) = if from > to { (to, from) } else { (from, to) };
    if hi.wrapping_sub(lo) == 255 {
        return;
    }
    let range = (hi - lo + 1) as u16;
    for b in buf.iter_mut() {
        *b = lo + (*b as u16 % range) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rand_between() {
        for _ in 0..100 {
            let v = rand_between(5, 10);
            assert!((5..=10).contains(&v), "{} not in [5,10]", v);
        }
        assert_eq!(rand_between(7, 7), 7);
        // rand_between(lo, hi) where lo > hi should be same distribution as reversed
        let a = rand_between(10, 5);
        assert!((5..=10).contains(&a));
    }

    #[test]
    fn test_rand_bytes_between() {
        let mut buf = [0u8; 1000];
        rand_bytes_between(&mut buf, 32, 126);
        for &b in &buf {
            assert!((32..=126).contains(&b));
        }
    }

    #[test]
    fn test_rand_bytes_not_zero() {
        let mut buf = [0u8; 256];
        rand_bytes(&mut buf);
        assert!(buf.iter().any(|&b| b != 0), "random bytes should not be all zero");
    }
}
