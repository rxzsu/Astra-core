use rand::RngExt;

pub fn rand_bytes(buf: &mut [u8]) {
    rand::rng().fill(buf);
}

pub fn rand_between(from: i64, to: i64) -> i64 {
    if from == to {
        return from;
    }
    let (lo, hi) = if from > to { (to, from) } else { (from, to) };
    rand::rng().random_range(lo..=hi)
}

pub fn rand_bytes_between(buf: &mut [u8], from: u8, to: u8) {
    rand::rng().fill(buf);
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
        assert!(buf.iter().any(|&b| b != 0));
    }
}
