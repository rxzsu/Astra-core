/// Byte-level bitmask operations.
/// Go equivalent: `common/bitmask`

/// Check if a specific bit is set in a byte.
pub fn has_bit(b: u8, bit: u8) -> bool {
    b & (1 << bit) != 0
}

/// Set a specific bit in a byte.
pub fn set_bit(b: &mut u8, bit: u8) {
    *b |= 1 << bit;
}

/// Clear a specific bit in a byte.
pub fn clear_bit(b: &mut u8, bit: u8) {
    *b &= !(1 << bit);
}

/// Toggle a specific bit in a byte.
pub fn toggle_bit(b: &mut u8, bit: u8) {
    *b ^= 1 << bit;
}

/// Byte mask for the lower N bits.
pub fn byte_mask(n: u8) -> u8 {
    if n >= 8 { 0xFF } else { (1 << n) - 1 }
}

/// Check if a byte has any of the given bits set.
pub fn has_any(b: u8, mask: u8) -> bool {
    b & mask != 0
}

/// Check if a byte has all of the given bits set.
pub fn has_all(b: u8, mask: u8) -> bool {
    b & mask == mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_ops() {
        let mut b = 0u8;
        set_bit(&mut b, 0);
        assert!(has_bit(b, 0));
        assert!(!has_bit(b, 1));
        clear_bit(&mut b, 0);
        assert!(!has_bit(b, 0));
    }

    #[test]
    fn test_toggle() {
        let mut b = 0u8;
        toggle_bit(&mut b, 2);
        assert!(has_bit(b, 2));
        toggle_bit(&mut b, 2);
        assert!(!has_bit(b, 2));
    }

    #[test]
    fn test_byte_mask() {
        assert_eq!(byte_mask(3), 0b0000_0111);
        assert_eq!(byte_mask(8), 0xFF);
    }

    #[test]
    fn test_has_any_all() {
        let b = 0b1010u8;
        assert!(has_any(b, 0b1000));
        assert!(!has_any(b, 0b0100));
        assert!(has_all(b, 0b1000));
        assert!(has_all(b, 0b1010));
        assert!(!has_all(b, 0b1111));
    }
}
