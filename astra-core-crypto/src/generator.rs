pub trait BytesGenerator: Send {
    fn generate(&mut self) -> Vec<u8>;
}

pub struct EmptyBytesGenerator;

impl BytesGenerator for EmptyBytesGenerator {
    fn generate(&mut self) -> Vec<u8> {
        Vec::new()
    }
}

pub struct StaticBytesGenerator {
    content: Vec<u8>,
}

impl StaticBytesGenerator {
    pub fn new(content: Vec<u8>) -> Self {
        StaticBytesGenerator { content }
    }
}

impl BytesGenerator for StaticBytesGenerator {
    fn generate(&mut self) -> Vec<u8> {
        self.content.clone()
    }
}

pub struct IncreasingNonceGenerator {
    nonce: Vec<u8>,
}

impl IncreasingNonceGenerator {
    pub fn new(nonce: Vec<u8>) -> Self {
        IncreasingNonceGenerator { nonce }
    }
}

impl BytesGenerator for IncreasingNonceGenerator {
    fn generate(&mut self) -> Vec<u8> {
        for b in self.nonce.iter_mut() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        self.nonce.clone()
    }
}

pub fn aead_nonce_generator(nonce_size: usize) -> impl BytesGenerator {
    let mut c = vec![0u8; nonce_size];
    for b in c.iter_mut() {
        *b = 0xFF;
    }
    IncreasingNonceGenerator::new(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_generator() {
        let mut g = EmptyBytesGenerator;
        assert!(g.generate().is_empty());
    }

    #[test]
    fn test_static_generator() {
        let mut g = StaticBytesGenerator::new(b"hello".to_vec());
        assert_eq!(g.generate(), b"hello");
    }

    #[test]
    fn test_increasing_nonce() {
        let mut g = IncreasingNonceGenerator::new(vec![0x00, 0x00]);
        let a = g.generate();
        let b = g.generate();
        let c = g.generate();
        assert_eq!(a, vec![0x01, 0x00]);
        assert_eq!(b, vec![0x02, 0x00]);
        assert_eq!(c, vec![0x03, 0x00]);
    }

    #[test]
    fn test_aead_nonce() {
        let mut g = aead_nonce_generator(12);
        let a = g.generate();
        let b = g.generate();
        assert_eq!(a.len(), 12);
        assert!(a != b);
        // a starts as all 0xFF incremented -> [0x00, 0x00, ..., 0x00] with carry
        // b is incremented again
        assert_eq!(a, vec![0x00; 12]);
        assert_eq!(
            b,
            vec![
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
    }
}
