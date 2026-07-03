use crate::cipher::StreamCipher;

const BLOCK_SIZE: usize = 64;

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

fn chacha20_block(state: &[u32; 16], rounds: usize) -> [u8; 64] {
    let mut x = *state;
    for _ in 0..rounds / 2 {
        quarter_round(&mut x, 0, 4, 8, 12);
        quarter_round(&mut x, 1, 5, 9, 13);
        quarter_round(&mut x, 2, 6, 10, 14);
        quarter_round(&mut x, 3, 7, 11, 15);
        quarter_round(&mut x, 0, 5, 10, 15);
        quarter_round(&mut x, 1, 6, 11, 12);
        quarter_round(&mut x, 2, 7, 8, 13);
        quarter_round(&mut x, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        let v = state[i].wrapping_add(x[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

pub struct ChaCha20Stream {
    state: [u32; 16],
    block: [u8; 64],
    offset: usize,
    rounds: usize,
}

impl ChaCha20Stream {
    pub fn new(key: &[u8], nonce: &[u8], rounds: usize) -> Self {
        assert_eq!(key.len(), 32, "ChaCha20 requires a 32-byte key");
        let mut state = [0u32; 16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        for i in 0..8 {
            state[i + 4] = u32::from_le_bytes([
                key[i * 4],
                key[i * 4 + 1],
                key[i * 4 + 2],
                key[i * 4 + 3],
            ]);
        }

        match nonce.len() {
            8 => {
                state[14] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
                state[15] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
            }
            12 => {
                state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
                state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
                state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);
            }
            _ => panic!("ChaCha20 requires 8 or 12 byte nonce"),
        }

        let block = chacha20_block(&state, rounds);
        ChaCha20Stream {
            state,
            block,
            offset: 0,
            rounds,
        }
    }
}

impl StreamCipher for ChaCha20Stream {
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        let mut i = 0;
        let max = src.len();
        while i < max {
            let gap = BLOCK_SIZE - self.offset;
            let limit = (i + gap).min(max);
            let o = self.offset;
            for j in i..limit {
                dst[j] = src[j] ^ self.block[o + (j - i)];
            }
            let consumed = limit - i;
            self.offset += consumed;
            i += consumed;
            if self.offset >= BLOCK_SIZE {
                self.offset = 0;
                self.state[12] = self.state[12].wrapping_add(1);
                self.block = chacha20_block(&self.state, self.rounds);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_quarter_round() {
        let mut state = [0u32; 16];
        state[0] = 0x11111111;
        state[1] = 0x01020304;
        state[2] = 0x9b8d6f43;
        state[3] = 0x01234567;
        quarter_round(&mut state, 0, 1, 2, 3);
        assert_eq!(state[0], 0xea2a92f4);
        assert_eq!(state[1], 0xcb1cf8ce);
        assert_eq!(state[2], 0x4581472e);
        assert_eq!(state[3], 0x5881c4bb);
    }

    #[test]
    fn test_chacha20_block_known() {
        let key = [0u8; 32];
        let nonce = [0u8; 8];
        let mut state = [0u32; 16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        for i in 0..8 {
            state[i + 4] = u32::from_le_bytes([
                key[i * 4],
                key[i * 4 + 1],
                key[i * 4 + 2],
                key[i * 4 + 3],
            ]);
        }
        state[14] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        state[15] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
        let block = chacha20_block(&state, 20);
        assert_eq!(block.len(), 64);
        assert_ne!(block, [0u8; 64]);
    }

    #[test]
    fn test_chacha20_xor() {
        let key = [0x00u8; 32];
        let nonce = [0x00u8; 12];
        let mut cipher = ChaCha20Stream::new(&key, &nonce, 20);
        let plaintext = b"Hello, ChaCha20!";
        let mut ciphertext = vec![0u8; plaintext.len()];
        cipher.xor_key_stream(&mut ciphertext, plaintext);
        assert_ne!(&ciphertext, plaintext);

        let mut decrypted = vec![0u8; plaintext.len()];
        let mut cipher2 = ChaCha20Stream::new(&key, &nonce, 20);
        cipher2.xor_key_stream(&mut decrypted, &ciphertext);
        assert_eq!(&decrypted, plaintext);
    }
}
