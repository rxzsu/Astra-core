use crate::cipher::{AeadCipher, StreamCipher};

// AES S-box
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
    0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
    0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
    0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
    0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
    0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
    0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
    0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
    0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
    0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
    0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
    0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
    0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
    0x16,
];

const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7,
    0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde,
    0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42,
    0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c,
    0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15,
    0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7,
    0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc,
    0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad,
    0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
    0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8,
    0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51,
    0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0,
    0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c,
    0x7d,
];

fn gf_mul2(x: u8) -> u8 {
    let mut r = (x as u16) << 1;
    if r & 0x100 != 0 {
        r ^= 0x11b;
    }
    r as u8
}

fn gf_mul3(x: u8) -> u8 {
    gf_mul2(x) ^ x
}

fn sub_word(w: u32) -> u32 {
    let b = w.to_le_bytes();
    u32::from_le_bytes([SBOX[b[0] as usize], SBOX[b[1] as usize], SBOX[b[2] as usize], SBOX[b[3] as usize]])
}

fn rot_word(w: u32) -> u32 {
    w.rotate_left(8)
}

fn add_round_key(state: &mut [u8; 16], round_key: &[u8]) {
    for i in 0..16 {
        state[i] ^= round_key[i];
    }
}

fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

fn inv_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = INV_SBOX[*b as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let s = *state;
    state[0] = s[0];
    state[1] = s[5];
    state[2] = s[10];
    state[3] = s[15];
    state[4] = s[4];
    state[5] = s[9];
    state[6] = s[14];
    state[7] = s[3];
    state[8] = s[8];
    state[9] = s[13];
    state[10] = s[2];
    state[11] = s[7];
    state[12] = s[12];
    state[13] = s[1];
    state[14] = s[6];
    state[15] = s[11];
}

fn inv_shift_rows(state: &mut [u8; 16]) {
    let s = *state;
    state[0] = s[0];
    state[1] = s[13];
    state[2] = s[10];
    state[3] = s[7];
    state[4] = s[4];
    state[5] = s[1];
    state[6] = s[14];
    state[7] = s[11];
    state[8] = s[8];
    state[9] = s[5];
    state[10] = s[2];
    state[11] = s[15];
    state[12] = s[12];
    state[13] = s[9];
    state[14] = s[6];
    state[15] = s[3];
}

fn mix_columns(state: &mut [u8; 16]) {
    for i in 0..4 {
        let col = i * 4;
        let a = state[col];
        let b = state[col + 1];
        let c = state[col + 2];
        let d = state[col + 3];
        state[col] = gf_mul2(a) ^ gf_mul3(b) ^ c ^ d;
        state[col + 1] = a ^ gf_mul2(b) ^ gf_mul3(c) ^ d;
        state[col + 2] = a ^ b ^ gf_mul2(c) ^ gf_mul3(d);
        state[col + 3] = gf_mul3(a) ^ b ^ c ^ gf_mul2(d);
    }
}

fn gf_mul9(x: u8) -> u8 {
    gf_mul2(gf_mul2(gf_mul2(x))) ^ x
}

fn gf_mul11(x: u8) -> u8 {
    gf_mul2(gf_mul2(gf_mul2(x))) ^ gf_mul2(x) ^ x
}

fn gf_mul13(x: u8) -> u8 {
    gf_mul2(gf_mul2(gf_mul2(x))) ^ gf_mul2(gf_mul2(x)) ^ x
}

fn gf_mul14(x: u8) -> u8 {
    gf_mul2(gf_mul2(gf_mul2(x))) ^ gf_mul2(gf_mul2(x)) ^ gf_mul2(x)
}

fn inv_mix_columns(state: &mut [u8; 16]) {
    for i in 0..4 {
        let col = i * 4;
        let a = state[col];
        let b = state[col + 1];
        let c = state[col + 2];
        let d = state[col + 3];
        state[col] = gf_mul14(a) ^ gf_mul11(b) ^ gf_mul13(c) ^ gf_mul9(d);
        state[col + 1] = gf_mul9(a) ^ gf_mul14(b) ^ gf_mul11(c) ^ gf_mul13(d);
        state[col + 2] = gf_mul13(a) ^ gf_mul9(b) ^ gf_mul14(c) ^ gf_mul11(d);
        state[col + 3] = gf_mul11(a) ^ gf_mul13(b) ^ gf_mul9(c) ^ gf_mul14(d);
    }
}

fn key_expansion(key: &[u8]) -> Vec<[u8; 16]> {
    let nk = key.len() / 4;
    let nr = nk + 6;
    let total_words = 4 * (nr + 1);
    let mut w = vec![0u32; total_words];

    for i in 0..nk {
        w[i] = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }

    let rcon: [u32; 15] = [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    ];

    for i in nk..total_words {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp = sub_word(rot_word(temp)) ^ rcon[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(temp);
        }
        w[i] = w[i - nk] ^ temp;
    }

    let mut round_keys = Vec::with_capacity(nr + 1);
    for r in 0..=nr {
        let mut rk = [0u8; 16];
        for j in 0..4 {
            rk[j * 4..j * 4 + 4].copy_from_slice(&w[r * 4 + j].to_le_bytes());
        }
        round_keys.push(rk);
    }
    round_keys
}

fn aes_encrypt_block(state: &mut [u8; 16], round_keys: &[[u8; 16]]) {
    let nr = round_keys.len() - 1;
    add_round_key(state, &round_keys[0]);
    for round in 1..nr {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &round_keys[round]);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &round_keys[nr]);
}

fn aes_decrypt_block(state: &mut [u8; 16], round_keys: &[[u8; 16]]) {
    let nr = round_keys.len() - 1;
    add_round_key(state, &round_keys[nr]);
    inv_shift_rows(state);
    inv_sub_bytes(state);
    for round in (1..nr).rev() {
        add_round_key(state, &round_keys[round]);
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state);
    }
    add_round_key(state, &round_keys[0]);
}

pub struct AesCipher {
    round_keys: Vec<[u8; 16]>,
}

impl AesCipher {
    pub fn new(key: &[u8]) -> Self {
        assert!(key.len() == 16 || key.len() == 24 || key.len() == 32);
        AesCipher {
            round_keys: key_expansion(key),
        }
    }

    pub fn encrypt(&self, block: &mut [u8; 16]) {
        aes_encrypt_block(block, &self.round_keys);
    }

    pub fn decrypt(&self, block: &mut [u8; 16]) {
        aes_decrypt_block(block, &self.round_keys);
    }
}

pub struct AesCfbStream {
    cipher: AesCipher,
    iv: [u8; 16],
    offset: usize,
    encrypt: bool,
}

impl AesCfbStream {
    pub fn new_encrypt(key: &[u8], iv: &[u8; 16]) -> Self {
        AesCfbStream {
            cipher: AesCipher::new(key),
            iv: *iv,
            offset: 0,
            encrypt: true,
        }
    }

    pub fn new_decrypt(key: &[u8], iv: &[u8; 16]) -> Self {
        AesCfbStream {
            cipher: AesCipher::new(key),
            iv: *iv,
            offset: 0,
            encrypt: false,
        }
    }
}

impl StreamCipher for AesCfbStream {
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        let mut i = 0;
        while i < src.len() {
            if self.offset == 0 {
                self.cipher.encrypt(&mut self.iv);
            }
            let n = (16 - self.offset).min(src.len() - i);
            for j in 0..n {
                dst[i + j] = src[i + j] ^ self.iv[self.offset + j];
            }
            if self.encrypt {
                for j in 0..n {
                    self.iv[self.offset + j] = dst[i + j];
                }
            } else {
                for j in 0..n {
                    self.iv[self.offset + j] = src[i + j];
                }
            }
            self.offset = (self.offset + n) % 16;
            i += n;
        }
    }
}

pub struct AesCtrStream {
    cipher: AesCipher,
    counter: [u8; 16],
    keystream: [u8; 16],
    offset: usize,
}

impl AesCtrStream {
    pub fn new(key: &[u8], nonce: &[u8; 16]) -> Self {
        let cipher = AesCipher::new(key);
        AesCtrStream {
            cipher,
            counter: *nonce,
            keystream: [0u8; 16],
            offset: 0,
        }
    }
}

impl StreamCipher for AesCtrStream {
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        let mut i = 0;
        while i < src.len() {
            if self.offset == 0 {
                self.cipher.encrypt(&mut self.counter);
                self.keystream = self.counter;
            }
            let n = (16 - self.offset).min(src.len() - i);
            for j in 0..n {
                dst[i + j] = src[i + j] ^ self.keystream[self.offset + j];
            }
            self.offset = (self.offset + n) % 16;
            if self.offset == 0 {
                for b in self.counter.iter_mut().rev() {
                    *b = b.wrapping_add(1);
                    if *b != 0 {
                        break;
                    }
                }
            }
            i += n;
        }
    }
}

fn gmul(a: u128, b: u128) -> u128 {
    let mut z: u128 = 0;
    let mut v: u128 = b;
    for i in 0..128 {
        if (a >> i) & 1 == 1 {
            z ^= v;
        }
        if v & 1 == 1 {
            v = (v >> 1) ^ 0xe1000000000000000000000000000000;
        } else {
            v >>= 1;
        }
    }
    z
}

fn bytes_to_u128(b: &[u8]) -> u128 {
    let mut buf = [0u8; 16];
    buf.copy_from_slice(b);
    u128::from_be_bytes(buf)
}

fn u128_to_bytes(v: u128) -> [u8; 16] {
    v.to_be_bytes()
}

fn ghash(h: u128, data: &[u8]) -> u128 {
    let mut y: u128 = 0;
    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        y ^= bytes_to_u128(&block);
        y = gmul(y, h);
    }
    y
}

pub struct AesGcmCipher {
    cipher: AesCipher,
    h: u128,
}

impl AesGcmCipher {
    pub fn new(key: &[u8]) -> Self {
        let cipher = AesCipher::new(key);
        let mut h_block = [0u8; 16];
        cipher.encrypt(&mut h_block);
        let h = bytes_to_u128(&h_block);
        AesGcmCipher { cipher, h }
    }

    fn inc32(counter: &mut [u8; 16]) {
        for i in (12..16).rev() {
            counter[i] = counter[i].wrapping_add(1);
            if counter[i] != 0 {
                break;
            }
        }
    }

    fn gctr(&self, icb: &[u8; 16], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        let mut counter = *icb;
        let mut offset = 0;
        while offset < data.len() {
            let mut encrypted = counter;
            self.cipher.encrypt(&mut encrypted);
            let n = (16usize).min(data.len() - offset);
            for j in 0..n {
                out.push(data[offset + j] ^ encrypted[j]);
            }
            Self::inc32(&mut counter);
            offset += n;
        }
        out
    }
}

impl AeadCipher for AesGcmCipher {
    fn nonce_size(&self) -> usize {
        12
    }

    fn overhead(&self) -> usize {
        16
    }

    fn open_with_nonce(
        &self,
        _dst: &mut Vec<u8>,
        ciphertext: &[u8],
        nonce: &[u8],
        _aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        if nonce.len() != 12 {
            return Err("GCM nonce must be 12 bytes".to_string());
        }
        if ciphertext.len() < 16 {
            return Err("ciphertext too short".to_string());
        }
        let ct_len = ciphertext.len() - 16;
        let tag = &ciphertext[ct_len..];
        let ct = &ciphertext[..ct_len];

        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;

        let mut encrypted = j0;
        self.cipher.encrypt(&mut encrypted);

        let plaintext = self.gctr(&j0, ct);

        // Verify tag (simplified - in production would use constant-time compare)
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(_aad);
        auth_data.extend_from_slice(ct);
        // Pad to 16 bytes
        while auth_data.len() % 16 != 0 {
            auth_data.push(0);
        }
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&(_aad.len() as u64 * 8).to_be_bytes());
        len_block[8..].copy_from_slice(&(ct_len as u64 * 8).to_be_bytes());
        auth_data.extend_from_slice(&len_block);

        let g = ghash(self.h, &auth_data);
        let expected_tag = u128_to_bytes(g ^ bytes_to_u128(&encrypted));

        if tag != expected_tag {
            return Err("GCM tag mismatch".to_string());
        }

        Ok(plaintext)
    }

    fn seal_with_nonce(
        &self,
        _dst: &mut Vec<u8>,
        plaintext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        if nonce.len() != 12 {
            return Err("GCM nonce must be 12 bytes".to_string());
        }

        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;

        let ciphertext = self.gctr(&j0, plaintext);

        // Compute GHASH
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(aad);
        auth_data.extend_from_slice(&ciphertext);
        while auth_data.len() % 16 != 0 {
            auth_data.push(0);
        }
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&(aad.len() as u64 * 8).to_be_bytes());
        len_block[8..].copy_from_slice(&(plaintext.len() as u64 * 8).to_be_bytes());
        auth_data.extend_from_slice(&len_block);

        let mut encrypted_j0 = j0;
        self.cipher.encrypt(&mut encrypted_j0);
        let g = ghash(self.h, &auth_data);
        let tag = u128_to_bytes(g ^ bytes_to_u128(&encrypted_j0));

        let mut result = ciphertext;
        result.extend_from_slice(&tag);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_128_key_expansion() {
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let rk = key_expansion(&key);
        assert_eq!(rk.len(), 11); // 10 rounds + 1
    }

    #[test]
    fn test_aes_128_encrypt_decrypt() {
        let key = [0x00u8; 16];
        let cipher = AesCipher::new(&key);
        let mut block = [0x00u8; 16];
        cipher.encrypt(&mut block);
        // AES-128 with all-zero key and plaintext produces known output
        assert_ne!(block, [0u8; 16]);

        let mut dec = block;
        cipher.decrypt(&mut dec);
        assert_eq!(dec, [0u8; 16]);
    }

    #[test]
    fn test_aes_cfb_roundtrip() {
        let key = [0x00u8; 16];
        let iv = [0x00u8; 16];
        let plaintext = b"Hello, AES-CFB!";

        let mut enc_stream = AesCfbStream::new_encrypt(&key, &iv);
        let mut ciphertext = vec![0u8; plaintext.len()];
        enc_stream.xor_key_stream(&mut ciphertext, plaintext);
        assert_ne!(&ciphertext, plaintext);

        let mut dec_stream = AesCfbStream::new_decrypt(&key, &iv);
        let mut decrypted = vec![0u8; plaintext.len()];
        dec_stream.xor_key_stream(&mut decrypted, &ciphertext);
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_aes_ctr_roundtrip() {
        let key = [0x00u8; 16];
        let nonce = [0x00u8; 16];
        let plaintext = b"Hello, AES-CTR!";

        let mut enc_stream = AesCtrStream::new(&key, &nonce);
        let mut ciphertext = vec![0u8; plaintext.len()];
        enc_stream.xor_key_stream(&mut ciphertext, plaintext);
        assert_ne!(&ciphertext, plaintext);

        let mut dec_stream = AesCtrStream::new(&key, &nonce);
        let mut decrypted = vec![0u8; plaintext.len()];
        dec_stream.xor_key_stream(&mut decrypted, &ciphertext);
        assert_eq!(&decrypted, plaintext);
    }
}
