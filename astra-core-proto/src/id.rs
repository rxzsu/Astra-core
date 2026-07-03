use core::fmt;

/// UUID (16 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UUID(pub [u8; 16]);

/// ID with an embedded command key (MD5-based). Mirrors go's `protocol.ID`.
#[derive(Clone, Copy)]
pub struct ID {
    uuid: UUID,
    cmd_key: [u8; ID_BYTES_LEN],
}

pub const ID_BYTES_LEN: usize = 16;

/// UUID namespace used for command key derivation.
const UUID_CMD_KEY_SALT: &[u8; 36] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

impl ID {
    pub fn new(uuid: UUID) -> Self {
        let mut input = Vec::with_capacity(16 + 36);
        input.extend_from_slice(&uuid.0);
        input.extend_from_slice(UUID_CMD_KEY_SALT);
        let digest = md5(&input);
        let mut cmd_key = [0u8; ID_BYTES_LEN];
        cmd_key.copy_from_slice(&digest[..ID_BYTES_LEN]);
        ID { uuid, cmd_key }
    }

    pub fn uuid(&self) -> UUID {
        self.uuid
    }

    pub fn cmd_key(&self) -> &[u8; ID_BYTES_LEN] {
        &self.cmd_key
    }

    pub fn bytes(&self) -> [u8; 16] {
        self.uuid.0
    }

    pub fn equals(&self, other: &ID) -> bool {
        self.uuid == other.uuid
    }
}

impl fmt::Debug for ID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ID({})", self.uuid)
    }
}

impl fmt::Display for ID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.uuid)
    }
}

impl fmt::Display for UUID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3],
            b[4], b[5],
            b[6], b[7],
            b[8], b[9],
            b[10], b[11], b[12], b[13], b[14], b[15],
        )
    }
}

// ── Minimal MD5 implementation (RFC 1321) ──────────────────────────

fn md5(input: &[u8]) -> [u8; 16] {
    let padded = pad(input);
    let mut a: u32 = 0x67452301;
    let mut b: u32 = 0xefcdab89;
    let mut c: u32 = 0x98badcfe;
    let mut d: u32 = 0x10325476;

    for chunk in padded.chunks_exact(64) {
        let mut x = [0u32; 16];
        for (i, w) in x.iter_mut().enumerate() {
            let off = i * 4;
            *w = u32::from_le_bytes([chunk[off], chunk[off + 1], chunk[off + 2], chunk[off + 3]]);
        }

        let (mut aa, mut bb, mut cc, mut dd) = (a, b, c, d);

        // Round 1
        for (i, k, s) in &round1 {
            let f = (bb & cc) | (!bb & dd);
            let g = k;
            aa = bb.wrapping_add((aa.wrapping_add(f).wrapping_add(x[*g as usize]).wrapping_add(T[*i])) << s | (aa.wrapping_add(f).wrapping_add(x[*g as usize]).wrapping_add(T[*i])) >> (32 - s));
            let tmp = dd; dd = cc; cc = bb; bb = aa; aa = tmp;
        }

        // Round 2
        for (i, k, s) in &round2 {
            let f = (bb & dd) | (cc & !dd);
            let g = k;
            aa = bb.wrapping_add((aa.wrapping_add(f).wrapping_add(x[*g as usize]).wrapping_add(T[*i])) << s | (aa.wrapping_add(f).wrapping_add(x[*g as usize]).wrapping_add(T[*i])) >> (32 - s));
            let tmp = dd; dd = cc; cc = bb; bb = aa; aa = tmp;
        }

        // Round 3
        for (i, k, s) in &round3 {
            let f = bb ^ cc ^ dd;
            let g = k;
            aa = bb.wrapping_add((aa.wrapping_add(f).wrapping_add(x[*g as usize]).wrapping_add(T[*i])) << s | (aa.wrapping_add(f).wrapping_add(x[*g as usize]).wrapping_add(T[*i])) >> (32 - s));
            let tmp = dd; dd = cc; cc = bb; bb = aa; aa = tmp;
        }

        // Round 4
        for (i, k, s) in &round4 {
            let f = cc ^ (bb | !dd);
            let g = k;
            aa = bb.wrapping_add((aa.wrapping_add(f).wrapping_add(x[*g as usize]).wrapping_add(T[*i])) << s | (aa.wrapping_add(f).wrapping_add(x[*g as usize]).wrapping_add(T[*i])) >> (32 - s));
            let tmp = dd; dd = cc; cc = bb; bb = aa; aa = tmp;
        }

        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a.to_le_bytes());
    out[4..8].copy_from_slice(&b.to_le_bytes());
    out[8..12].copy_from_slice(&c.to_le_bytes());
    out[12..16].copy_from_slice(&d.to_le_bytes());
    out
}

fn pad(input: &[u8]) -> Vec<u8> {
    let bit_len = (input.len() as u64) * 8;
    let mut padded = input.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());
    padded
}

const T: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

// Round indices: (table_index, x_index, shift)
const round1: [(usize, u32, u32); 16] = [
    (0, 0, 7), (1, 1, 12), (2, 2, 17), (3, 3, 22),
    (4, 4, 7), (5, 5, 12), (6, 6, 17), (7, 7, 22),
    (8, 8, 7), (9, 9, 12), (10, 10, 17), (11, 11, 22),
    (12, 12, 7), (13, 13, 12), (14, 14, 17), (15, 15, 22),
];

const round2: [(usize, u32, u32); 16] = [
    (16, 1, 5), (17, 6, 9), (18, 11, 14), (19, 0, 20),
    (20, 5, 5), (21, 10, 9), (22, 15, 14), (23, 4, 20),
    (24, 9, 5), (25, 14, 9), (26, 3, 14), (27, 8, 20),
    (28, 13, 5), (29, 2, 9), (30, 7, 14), (31, 12, 20),
];

const round3: [(usize, u32, u32); 16] = [
    (32, 5, 4), (33, 8, 11), (34, 11, 16), (35, 14, 23),
    (36, 1, 4), (37, 4, 11), (38, 7, 16), (39, 10, 23),
    (40, 13, 4), (41, 0, 11), (42, 3, 16), (43, 6, 23),
    (44, 9, 4), (45, 12, 11), (46, 15, 16), (47, 2, 23),
];

const round4: [(usize, u32, u32); 16] = [
    (48, 0, 6), (49, 7, 10), (50, 14, 15), (51, 5, 21),
    (52, 12, 6), (53, 3, 10), (54, 10, 15), (55, 1, 21),
    (56, 8, 6), (57, 15, 10), (58, 6, 15), (59, 13, 21),
    (60, 4, 6), (61, 11, 10), (62, 2, 15), (63, 9, 21),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_basic() {
        let digest = md5(b"");
        assert_eq!(digest, [0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e]);

        let digest = md5(b"abc");
        assert_eq!(digest, [0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72]);

        let digest = md5(b"message digest");
        assert_eq!(digest, [0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d, 0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0]);
    }

    #[test]
    fn test_new_id() {
        let uuid = UUID([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ]);
        let id = ID::new(uuid);
        assert_eq!(id.uuid(), uuid);
        assert_eq!(id.uuid().0, uuid.0);
        assert_eq!(id.cmd_key().len(), 16);
    }

    #[test]
    fn test_id_equals() {
        let uuid = UUID([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ]);
        let a = ID::new(uuid);
        let b = ID::new(uuid);
        assert!(a.equals(&b));
    }

    #[test]
    fn test_uuid_display() {
        let uuid = UUID([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ]);
        let s = format!("{}", uuid);
        assert_eq!(s, "00010203-0405-0607-0809-0a0b0c0d0e0f");
    }

    #[test]
    fn test_id_bytes() {
        let uuid = UUID([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ]);
        let id = ID::new(uuid);
        assert_eq!(id.bytes(), uuid.0);
    }
}
