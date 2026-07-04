use core::fmt;
use md5::{Digest, Md5};

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

fn md5(input: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

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
