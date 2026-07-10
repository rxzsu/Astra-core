
pub const COMMAND_AUTH_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandError {
    TooLarge,
    TypeMismatch,
    InvalidAuth,
    InsufficientLength,
    UnknownCommand(u16),
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandError::TooLarge => write!(f, "command too large"),
            CommandError::TypeMismatch => write!(f, "command type mismatch"),
            CommandError::InvalidAuth => write!(f, "invalid auth"),
            CommandError::InsufficientLength => write!(f, "insufficient length"),
            CommandError::UnknownCommand(id) => write!(f, "unknown command: {}", id),
        }
    }
}

/// Marshal a VMess response command.
/// Format: [auth(4 bytes)][cmd_id(1 byte)][cmd_len(1 byte)][cmd_data(cmd_len bytes)]
pub fn marshal_command(cmd_id: u16, cmd_data: &[u8]) -> Result<Vec<u8>, CommandError> {
    let total_len = COMMAND_AUTH_LEN + 1 + 1 + cmd_data.len();
    if total_len > 65535 {
        return Err(CommandError::TooLarge);
    }
    let mut buf = Vec::with_capacity(total_len);
    // Auth: FNV-1a hash of (cmd_id || cmd_data)
    let auth = compute_auth(cmd_id, cmd_data);
    buf.extend_from_slice(&auth.to_be_bytes());
    buf.push((cmd_id & 0xff) as u8);
    buf.push(cmd_data.len() as u8);
    buf.extend_from_slice(cmd_data);
    Ok(buf)
}

/// Unmarshal a VMess response command.
/// Validates the 4-byte auth header, then returns (cmd_id, cmd_data).
pub fn unmarshal_command(data: &[u8]) -> Result<(u16, Vec<u8>), CommandError> {
    if data.len() < COMMAND_AUTH_LEN + 2 {
        return Err(CommandError::InsufficientLength);
    }
    let auth = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let cmd_id = data[4] as u16;
    let cmd_len = data[5] as usize;
    if data.len() < COMMAND_AUTH_LEN + 2 + cmd_len {
        return Err(CommandError::InsufficientLength);
    }
    let cmd_data = data[6..6 + cmd_len].to_vec();

    let expected_auth = compute_auth(cmd_id, &cmd_data);
    if auth != expected_auth {
        return Err(CommandError::InvalidAuth);
    }

    Ok((cmd_id, cmd_data))
}

fn compute_auth(cmd_id: u16, cmd_data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    hash ^= (cmd_id & 0xff) as u32;
    hash = hash.wrapping_mul(0x01000193);
    hash ^= ((cmd_id >> 8) & 0xff) as u32;
    hash = hash.wrapping_mul(0x01000193);
    for &byte in cmd_data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// Trait for VMess command serialization.
pub trait VmessCommand: Send + Sync {
    fn marshal(&self) -> Result<Vec<u8>, CommandError>;
    fn unmarshal(data: &[u8]) -> Result<Self, CommandError>
    where
        Self: Sized;
    fn cmd_id() -> u16;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_marshal_unmarshal_roundtrip() {
        let data = vec![0x01, 0x02, 0x03];
        let cmd_id = 1;
        let marshaled = marshal_command(cmd_id, &data).unwrap();
        let (decoded_id, decoded_data) = unmarshal_command(&marshaled).unwrap();
        assert_eq!(decoded_id, cmd_id);
        assert_eq!(decoded_data, data);
    }

    #[test]
    fn test_invalid_auth() {
        let data = vec![0x01, 0x02, 0x03];
        let marshaled = marshal_command(1, &data).unwrap();
        // Tamper with auth byte
        let mut tampered = marshaled;
        tampered[0] ^= 0xff;
        assert!(matches!(
            unmarshal_command(&tampered),
            Err(CommandError::InvalidAuth)
        ));
    }

    #[test]
    fn test_insufficient_length() {
        assert!(matches!(
            unmarshal_command(&[0; 3]),
            Err(CommandError::InsufficientLength)
        ));
    }
}
