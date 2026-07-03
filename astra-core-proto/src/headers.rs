use crate::payload::TransferType;
use astra_core_net::destination::{TcpDestination, UdpDestination};
use astra_core_net::{Address, Destination, Port};

/// Security encryption type. Mirrors go Xray-core's `SecurityType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityType {
    Unknown = 0,
    Auto = 2,
    Aes128Gcm = 3,
    ChaCha20Poly1305 = 4,
    None = 5,
    Zero = 6,
}

impl SecurityType {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => SecurityType::Unknown,
            2 => SecurityType::Auto,
            3 => SecurityType::Aes128Gcm,
            4 => SecurityType::ChaCha20Poly1305,
            5 => SecurityType::None,
            6 => SecurityType::Zero,
            _ => SecurityType::Unknown,
        }
    }

    pub fn from_byte(b: u8) -> Self {
        Self::from_i32(b as i32)
    }

    pub fn as_i32(self) -> i32 {
        self as i32
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Security configuration: wraps SecurityType with auto-detection logic.
#[derive(Debug, Clone, Copy)]
pub struct SecurityConfig {
    pub typ: SecurityType,
}

impl SecurityConfig {
    pub fn new(typ: SecurityType) -> Self {
        SecurityConfig { typ }
    }

    /// Resolves AUTO to the actual encryption type.
    /// Always returns Aes128Gcm when AUTO (no hardware detection in pure Rust).
    pub fn get_security_type(&self) -> SecurityType {
        match self.typ {
            SecurityType::Auto => SecurityType::Aes128Gcm,
            other => other,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            typ: SecurityType::Auto,
        }
    }
}

/// Request command type in proxy protocol headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestCommand {
    Tcp = 0x01,
    Udp = 0x02,
    Mux = 0x03,
    Rvs = 0x04,
}

impl RequestCommand {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(RequestCommand::Tcp),
            0x02 => Some(RequestCommand::Udp),
            0x03 => Some(RequestCommand::Mux),
            0x04 => Some(RequestCommand::Rvs),
            _ => None,
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }

    pub fn transfer_type(self) -> TransferType {
        match self {
            RequestCommand::Udp => TransferType::Packet,
            _ => TransferType::Stream,
        }
    }
}

/// Request option bit flags (byte mask).
pub mod request_option {
    pub const ChunkStream: u8 = 0x01;
    pub const ChunkMasking: u8 = 0x04;
    pub const GlobalPadding: u8 = 0x08;
    pub const AuthenticatedLength: u8 = 0x10;
}

/// Response option bit flags (byte mask).
pub mod response_option {
    pub const ConnectionReuse: u8 = 0x01;
}

/// Request header in proxy protocol (VMess/VLESS).
#[derive(Debug, Clone)]
pub struct RequestHeader {
    pub version: u8,
    pub command: RequestCommand,
    pub option: u8,
    pub security: SecurityType,
    pub port: Port,
    pub address: Address,
    pub user: Option<MemoryUser>,
}

impl RequestHeader {
    pub fn destination(&self) -> Destination {
        match self.command {
            RequestCommand::Udp => UdpDestination(self.address.clone(), self.port),
            _ => TcpDestination(self.address.clone(), self.port),
        }
    }
}

/// Response command — any type can serve (empty interface in go).
pub type ResponseCommand = Box<dyn std::any::Any + Send>;

/// Response header in proxy protocol.
#[derive(Debug)]
pub struct ResponseHeader {
    pub option: u8,
    pub command: Option<ResponseCommand>,
}

use std::sync::Arc;

/// In-memory representation of a user account (cached form).
#[derive(Debug, Clone)]
pub struct MemoryUser {
    pub account: Option<Arc<dyn Account>>,
    pub email: String,
    pub level: u32,
}

/// Account interface — must support equality and conversion to a portable form.
pub trait Account: std::fmt::Debug + Send + Sync {
    fn equals(&self, other: &dyn Account) -> bool;
    fn as_any(&self) -> &dyn std::any::Any;
}

impl MemoryUser {
    pub fn new(level: u32, email: String, account: Option<Arc<dyn Account>>) -> Self {
        MemoryUser {
            account,
            email,
            level,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{AddressType, TransferType};

    #[test]
    fn test_security_type_roundtrip() {
        for (val, expected) in [
            (0, SecurityType::Unknown),
            (2, SecurityType::Auto),
            (3, SecurityType::Aes128Gcm),
            (4, SecurityType::ChaCha20Poly1305),
            (5, SecurityType::None),
            (6, SecurityType::Zero),
        ] {
            assert_eq!(SecurityType::from_i32(val), expected);
            assert_eq!(expected.as_i32(), val);
        }
    }

    #[test]
    fn test_security_config_auto() {
        let cfg = SecurityConfig::new(SecurityType::Auto);
        assert_eq!(cfg.get_security_type(), SecurityType::Aes128Gcm);
        let cfg = SecurityConfig::new(SecurityType::Zero);
        assert_eq!(cfg.get_security_type(), SecurityType::Zero);
    }

    #[test]
    fn test_request_command_from_byte() {
        assert_eq!(RequestCommand::from_byte(0x01), Some(RequestCommand::Tcp));
        assert_eq!(RequestCommand::from_byte(0x02), Some(RequestCommand::Udp));
        assert_eq!(RequestCommand::from_byte(0x03), Some(RequestCommand::Mux));
        assert_eq!(RequestCommand::from_byte(0x04), Some(RequestCommand::Rvs));
        assert_eq!(RequestCommand::from_byte(0xff), None);
    }

    #[test]
    fn test_request_command_transfer_type() {
        assert_eq!(RequestCommand::Tcp.transfer_type(), TransferType::Stream);
        assert_eq!(RequestCommand::Udp.transfer_type(), TransferType::Packet);
        assert_eq!(RequestCommand::Mux.transfer_type(), TransferType::Stream);
        assert_eq!(RequestCommand::Rvs.transfer_type(), TransferType::Stream);
    }

    #[test]
    fn test_request_command_as_byte() {
        assert_eq!(RequestCommand::Tcp.as_byte(), 0x01);
        assert_eq!(RequestCommand::Udp.as_byte(), 0x02);
    }

    #[test]
    fn test_request_option_constants() {
        assert_eq!(request_option::ChunkStream, 0x01);
        assert_eq!(request_option::ChunkMasking, 0x04);
        assert_eq!(request_option::GlobalPadding, 0x08);
        assert_eq!(request_option::AuthenticatedLength, 0x10);
        assert_eq!(response_option::ConnectionReuse, 0x01);
    }

    #[test]
    fn test_memory_user() {
        let mu = MemoryUser::new(1, "test@example.com".into(), None);
        assert_eq!(mu.level, 1);
        assert_eq!(mu.email, "test@example.com");
        assert!(mu.account.is_none());
    }

    #[test]
    fn test_transfer_type_roundtrip() {
        assert_eq!(TransferType::from_byte(0), TransferType::Stream);
        assert_eq!(TransferType::from_byte(1), TransferType::Packet);
        assert_eq!(TransferType::from_byte(255), TransferType::Packet);
        assert_eq!(TransferType::Stream.as_byte(), 0);
        assert_eq!(TransferType::Packet.as_byte(), 1);
    }

    #[test]
    fn test_address_type() {
        assert_eq!(AddressType::from_byte(1), Some(AddressType::IPv4));
        assert_eq!(AddressType::from_byte(2), Some(AddressType::Domain));
        assert_eq!(AddressType::from_byte(3), Some(AddressType::IPv6));
        assert_eq!(AddressType::from_byte(0), None);
        assert_eq!(AddressType::IPv4.as_byte(), 1);
        assert_eq!(AddressType::Domain.as_byte(), 2);
        assert_eq!(AddressType::IPv6.as_byte(), 3);
    }
}
