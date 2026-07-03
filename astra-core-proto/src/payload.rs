/// Transfer type (stream vs packet). Mirrors go Xray-core's `TransferType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransferType {
    Stream = 0,
    Packet = 1,
}

impl TransferType {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => TransferType::Stream,
            _ => TransferType::Packet,
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Address type byte used in wire protocol (VMess/VLESS headers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressType {
    IPv4 = 1,
    Domain = 2,
    IPv6 = 3,
}

impl AddressType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(AddressType::IPv4),
            2 => Some(AddressType::Domain),
            3 => Some(AddressType::IPv6),
            _ => None,
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }
}
