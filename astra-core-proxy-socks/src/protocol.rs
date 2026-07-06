use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use astra_core_net::{Address, Port};

pub const SOCKS4_VERSION: u8 = 0x04;
pub const SOCKS5_VERSION: u8 = 0x05;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const SOCKS4_GRANTED: u8 = 90;
pub const SOCKS4_REJECTED: u8 = 91;

pub const AUTH_NOT_REQUIRED: u8 = 0x00;
pub const AUTH_PASSWORD: u8 = 0x02;
pub const AUTH_NO_MATCH: u8 = 0xFF;

pub const STATUS_SUCCESS: u8 = 0x00;
pub const STATUS_CMD_NOT_SUPPORTED: u8 = 0x07;
pub const STATUS_ADDR_NOT_SUPPORTED: u8 = 0x08;

#[derive(Debug, Clone)]
pub struct SocksConfig {
    pub auth_type: AuthType,
    pub accounts: HashMap<String, String>,
    pub udp_enabled: bool,
    pub address: Option<Address>,
    pub user_level: u32,
}

impl Default for SocksConfig {
    fn default() -> Self {
        SocksConfig {
            auth_type: AuthType::NoAuth,
            accounts: HashMap::new(),
            udp_enabled: false,
            address: None,
            user_level: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthType {
    NoAuth,
    Password,
}

pub async fn read_exact<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> Result<(), String> {
    r.read_exact(buf).await.map(|_| ()).map_err(|e| format!("read error: {}", e))
}

pub async fn read_u8<R: AsyncRead + Unpin>(r: &mut R) -> Result<u8, String> {
    r.read_u8().await.map_err(|e| format!("read u8: {}", e))
}

pub async fn read_u16<R: AsyncRead + Unpin>(r: &mut R) -> Result<u16, String> {
    r.read_u16().await.map_err(|e| format!("read u16: {}", e))
}

pub async fn write_all<W: AsyncWrite + Unpin>(w: &mut W, buf: &[u8]) -> Result<(), String> {
    w.write_all(buf).await.map_err(|e| format!("write error: {}", e))
}

pub async fn read_until_null<R: AsyncRead + Unpin>(r: &mut R) -> Result<String, String> {
    let mut buf = Vec::new();
    loop {
        let byte = read_u8(r).await?;
        if byte == 0x00 {
            break;
        }
        buf.push(byte);
    }
    String::from_utf8(buf).map_err(|_| "invalid utf-8".to_string())
}

pub async fn socks5_auth<C: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut C,
    config: &SocksConfig,
) -> Result<Option<String>, String> {
    let nmethods = read_u8(conn).await? as usize;
    let mut methods = vec![0u8; nmethods];
    read_exact(conn, &mut methods).await?;

    let expected_auth = if config.auth_type == AuthType::Password {
        AUTH_PASSWORD
    } else {
        AUTH_NOT_REQUIRED
    };

    if !methods.contains(&expected_auth) {
        write_all(conn, &[SOCKS5_VERSION, AUTH_NO_MATCH]).await?;
        return Err("no matching auth method".into());
    }

    write_all(conn, &[SOCKS5_VERSION, expected_auth]).await?;

    if expected_auth == AUTH_PASSWORD {
        let ver = read_u8(conn).await?;
        if ver != 0x01 {
            write_all(conn, &[0x01, 0xFF]).await?;
            return Err("invalid auth version".into());
        }

        let ulen = read_u8(conn).await? as usize;
        let mut uname = vec![0u8; ulen];
        read_exact(conn, &mut uname).await?;
        let username = String::from_utf8(uname).map_err(|_| "invalid username".to_string())?;

        let plen = read_u8(conn).await? as usize;
        let mut passwd = vec![0u8; plen];
        read_exact(conn, &mut passwd).await?;
        let password = String::from_utf8(passwd).map_err(|_| "invalid password".to_string())?;

        let valid = config.accounts.get(&username).map_or(false, |p| p == &password);
        if !valid {
            write_all(conn, &[0x01, 0xFF]).await?;
            return Err("invalid credentials".into());
        }

        write_all(conn, &[0x01, 0x00]).await?;
        return Ok(Some(username));
    }

    Ok(None)
}

pub fn socks5_response(addr: &Address, port: Port) -> Vec<u8> {
    let mut buf = vec![SOCKS5_VERSION, STATUS_SUCCESS, 0x00];
    encode_addr_port(&mut buf, addr, port);
    buf
}

pub fn socks5_error(code: u8) -> Vec<u8> {
    let buf = vec![SOCKS5_VERSION, code, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    buf
}

pub fn socks4_response(status: u8, addr: &Address, port: Port) -> Vec<u8> {
    let mut buf = vec![0x00, status];
    buf.extend_from_slice(&port.value().to_be_bytes());
    match addr {
        Address::Ipv4(ip) => buf.extend_from_slice(ip),
        _ => buf.extend_from_slice(&[0, 0, 0, 0]),
    }
    buf
}

pub fn encode_addr_port(buf: &mut Vec<u8>, addr: &Address, port: Port) {
    match addr {
        Address::Ipv4(ip) => {
            buf.push(0x01);
            buf.extend_from_slice(ip);
        }
        Address::Ipv6(ip) => {
            buf.push(0x04);
            buf.extend_from_slice(ip);
        }
        Address::Domain(domain) => {
            buf.push(0x03);
            let b = domain.as_bytes();
            buf.push(b.len() as u8);
            buf.extend_from_slice(b);
        }
    }
    buf.extend_from_slice(&port.value().to_be_bytes());
}

pub fn decode_addr_port(data: &[u8]) -> Result<(Address, Port), String> {
    if data.is_empty() {
        return Err("empty address data".into());
    }
    let atype = data[0];
    let (addr, consumed) = match atype {
        0x01 => {
            if data.len() < 5 {
                return Err("short ipv4".into());
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&data[1..5]);
            (Address::Ipv4(ip), 5)
        }
        0x03 => {
            if data.len() < 2 {
                return Err("short domain".into());
            }
            let dlen = data[1] as usize;
            if data.len() < 2 + dlen {
                return Err("short domain name".into());
            }
            let domain = String::from_utf8(data[2..2 + dlen].to_vec())
                .map_err(|_| "invalid domain".to_string())?;
            (Address::Domain(domain), 2 + dlen)
        }
        0x04 => {
            if data.len() < 17 {
                return Err("short ipv6".into());
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&data[1..17]);
            (Address::Ipv6(ip), 17)
        }
        _ => return Err(format!("unknown address type: {}", atype)),
    };
    if data.len() < consumed + 2 {
        return Err("short port".into());
    }
    let port = Port(u16::from_be_bytes([data[consumed], data[consumed + 1]]));
    Ok((addr, port))
}

pub fn address_wire_size(addr: &Address) -> usize {
    match addr {
        Address::Ipv4(_) => 1 + 4,
        Address::Ipv6(_) => 1 + 16,
        Address::Domain(d) => 1 + 1 + d.len(),
    }
}

pub fn encode_udp_packet(addr: &Address, port: Port, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x00, 0x00, 0x00];
    encode_addr_port(&mut buf, addr, port);
    buf.extend_from_slice(payload);
    buf
}

pub fn decode_udp_packet(data: &[u8]) -> Result<(Address, Port, &[u8]), String> {
    if data.len() < 3 {
        return Err("packet too short".into());
    }
    if data[2] != 0 {
        return Err("fragmented packets not supported".into());
    }
    let (addr, port) = decode_addr_port(&data[3..])?;
    let header_size = 3 + address_wire_size(&addr);
    if data.len() < header_size {
        return Err("packet too short for header".into());
    }
    Ok((addr, port, &data[header_size..]))
}
