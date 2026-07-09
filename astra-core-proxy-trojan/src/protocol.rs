use sha2::{Digest, Sha224};
use tokio::io::AsyncReadExt;

use astra_core_net::{Address, Destination, Network, Port};

pub const COMMAND_TCP: u8 = 0x01;
pub const COMMAND_UDP: u8 = 0x03;

pub fn key_from_password(password: &str) -> [u8; 56] {
    let hash = Sha224::digest(password.as_bytes());
    let mut hex_buf = [0u8; 56];
    hex::encode_to_slice(hash, &mut hex_buf).expect("hex encode");
    hex_buf
}

pub fn write_address(buf: &mut Vec<u8>, addr: &Address) {
    match addr {
        Address::Ipv4(octets) => {
            buf.push(0x01);
            buf.extend_from_slice(octets);
        }
        Address::Ipv6(octets) => {
            buf.push(0x04);
            buf.extend_from_slice(octets);
        }
        Address::Domain(domain) => {
            buf.push(0x03);
            let len = domain.len();
            assert!(len <= 255, "domain too long");
            buf.push(len as u8);
            buf.extend_from_slice(domain.as_bytes());
        }
    }
}

pub fn read_address(data: &[u8]) -> Result<(Address, usize), String> {
    if data.is_empty() {
        return Err("empty address data".into());
    }
    let atype = data[0];
    let mut offset = 1;

    let address = match atype {
        0x01 => {
            if data.len() < offset + 4 {
                return Err("short ipv4 address".into());
            }
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&data[offset..offset + 4]);
            offset += 4;
            Address::Ipv4(octets)
        }
        0x04 => {
            if data.len() < offset + 16 {
                return Err("short ipv6 address".into());
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[offset..offset + 16]);
            offset += 16;
            Address::Ipv6(octets)
        }
        0x03 => {
            if data.len() < offset + 1 {
                return Err("short domain length".into());
            }
            let dlen = data[offset] as usize;
            offset += 1;
            if data.len() < offset + dlen {
                return Err("short domain data".into());
            }
            let domain =
                std::str::from_utf8(&data[offset..offset + dlen]).map_err(|_| "invalid domain")?;
            offset += dlen;
            Address::Domain(domain.to_owned())
        }
        _ => return Err(format!("unknown address type: {}", atype)),
    };

    if data.len() < offset + 2 {
        return Err("short port".into());
    }
    let _port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    Ok((address, offset))
}

pub fn write_tcp_header(key: &[u8; 56], addr: &Address, port: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(56 + 2 + 1 + 1 + 4 + 16 + 1 + 2 + 2);
    buf.extend_from_slice(key);
    buf.extend_from_slice(b"\r\n");
    buf.push(COMMAND_TCP);
    write_address(&mut buf, addr);
    buf.extend_from_slice(&port.to_be_bytes());
    buf.extend_from_slice(b"\r\n");
    buf
}

pub fn write_udp_packet(addr: &Address, port: u16, payload: &[u8]) -> Vec<u8> {
    let addr_size = match addr {
        Address::Ipv4(_) => 1 + 4,
        Address::Ipv6(_) => 1 + 16,
        Address::Domain(d) => 1 + 1 + d.len(),
    };
    let mut buf = Vec::with_capacity(addr_size + 2 + 2 + payload.len());
    write_address(&mut buf, addr);
    buf.extend_from_slice(&port.to_be_bytes());
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(payload);
    buf
}

pub struct TrojanHeader {
    pub key: [u8; 56],
    pub command: u8,
    pub destination: Destination,
}

/// Parse a Trojan header from a byte slice (used for fallback detection).
/// Returns header and total header size in bytes.
pub fn read_header_from_slice(data: &[u8]) -> Result<(TrojanHeader, usize), String> {
    if data.len() < 58 {
        return Err("trojan: header too short".into());
    }
    let mut key = [0u8; 56];
    key.copy_from_slice(&data[..56]);

    if data[56] != b'\r' || data[57] != b'\n' {
        return Err("trojan: expected crlf after key".into());
    }

    let cmd = data[58];
    let atype = data[59];
    let mut offset = 60;

    let address = match atype {
        0x01 => {
            if data.len() < offset + 4 {
                return Err("short ipv4".into());
            }
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&data[offset..offset + 4]);
            offset += 4;
            Address::Ipv4(octets)
        }
        0x04 => {
            if data.len() < offset + 16 {
                return Err("short ipv6".into());
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[offset..offset + 16]);
            offset += 16;
            Address::Ipv6(octets)
        }
        0x03 => {
            if data.len() < offset + 1 {
                return Err("short domain len".into());
            }
            let dlen = data[offset] as usize;
            offset += 1;
            if data.len() < offset + dlen {
                return Err("short domain".into());
            }
            let domain = std::str::from_utf8(&data[offset..offset + dlen])
                .map_err(|_| "invalid domain utf8")?;
            offset += dlen;
            Address::Domain(domain.to_owned())
        }
        _ => return Err(format!("unknown address type: {}", atype)),
    };

    if data.len() < offset + 2 {
        return Err("short port".into());
    }
    let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    if data.len() < offset + 2 || data[offset] != b'\r' || data[offset + 1] != b'\n' {
        return Err("trojan: expected trailing crlf".into());
    }
    offset += 2;

    let network = match cmd {
        COMMAND_TCP => Network::Tcp,
        COMMAND_UDP => Network::Udp,
        _ => return Err(format!("trojan: unknown command: {}", cmd)),
    };

    Ok((
        TrojanHeader {
            key,
            command: cmd,
            destination: Destination {
                address,
                port: Port(port),
                network,
            },
        },
        offset,
    ))
}

pub async fn read_header<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<TrojanHeader, String> {
    let mut key = [0u8; 56];
    reader
        .read_exact(&mut key)
        .await
        .map_err(|e| format!("trojan: read key: {}", e))?;

    let mut crlf = [0u8; 2];
    reader
        .read_exact(&mut crlf)
        .await
        .map_err(|e| format!("trojan: read crlf: {}", e))?;
    if crlf != *b"\r\n" {
        return Err("trojan: expected crlf after key".into());
    }

    let mut cmd = [0u8; 1];
    reader
        .read_exact(&mut cmd)
        .await
        .map_err(|e| format!("trojan: read command: {}", e))?;

    let mut atype = [0u8; 1];
    reader
        .read_exact(&mut atype)
        .await
        .map_err(|e| format!("trojan: read address type: {}", e))?;

    let address = match atype[0] {
        0x01 => {
            let mut octets = [0u8; 4];
            reader
                .read_exact(&mut octets)
                .await
                .map_err(|e| format!("trojan: read ipv4: {}", e))?;
            Address::Ipv4(octets)
        }
        0x04 => {
            let mut octets = [0u8; 16];
            reader
                .read_exact(&mut octets)
                .await
                .map_err(|e| format!("trojan: read ipv6: {}", e))?;
            Address::Ipv6(octets)
        }
        0x03 => {
            let mut dlen = [0u8; 1];
            reader
                .read_exact(&mut dlen)
                .await
                .map_err(|e| format!("trojan: read domain len: {}", e))?;
            let mut domain = vec![0u8; dlen[0] as usize];
            reader
                .read_exact(&mut domain)
                .await
                .map_err(|e| format!("trojan: read domain: {}", e))?;
            let domain_str =
                std::str::from_utf8(&domain).map_err(|_| "trojan: invalid domain utf8")?;
            Address::Domain(domain_str.to_owned())
        }
        _ => return Err(format!("trojan: unknown address type: {}", atype[0])),
    };

    let mut port_buf = [0u8; 2];
    reader
        .read_exact(&mut port_buf)
        .await
        .map_err(|e| format!("trojan: read port: {}", e))?;
    let port = u16::from_be_bytes(port_buf);

    let mut crlf2 = [0u8; 2];
    reader
        .read_exact(&mut crlf2)
        .await
        .map_err(|e| format!("trojan: read trailing crlf: {}", e))?;
    if crlf2 != *b"\r\n" {
        return Err("trojan: expected trailing crlf".into());
    }

    let network = match cmd[0] {
        COMMAND_TCP => Network::Tcp,
        COMMAND_UDP => Network::Udp,
        _ => return Err(format!("trojan: unknown command: {}", cmd[0])),
    };

    Ok(TrojanHeader {
        key,
        command: cmd[0],
        destination: Destination {
            address,
            port: Port(port),
            network,
        },
    })
}
