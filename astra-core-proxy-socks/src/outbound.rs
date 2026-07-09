use tokio::io::{AsyncReadExt, AsyncWriteExt};

use astra_core_net::{Address, Destination, Network, Port};
use astra_core_proxy::{async_trait, AsyncConn, Dialer, OutboundHandler, ProxyResult, UdpLink};
use astra_core_session::Session;
use astra_core_transport::{Link, UdpPacket};

use crate::protocol::*;

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server_address: Address,
    pub server_port: Port,
    pub username: String,
    pub password: String,
}

pub struct Handler {
    config: ClientConfig,
}

impl Handler {
    pub fn new(config: ClientConfig) -> Self {
        Handler { config }
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    async fn process(
        &self,
        session: Session,
        link: &mut Link,
        dialer: &dyn Dialer,
    ) -> ProxyResult<()> {
        let target = session
            .outbound
            .as_ref()
            .ok_or_else(|| "no outbound target".to_string())?
            .target
            .clone();

        if target.network == Network::Udp {
            return Err("UDP over SOCKS outbound requires process_udp".into());
        }

        let server_dest = Destination {
            address: self.config.server_address.clone(),
            port: self.config.server_port,
            network: Network::Tcp,
        };

        let mut remote: Box<dyn AsyncConn> = dialer.dial(session, server_dest).await?;
        let (mut remote_r, mut remote_w) = tokio::io::split(&mut *remote);

        socks5_client_handshake(
            &mut remote_r,
            &mut remote_w,
            &self.config.username,
            &self.config.password,
            &target.address,
            target.port,
        )
        .await?;

        let to_remote = tokio::io::copy(&mut link.reader, &mut remote_w);
        let to_local = tokio::io::copy(&mut remote_r, &mut link.writer);

        tokio::select! {
            r = to_remote => r.map(|_| ()),
            r = to_local => r.map(|_| ()),
        }
        .map_err(|e| format!("socks outbound copy: {}", e))?;

        Ok(())
    }

    async fn process_udp(&self, _session: Session, link: &mut UdpLink) -> ProxyResult<()> {
        let server_addr = format!(
            "{}:{}",
            self.config.server_address,
            self.config.server_port.value()
        );
        let remote = tokio::net::TcpStream::connect(&server_addr)
            .await
            .map_err(|e| format!("connect socks server {}: {}", server_addr, e))?;
        let (mut remote_r, mut remote_w) = tokio::io::split(remote);

        let (relay_addr, relay_port) = socks5_udp_associate(
            &mut remote_r,
            &mut remote_w,
            &self.config.username,
            &self.config.password,
        )
        .await?;

        let relay_addr_str = format!("{}:{}", relay_addr, relay_port.value());
        let relay = std::sync::Arc::new(
            tokio::net::UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| format!("bind udp: {}", e))?,
        );

        let writer = link.writer.clone();
        let relay_clone = relay.clone();

        // Read responses from relay and send through link
        let recv_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            while let Ok((n, _src)) = relay_clone.recv_from(&mut buf).await {
                if let Ok((addr, port, payload)) = decode_udp_packet(&buf[..n]) {
                    let source = Destination {
                        address: addr,
                        port,
                        network: Network::Udp,
                    };
                    let pkt = UdpPacket::new(source.clone(), source, payload.to_vec());
                    if writer.send(pkt).is_err() {
                        break;
                    }
                }
            }
        });

        // Read requests from link, wrap in SOCKS UDP header, send to relay
        while let Some(packet) = link.recv().await {
            let encoded =
                encode_udp_packet(&packet.target.address, packet.target.port, &packet.data);
            if relay.send_to(&encoded, &relay_addr_str).await.is_err() {
                break;
            }
        }

        let _ = recv_handle.await;
        Ok(())
    }
}

pub async fn socks5_client_handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
    username: &str,
    password: &str,
    target_addr: &Address,
    target_port: Port,
) -> Result<(), String>
where
    R: AsyncReadExt + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    let has_auth = !username.is_empty();
    let auth_byte = if has_auth {
        AUTH_PASSWORD
    } else {
        AUTH_NOT_REQUIRED
    };

    write_all(writer, &[SOCKS5_VERSION, 0x01, auth_byte]).await?;

    let mut resp = [0u8; 2];
    read_exact(reader, &mut resp).await?;
    if resp[0] != SOCKS5_VERSION {
        return Err(format!("unexpected socks version: {}", resp[0]));
    }
    if resp[1] != auth_byte {
        return Err(format!("auth method rejected: {}", resp[1]));
    }

    if has_auth {
        let ulen = username.len() as u8;
        let plen = password.len() as u8;
        let mut auth_req = vec![0x01, ulen];
        auth_req.extend_from_slice(username.as_bytes());
        auth_req.push(plen);
        auth_req.extend_from_slice(password.as_bytes());
        write_all(writer, &auth_req).await?;

        let mut auth_resp = [0u8; 2];
        read_exact(reader, &mut auth_resp).await?;
        if auth_resp[1] != 0x00 {
            return Err("auth rejected".into());
        }
    }

    let mut req = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00];
    encode_addr_port(&mut req, target_addr, target_port);
    write_all(writer, &req).await?;

    let mut resp_hdr = [0u8; 4];
    read_exact(reader, &mut resp_hdr).await?;
    if resp_hdr[1] != STATUS_SUCCESS {
        return Err(format!("server rejected: {}", resp_hdr[1]));
    }

    let atyp = resp_hdr[3];
    match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            read_exact(reader, &mut ip).await?;
        }
        0x03 => {
            let len = read_u8(reader).await? as usize;
            let mut d = vec![0u8; len];
            read_exact(reader, &mut d).await?;
        }
        0x04 => {
            let mut ip = [0u8; 16];
            read_exact(reader, &mut ip).await?;
        }
        _ => return Err(format!("unknown bind addr type: {}", atyp)),
    }
    let _ = read_u16(reader).await?;

    Ok(())
}

/// Perform SOCKS5 auth (no CONNECT command), then send UDP ASSOCIATE.
/// Returns the relay address from the server response.
pub async fn socks5_udp_associate<R, W>(
    reader: &mut R,
    writer: &mut W,
    username: &str,
    password: &str,
) -> Result<(Address, Port), String>
where
    R: AsyncReadExt + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    let has_auth = !username.is_empty();
    let auth_byte = if has_auth {
        AUTH_PASSWORD
    } else {
        AUTH_NOT_REQUIRED
    };

    write_all(writer, &[SOCKS5_VERSION, 0x01, auth_byte]).await?;

    let mut resp = [0u8; 2];
    read_exact(reader, &mut resp).await?;
    if resp[0] != SOCKS5_VERSION {
        return Err(format!("unexpected socks version: {}", resp[0]));
    }
    if resp[1] != auth_byte {
        return Err(format!("auth method rejected: {}", resp[1]));
    }

    if has_auth {
        let ulen = username.len() as u8;
        let plen = password.len() as u8;
        let mut auth_req = vec![0x01, ulen];
        auth_req.extend_from_slice(username.as_bytes());
        auth_req.push(plen);
        auth_req.extend_from_slice(password.as_bytes());
        write_all(writer, &auth_req).await?;

        let mut auth_resp = [0u8; 2];
        read_exact(reader, &mut auth_resp).await?;
        if auth_resp[1] != 0x00 {
            return Err("auth rejected".into());
        }
    }

    // UDP ASSOCIATE with 0.0.0.0:0 (let server pick relay address)
    let mut req = vec![SOCKS5_VERSION, CMD_UDP_ASSOCIATE, 0x00];
    encode_addr_port(&mut req, &Address::Ipv4([0, 0, 0, 0]), Port(0));
    write_all(writer, &req).await?;

    let mut resp_hdr = [0u8; 4];
    read_exact(reader, &mut resp_hdr).await?;
    if resp_hdr[1] != STATUS_SUCCESS {
        return Err(format!("server rejected UDP ASSOCIATE: {}", resp_hdr[1]));
    }

    let atyp = resp_hdr[3];
    let relay_addr = match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            read_exact(reader, &mut ip).await?;
            Address::Ipv4(ip)
        }
        0x03 => {
            let len = read_u8(reader).await? as usize;
            let mut d = vec![0u8; len];
            read_exact(reader, &mut d).await?;
            Address::Domain(String::from_utf8(d).map_err(|_| "invalid domain".to_string())?)
        }
        0x04 => {
            let mut ip = [0u8; 16];
            read_exact(reader, &mut ip).await?;
            Address::Ipv6(ip)
        }
        _ => return Err(format!("unknown bind addr type: {}", atyp)),
    };
    let relay_port = Port(read_u16(reader).await?);

    Ok((relay_addr, relay_port))
}
