pub mod protocol;
pub mod outbound;

use std::sync::Arc;
use tokio::io::AsyncReadExt;

use astra_core_net::{Address, Destination, Network, Port};
use astra_core_net::address::any_ip;
use astra_core_proxy::{async_trait, Conn, Dispatcher, InboundHandler, ProxyResult};
use astra_core_session::{Outbound, Session};
use astra_core_transport::new_link_stream;

use protocol::*;

#[derive(Clone)]
pub struct Handler {
    pub config: SocksConfig,
}

impl Handler {
    pub fn new() -> Self {
        Handler {
            config: SocksConfig::default(),
        }
    }

    pub fn with_config(config: SocksConfig) -> Self {
        Handler { config }
    }
}

#[async_trait]
impl InboundHandler for Handler {
    async fn process(
        &self,
        session: Session,
        mut conn: Conn,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> ProxyResult<()> {
        let mut version_buf = [0u8; 1];
        let n = (&mut conn).read(&mut version_buf).await
            .map_err(|e| format!("socks read: {}", e))?;
        if n == 0 {
            return Err("connection closed".into());
        }

        match version_buf[0] {
            SOCKS4_VERSION => {
                handle_socks4(&self.config, &mut conn, &session, dispatcher).await
            }
            SOCKS5_VERSION => {
                handle_socks5(&self.config, &mut conn, &session, dispatcher).await
            }
            v => Err(format!("unknown socks version: {}", v)),
        }
    }
}

async fn handle_socks4(
    config: &SocksConfig,
    conn: &mut Conn,
    session: &Session,
    dispatcher: Arc<dyn Dispatcher>,
) -> ProxyResult<()> {
    if config.auth_type == AuthType::Password {
        write_all(conn, &socks4_response(SOCKS4_REJECTED, any_ip(), Port(0))).await?;
        return Err("socks4 not allowed with auth".into());
    }

    let cmd = read_u8(conn).await?;
    let port_num = read_u16(conn).await?;
    let port = Port(port_num);

    let mut ip_buf = [0u8; 4];
    read_exact(conn, &mut ip_buf).await?;
    let mut address = Address::Ipv4(ip_buf);

    let _user_id = read_until_null(conn).await?;

    if ip_buf[0] == 0x00 && ip_buf[1] == 0x00 && ip_buf[2] == 0x00 && ip_buf[3] != 0x00 {
        let domain = read_until_null(conn).await?;
        address = Address::Domain(domain);
    }

    if cmd != CMD_CONNECT {
        write_all(conn, &socks4_response(SOCKS4_REJECTED, any_ip(), Port(0))).await?;
        return Err(format!("socks4 unsupported cmd: {}", cmd));
    }

    let dest = Destination {
        address: address.clone(),
        port,
        network: Network::Tcp,
    };

    write_all(conn, &socks4_response(SOCKS4_GRANTED, &address, port)).await?;

    let mut outbound_session = session.clone();
    outbound_session.outbound = Some(Outbound {
        target: dest.clone(),
        original_target: dest.clone(),
        route_target: None,
        tag: String::new(),
    });

    let link = dispatcher.dispatch(outbound_session, dest).await?;
    let mut link_stream = new_link_stream(link);

    tokio::io::copy_bidirectional(conn, &mut link_stream).await
        .map_err(|e| format!("socks4 relay: {}", e))?;

    Ok(())
}

async fn handle_socks5(
    config: &SocksConfig,
    conn: &mut Conn,
    session: &Session,
    dispatcher: Arc<dyn Dispatcher>,
) -> ProxyResult<()> {
    let _username = socks5_auth(conn, config).await?;

    let mut req = [0u8; 3];
    read_exact(conn, &mut req).await?;
    let cmd = req[1];

    let (address, port) = {
        let atyp = read_u8(conn).await?;
        let addr = match atyp {
            0x01 => {
                let mut ip = [0u8; 4];
                read_exact(conn, &mut ip).await?;
                Address::Ipv4(ip)
            }
            0x03 => {
                let len = read_u8(conn).await? as usize;
                let mut domain = vec![0u8; len];
                read_exact(conn, &mut domain).await?;
                Address::Domain(String::from_utf8(domain).map_err(|_| "invalid domain".to_string())?)
            }
            0x04 => {
                let mut ip = [0u8; 16];
                read_exact(conn, &mut ip).await?;
                Address::Ipv6(ip)
            }
            _ => {
                write_all(conn, &socks5_error(STATUS_ADDR_NOT_SUPPORTED)).await?;
                return Err(format!("unsupported addr type: {}", atyp));
            }
        };
        let port = read_u16(conn).await?;
        (addr, Port(port))
    };

    match cmd {
        CMD_CONNECT => {
            let dest = Destination {
                address: address.clone(),
                port,
                network: Network::Tcp,
            };

            write_all(conn, &socks5_response(&address, port)).await?;

            let mut outbound_session = session.clone();
            outbound_session.outbound = Some(Outbound {
                target: dest.clone(),
                original_target: dest.clone(),
                route_target: None,
                tag: String::new(),
            });

            let link = dispatcher.dispatch(outbound_session, dest).await?;
            let mut link_stream = new_link_stream(link);

            tokio::io::copy_bidirectional(conn, &mut link_stream).await
                .map_err(|e| format!("socks5 relay: {}", e))?;

            Ok(())
        }
        CMD_UDP_ASSOCIATE => {
            if !config.udp_enabled {
                write_all(conn, &socks5_error(STATUS_CMD_NOT_SUPPORTED)).await?;
                return Err("UDP not enabled".into());
            }
            write_all(conn, &socks5_response(any_ip(), Port(0))).await?;
            let mut buf = [0u8; 1024];
            loop {
                match conn.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    _ => {}
                }
            }
            Ok(())
        }
        CMD_BIND => {
            write_all(conn, &socks5_error(STATUS_CMD_NOT_SUPPORTED)).await?;
            Err("TCP BIND not supported".into())
        }
        _ => {
            write_all(conn, &socks5_error(STATUS_CMD_NOT_SUPPORTED)).await?;
            Err(format!("unknown cmd: {}", cmd))
        }
    }
}

impl Default for Handler {
    fn default() -> Self {
        Self::new()
    }
}
