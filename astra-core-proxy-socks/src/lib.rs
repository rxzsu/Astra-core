pub mod outbound;
pub mod protocol;

use std::sync::Arc;
use tokio::io::AsyncReadExt;

use astra_core_net::address::any_ip;
use astra_core_net::{Address, Destination, Network, Port};
use astra_core_proxy::{async_trait, Conn, Dispatcher, InboundHandler, ProxyResult};
use astra_core_session::{Outbound, Session};
use astra_core_transport::{new_link_stream, UdpPacket};

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
        let n = conn
            .read(&mut version_buf)
            .await
            .map_err(|e| format!("socks read: {}", e))?;
        if n == 0 {
            return Err("connection closed".into());
        }

        match version_buf[0] {
            SOCKS4_VERSION => handle_socks4(&self.config, &mut conn, &session, dispatcher).await,
            SOCKS5_VERSION => handle_socks5(&self.config, &mut conn, &session, dispatcher).await,
            _ => {
                // Not a SOCKS request — try HTTP CONNECT
                Err(format!(
                    "not a SOCKS request: byte=0x{:02x} (HTTP fallback not available)",
                    version_buf[0]
                ))
            }
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

    tokio::io::copy_bidirectional(conn, &mut link_stream)
        .await
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

    let (address, port) = read_socks5_addr_port(conn).await?;

    match cmd {
        CMD_CONNECT => tcp_connect(config, conn, session, dispatcher, address, port).await,
        CMD_UDP_ASSOCIATE => udp_associate(config, conn, session, dispatcher, address, port).await,
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

async fn read_socks5_addr_port(conn: &mut Conn) -> Result<(Address, Port), String> {
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
        _ => return Err(format!("unsupported addr type: {}", atyp)),
    };
    let port = Port(read_u16(conn).await?);
    Ok((addr, port))
}

async fn tcp_connect(
    _config: &SocksConfig,
    conn: &mut Conn,
    session: &Session,
    dispatcher: Arc<dyn Dispatcher>,
    address: Address,
    port: Port,
) -> ProxyResult<()> {
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

    tokio::io::copy_bidirectional(conn, &mut link_stream)
        .await
        .map_err(|e| format!("socks5 relay: {}", e))?;

    Ok(())
}

async fn udp_associate(
    config: &SocksConfig,
    conn: &mut Conn,
    session: &Session,
    dispatcher: Arc<dyn Dispatcher>,
    address: Address,
    port: Port,
) -> ProxyResult<()> {
    if !config.udp_enabled {
        write_all(conn, &socks5_error(STATUS_CMD_NOT_SUPPORTED)).await?;
        return Err("UDP not enabled".into());
    }

    let _udp_enabled = config.udp_enabled;
    let cone = config.cone;

    let outbound_session = {
        let mut s = session.clone();
        s.outbound = Some(Outbound {
            target: Destination {
                address: address.clone(),
                port,
                network: Network::Udp,
            },
            original_target: Destination {
                address: address.clone(),
                port,
                network: Network::Udp,
            },
            route_target: None,
            tag: String::new(),
        });
        s
    };

    let mut udp_link = dispatcher.dispatch_udp(outbound_session).await?;

    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("bind udp: {}", e))?;
    let bind_port = socket
        .local_addr()
        .map_err(|e| format!("local addr: {}", e))?
        .port();

    write_all(conn, &socks5_response(any_ip(), Port(bind_port))).await?;

    let socket = std::sync::Arc::new(socket);
    let client_addr = std::sync::Arc::new(tokio::sync::Mutex::<Option<std::net::SocketAddr>>::new(
        None,
    ));

    let link_writer = udp_link.writer.clone();
    let client_addr_clone = client_addr.clone();
    let socket_clone = socket.clone();

    // FullCone: lock the first destination for the session
    let cone_dest: Arc<std::sync::Mutex<Option<Destination>>> =
        Arc::new(std::sync::Mutex::new(None));

    // Read UDP packets from SOCKS client, parse and send through UdpLink
    let to_upstream = {
        let cone_dest = cone_dest.clone();
        tokio::spawn(async move {
            loop {
                let mut recv_buf = vec![0u8; 65535];
                match socket_clone.recv_from(&mut recv_buf).await {
                    Ok((n, src)) => {
                        *client_addr_clone.lock().await = Some(src);
                        if let Ok((addr, port, payload)) = decode_udp_packet(&recv_buf[..n]) {
                            let target = Destination {
                                address: addr,
                                port,
                                network: Network::Udp,
                            };
                            let target = if cone {
                                let mut guard = cone_dest.lock().unwrap();
                                if guard.is_some() {
                                    guard.clone().unwrap()
                                } else {
                                    *guard = Some(target.clone());
                                    target
                                }
                            } else {
                                target
                            };
                            let addr = match src.ip() {
                                std::net::IpAddr::V4(v4) => Address::Ipv4(v4.octets()),
                                std::net::IpAddr::V6(v6) => Address::Ipv6(v6.octets()),
                            };
                            let source = Destination {
                                address: addr,
                                port: Port(src.port()),
                                network: Network::Udp,
                            };
                            let pkt = UdpPacket::new(source, target, payload.to_vec());
                            if link_writer.send(pkt).is_err() {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        })
    };

    // Read responses from UdpLink, wrap in SOCKS UDP header, send back to client
    let from_upstream = tokio::spawn(async move {
        loop {
            match udp_link.reader.recv().await {
                Some(pkt) => {
                    let guard = client_addr.lock().await;
                    if let Some(addr) = *guard {
                        let response =
                            encode_udp_packet(&pkt.source.address, pkt.source.port, &pkt.data);
                        let _ = socket.send_to(&response, addr).await;
                    }
                }
                None => break,
            }
        }
    });

    // Keep TCP connection alive; exit when client closes it
    let mut keepalive = [0u8; 1];
    loop {
        match conn.read(&mut keepalive).await {
            Ok(0) | Err(_) => break,
            _ => {}
        }
    }

    let _ = to_upstream.await;
    let _ = from_upstream.await;
    Ok(())
}

impl Default for Handler {
    fn default() -> Self {
        Self::new()
    }
}
