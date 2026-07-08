use std::sync::Arc;

use astra_core_config::transport as cfg;
use astra_core_net::Destination;
use astra_core_proxy::Conn;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub use astra_core_proxy::ProxyResult;

/// Transport protocol selection for outbound connections.
#[derive(Clone)]
#[derive(Default)]
pub enum Transport {
    #[default]
    RawTcp,
    WebSocket {
        host: String,
        path: String,
        headers: Vec<(String, String)>,
    },
    HttpUpgrade(astra_core_transport_httpupgrade::config::Config),
    Kcp(astra_core_transport_kcp::config::Config),
    Grpc {
        service_name: String,
    },
    SplitHttp(astra_core_transport_splithttp::config::Config),
    Quic(astra_core_transport_quic::config::QuicConfig),
    H2 {
        host: String,
        path: String,
    },
}


impl Transport {
    pub fn from_stream_config(stream: &cfg::StreamConfig) -> Self {
        if stream.network.is_h2() {
            let host = stream.http_settings
                .as_ref()
                .and_then(|h| h.host.first())
                .cloned()
                .unwrap_or_default();
            let path = stream.http_settings
                .as_ref()
                .map(|h| h.path.clone())
                .filter(|p| !p.is_empty())
                .unwrap_or_else(|| "/".into());
            return Self::H2 { host, path };
        }
        if let Some(kcp) = &stream.kcp_settings {
            return Self::Kcp(astra_core_transport_kcp::config::Config {
                mtu: kcp.mtu.unwrap_or(1350),
                tti: kcp.tti.unwrap_or(50),
                uplink_capacity: kcp.uplink_capacity.unwrap_or(5),
                downlink_capacity: kcp.downlink_capacity.unwrap_or(20),
                cwnd_multiplier: 1,
                max_sending_window: 2 * 1024 * 1024,
            });
        }
        if let Some(ws) = &stream.ws_settings {
            let headers = ws
                .headers
                .as_ref()
                .and_then(|v| v.as_object())
                .map(|obj| {
                    obj.iter()
                        .map(|(k, v)| {
                            (k.clone(), v.as_str().unwrap_or_default().to_string())
                        })
                        .collect()
                })
                .unwrap_or_default();
            return Self::WebSocket {
                host: ws.host.clone(),
                path: if ws.path.is_empty() {
                    "/".into()
                } else {
                    ws.path.clone()
                },
                headers,
            };
        }
        if let Some(http) = &stream.httpupgrade_settings {
            return Self::HttpUpgrade(astra_core_transport_httpupgrade::config::Config {
                host: http.host.clone(),
                path: http.path.clone(),
                headers: http
                    .headers
                    .as_ref()
                    .and_then(|v| v.as_object())
                    .map(|obj| {
                        obj.iter()
                            .map(|(k, v)| {
                                (k.clone(), v.as_str().unwrap_or_default().to_string())
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                accept_proxy_protocol: http.accept_proxy_protocol,
            });
        }
        if let Some(grpc) = &stream.grpc_settings {
            return Self::Grpc {
                service_name: grpc.service_name.clone(),
            };
        }
        if let Some(sh) = &stream.splithttp_settings {
            return Self::SplitHttp(
                astra_core_transport_splithttp::config::Config::from_stream_config(sh),
            );
        }
        if let Some(quic) = &stream.quic_settings {
            return Self::Quic(quic.into());
        }
        Self::RawTcp
    }

    pub fn as_network_type(&self) -> &str {
        match self {
            Self::RawTcp => "tcp",
            Self::WebSocket { .. } => "websocket",
            Self::HttpUpgrade(_) => "httpupgrade",
            Self::Kcp(_) => "mkcp",
            Self::Grpc { .. } => "grpc",
            Self::SplitHttp(_) => "splithttp",
            Self::Quic(_) => "quic",
            Self::H2 { .. } => "h2",
        }
    }
}

/// Dial a connection using the configured transport.
/// `bind_address` — optional source IP for send_through support.
pub async fn dial_transport(
    transport: &Transport,
    dest: &Destination,
    bind_address: Option<&str>,
) -> ProxyResult<Conn> {
    let addr_str = format!("{}:{}", dest.address, dest.port.value());

    match transport {
        Transport::Kcp(kcp_cfg) => {
            use std::net::SocketAddr;
            let remote: SocketAddr = addr_str
                .parse()
                .map_err(|e| format!("kcp parse addr: {}", e))?;
            let bind: SocketAddr = if remote.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            };

            let kcp_conn =
                astra_core_transport_kcp::dialer::dial_kcp(bind, remote, kcp_cfg.clone())
                    .await
                    .map_err(|e| format!("kcp dial: {}", e))?;

            let (client, server) = tokio::io::duplex(64 * 1024);
            let (mut server_reader, mut server_writer) = tokio::io::split(server);
            let c = kcp_conn.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    let n = match c.read_bytes(&mut buf).await {
                        Ok(n) if n > 0 => n,
                        _ => break,
                    };
                    if server_writer.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    let n = match server_reader.read(&mut buf).await {
                        Ok(n) if n > 0 => n,
                        _ => break,
                    };
                    if kcp_conn.write_bytes(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });

            Ok(Box::new(client))
        }
        Transport::WebSocket {
            host,
            path,
            headers,
        } => {
            let ws_cfg = astra_core_transport_ws::dialer::WsDialerConfig {
                host: host.clone(),
                path: path.clone(),
                headers: headers.clone(),
            };
            let ws_conn = astra_core_transport_ws::dialer::dial_ws(dest, &ws_cfg)
                .await
                .map_err(|e| format!("ws dial: {}", e))?;
            Ok(Box::new(ws_conn))
        }
        Transport::HttpUpgrade(http_cfg) => {
            let tcp =
                astra_core_transport_httpupgrade::dialer::dial(dest, http_cfg)
                    .await
                    .map_err(|e| format!("httpupgrade dial: {}", e))?;
            Ok(Box::new(tcp))
        }
        Transport::SplitHttp(sh_cfg) => {
            let cfg = Arc::new(sh_cfg.clone());
            astra_core_transport_splithttp::dialer::dial(dest, &cfg).await
        }
        Transport::Grpc { service_name } => {
            let config = astra_core_transport_grpc::dialer::GrpcDialerConfig {
                service_name: service_name.clone(),
                multi_mode: false,
            };
            let hunk = astra_core_transport_grpc::dialer::dial_grpc(dest, &config)
                .await
                .map_err(|e| format!("grpc dial: {}", e))?;
            Ok(Box::new(hunk))
        }
        Transport::Quic(quic_cfg) => {
            let quic_conn = astra_core_transport_quic::dialer::dial_quic(dest, quic_cfg)
                .await
                .map_err(|e| format!("quic dial: {}", e))?;
            Ok(Box::new(quic_conn))
        }
        Transport::H2 { host, path } => {
            astra_core_transport_h2::dialer::dial_h2(dest, host, path).await
        }
        Transport::RawTcp => {
            // support send_through (bind to specific source IP)
            let is_ipv6 = addr_str.contains("]:") || addr_str.matches(':').count() > 1;
            let socket = if is_ipv6 {
                tokio::net::TcpSocket::new_v6()
                    .map_err(|e| format!("create socket: {}", e))?
            } else {
                tokio::net::TcpSocket::new_v4()
                    .map_err(|e| format!("create socket: {}", e))?
            };

            // send_through: bind to specific source IP before connect
            if let Some(bind_ip) = bind_address {
                let bind_addr: std::net::SocketAddr = format!("{}:0", bind_ip)
                    .parse()
                    .map_err(|e| format!("invalid bind address {}: {}", bind_ip, e))?;
                socket.bind(bind_addr)
                    .map_err(|e| format!("bind {}: {}", bind_ip, e))?;
            }
            let tcp = socket.connect(addr_str.parse::<std::net::SocketAddr>()
                .map_err(|e| format!("parse addr {}: {}", addr_str, e))?)
                .await
                .map_err(|e| format!("connect {}: {}", addr_str, e))?;
            Ok(Box::new(tcp))
        }
    }
}

/// Listen for incoming proxy connections using the configured transport.
pub async fn serve_transport<F>(
    transport: &Transport,
    listen_addr: &str,
    on_conn: F,
) -> ProxyResult<()>
where
    F: Fn(Conn) + Send + Sync + 'static,
{
    match transport {
        Transport::Kcp(kcp_cfg) => {
            let addr: std::net::SocketAddr = listen_addr
                .parse()
                .map_err(|e| format!("kcp listen addr: {}", e))?;
            let handler: Arc<dyn Fn(Arc<astra_core_transport_kcp::connection::Connection>) + Send + Sync> =
                Arc::new(move |kcp_conn| {
                    let (client, server) = tokio::io::duplex(64 * 1024);
                    let (mut server_reader, mut server_writer) = tokio::io::split(server);
                    let c = kcp_conn.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65536];
                        loop {
                            let n = match c.read_bytes(&mut buf).await {
                                Ok(n) if n > 0 => n,
                                _ => break,
                            };
                            if server_writer.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    });
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65536];
                        loop {
                            let n = match server_reader.read(&mut buf).await {
                                Ok(n) if n > 0 => n,
                                _ => break,
                            };
                            if kcp_conn.write_bytes(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    });
                    on_conn(Box::new(client));
                });

            astra_core_transport_kcp::listener::listen_kcp(addr, kcp_cfg.clone(), handler)
                .await
                .map_err(|e| format!("kcp listen: {}", e))?;
            Ok(())
        }
        Transport::WebSocket { host, path, .. } => {
            let ws_cfg = astra_core_transport_ws::listener::WsListenerConfig {
                host: host.clone(),
                path: path.clone(),
            };
            let handler: Arc<dyn Fn(astra_core_transport_ws::connection::WsConnection<tokio::net::TcpStream>) + Send + Sync> =
                Arc::new(move |ws_conn| {
                    on_conn(Box::new(ws_conn));
                });

            astra_core_transport_ws::listener::serve_ws(listen_addr, ws_cfg, handler)
                .await
                .map_err(|e| format!("ws listen: {}", e))?;
            Ok(())
        }
        Transport::HttpUpgrade(http_cfg) => {
            let handler_cb = Arc::new(move |tcp: tokio::net::TcpStream| {
                on_conn(Box::new(tcp));
            });

            astra_core_transport_httpupgrade::listener::serve(listen_addr, http_cfg.clone(), handler_cb)
                .await
                .map_err(|e| format!("httpupgrade listen: {}", e))?;
            Ok(())
        }
        Transport::SplitHttp(sh_cfg) => {
            let listener =
                astra_core_transport_splithttp::listener::SplitHTTPListener::new(sh_cfg.clone());
            listener.serve(listen_addr, on_conn).await
        }
        // QUIC inbound is handled separately via the inbound TLS config
        // because QUIC requires TLS natively.
        Transport::Quic(_) => {
            Err("quic inbound: use TLS transport config".into())
        }
        Transport::Grpc { service_name: _ } => {
            use astra_core_transport_grpc::listener as grpc_listener;
            let handler: grpc_listener::GrpcConnHandler = Arc::new(move |hunk| {
                on_conn(Box::new(hunk));
            });
            grpc_listener::serve_grpc(listen_addr, handler)
                .await
                .map_err(|e| format!("grpc serve: {}", e))?;
            Ok(())
        }
        Transport::H2 { .. } => {
            Err("h2 inbound: use TLS transport config".into())
        }
        Transport::RawTcp => {
            let listener = tokio::net::TcpListener::bind(listen_addr)
                .await
                .map_err(|e| format!("bind {}: {}", listen_addr, e))?;
            loop {
                let (conn, _) = listener
                    .accept()
                    .await
                    .map_err(|e| format!("accept: {}", e))?;
                // Accept PROXY protocol if configured
                // The PROXY header parsing happens in the inbound handler
                on_conn(Box::new(conn));
            }
        }
    }
}
