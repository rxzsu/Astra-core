use std::sync::Arc;

use astra_core_net::{Address, Destination, Network, Port};
use astra_core_proxy::{Conn, Dispatcher, InboundHandler, ProxyResult};
use astra_core_session::{Inbound, Session};
use tokio::net::TcpListener;
use tracing::info;

use crate::transport;

#[derive(Clone, Copy, PartialEq)]
pub enum ListenNetwork {
    Tcp,
    Udp,
    Both,
}

impl ListenNetwork {
    pub fn from_str(s: &str) -> Self {
        match s {
            "udp" => ListenNetwork::Udp,
            "tcp,udp" | "tcp, udp" | "both" => ListenNetwork::Both,
            _ => ListenNetwork::Tcp,
        }
    }

    pub fn has_udp(self) -> bool {
        self == ListenNetwork::Udp || self == ListenNetwork::Both
    }

    pub fn has_tcp(self) -> bool {
        self == ListenNetwork::Tcp || self == ListenNetwork::Both
    }
}

#[derive(Clone)]
pub struct TlsConfig {
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub cert_data: Vec<u8>,
    pub key_data: Vec<u8>,
}

pub struct AlwaysOnInboundHandler {
    tag: String,
    proxy: Arc<dyn InboundHandler>,
    listen_addr: String,
    transport: transport::Transport,
    tls: Option<TlsConfig>,
    network: ListenNetwork,
}

impl AlwaysOnInboundHandler {
    pub fn new(
        tag: String,
        proxy: Arc<dyn InboundHandler>,
        listen_addr: String,
    ) -> Self {
        AlwaysOnInboundHandler {
            tag,
            proxy,
            listen_addr,
            transport: transport::Transport::RawTcp,
            tls: None,
            network: ListenNetwork::Tcp,
        }
    }

    pub fn with_transport(mut self, t: transport::Transport) -> Self {
        self.transport = t;
        self
    }

    pub fn with_tls(mut self, tls: TlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    pub fn with_network(mut self, network: ListenNetwork) -> Self {
        self.network = network;
        self
    }

    /// Static TLS wrapping for a Conn.
    async fn tls_wrap(conn: Conn, tls_cfg: &TlsConfig) -> ProxyResult<Conn> {
        if tls_cfg.cert_data.is_empty() || tls_cfg.key_data.is_empty() {
            return Ok(conn);
        }
        let cert = rustls::pki_types::CertificateDer::from(tls_cfg.cert_data.clone());
        let key = rustls::pki_types::PrivateKeyDer::try_from(tls_cfg.key_data.clone())
            .map_err(|e| format!("invalid tls key: {:?}", e))?;

        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| format!("tls config: {}", e))?;

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
        let tls_stream = acceptor.accept(conn).await
            .map_err(|e| format!("tls accept: {}", e))?;
        Ok(Box::new(tls_stream))
    }

    pub async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> ProxyResult<()> {
        let listen = self.listen_addr.clone();

        match &self.transport {
            transport::Transport::RawTcp => {
                if self.network.has_udp() {
                    let udp_socket = Arc::new(
                        tokio::net::UdpSocket::bind(&listen)
                            .await
                            .map_err(|e| format!("bind udp {}: {}", listen, e))?,
                    );
                    let udp_dispatcher = dispatcher.clone();
                    let udp_tag = self.tag.clone();

                    info!("inbound {} listening on {} (udp)", self.tag, listen);

                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65535];
                        loop {
                            let (n, peer) = match udp_socket.recv_from(&mut buf).await {
                                Ok(r) => r,
                                Err(_) => break,
                            };
                            let data = buf[..n].to_vec();

                            let source_addr = match peer.ip() {
                                std::net::IpAddr::V4(v4) => Address::Ipv4(v4.octets()),
                                std::net::IpAddr::V6(v6) => Address::Ipv6(v6.octets()),
                            };

                            let session = Session {
                                inbound: Some(Inbound {
                                    source: Destination {
                                        address: source_addr,
                                        port: Port(peer.port()),
                                        network: Network::Udp,
                                    },
                                    local: None,
                                    gateway: None,
                                    tag: udp_tag.clone(),
                                }),
                                outbound: None,
                                content: None,
                            };

                            let mut udp_link = match udp_dispatcher.dispatch_udp(session).await {
                                Ok(link) => link,
                                Err(_) => continue,
                            };

                            let placeholder = Destination {
                                address: Address::Ipv4([0, 0, 0, 0]),
                                port: Port(0),
                                network: Network::Udp,
                            };
                            let pkt = astra_core_transport::UdpPacket::new(
                                placeholder.clone(), placeholder, data,
                            );
                            let _ = udp_link.send(pkt);

                            let resp = tokio::time::timeout(
                                std::time::Duration::from_secs(10),
                                udp_link.recv(),
                            )
                            .await
                            .ok()
                            .flatten();

                            if let Some(pkt) = resp {
                                let _ = udp_socket.send_to(&pkt.data, peer).await;
                            }
                        }
                    });
                }

                if !self.network.has_tcp() {
                    return Ok(());
                }

                let listener = TcpListener::bind(&listen)
                    .await
                    .map_err(|e| format!("bind {}: {}", listen, e))?;

                info!("inbound {} listening on {} (tcp)", self.tag, listen);

                let tls_cfg = self.tls.clone();

                loop {
                    let (mut conn, peer) = match listener.accept().await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::error!("accept error: {}", e);
                            continue;
                        }
                    };

                    let proxy = self.proxy.clone();
                    let dispatcher = dispatcher.clone();
                    let tag = self.tag.clone();
                    let tls = tls_cfg.clone();

                    tokio::spawn(async move {
                        let address = match peer.ip() {
                            std::net::IpAddr::V4(v4) => Address::Ipv4(v4.octets()),
                            std::net::IpAddr::V6(v6) => Address::Ipv6(v6.octets()),
                        };

                        // Sniff initial bytes for protocol detection
                        let mut sniff_buf = vec![0u8; 8192];
                        let (sniff_result, conn) = match tokio::io::AsyncReadExt::read(&mut conn, &mut sniff_buf).await {
                            Ok(0) | Err(_) => {
                                (astra_core_sniffing::SniffResult::default(), Box::new(conn) as Conn)
                            }
                            Ok(n) => {
                                let data = sniff_buf[..n].to_vec();
                                let result = astra_core_sniffing::sniff(&data);
                                let wrapped = astra_core_sniffing::SniffedStream::new(conn, data);
                                (result, Box::new(wrapped) as Conn)
                            }
                        };

                        // Wrap in TLS if configured
                        let conn = match tls {
                            Some(ref tls_cfg) => {
                                match Self::tls_wrap(conn, tls_cfg).await {
                                    Ok(c) => c,
                                    Err(e) => {
                                        tracing::error!("tls wrap error: {}", e);
                                        return;
                                    }
                                }
                            }
                            None => conn,
                        };

                        let protocol = sniff_result.protocol.as_str();
                        let domain = sniff_result.domain.clone();

                        let content = if !protocol.is_empty() || domain.is_some() {
                            let mut c = astra_core_session::Content::default();
                            if !protocol.is_empty() {
                                c.protocol = Some(protocol.to_string());
                            }
                            if let Some(d) = domain {
                                c.attributes.insert("sniffed_domain".to_string(), d);
                            }
                            Some(c)
                        } else {
                            None
                        };

                        let session = Session {
                            inbound: Some(Inbound {
                                source: Destination {
                                    address,
                                    port: Port(peer.port()),
                                    network: Network::Tcp,
                                },
                                local: None,
                                gateway: None,
                                tag,
                            }),
                            outbound: None,
                            content,
                        };

                        if let Err(e) = proxy.process(session, conn, dispatcher).await {
                            tracing::error!("inbound process error: {}", e);
                        }
                    });
                }
            }
            transport::Transport::Quic(_quic_cfg) => {
                info!("inbound {} listening on {} (quic)", self.tag, listen);

                let tls_cfg = self.tls.as_ref().ok_or_else(|| {
                    "QUIC inbound requires TLS config with certificates".to_string()
                })?;

                let cert = rustls::pki_types::CertificateDer::from(tls_cfg.cert_data.clone());
                let key = rustls::pki_types::PrivateKeyDer::try_from(tls_cfg.key_data.clone())
                    .map_err(|e| format!("invalid tls key: {:?}", e))?;

                let tls_config = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(vec![cert], key)
                    .map_err(|e| format!("tls config: {}", e))?;

                let quic_tls: quinn::crypto::rustls::QuicServerConfig = tls_config
                    .try_into()
                    .map_err(|e: quinn::crypto::rustls::NoInitialCipherSuite| format!("QUIC TLS: {}", e))?;

                let mut quic_server = quinn::ServerConfig::with_crypto(
                    std::sync::Arc::new(quic_tls)
                );
                let mut transport_cfg = quinn::TransportConfig::default();
                transport_cfg.max_concurrent_bidi_streams(100u32.into());
                quic_server.transport_config(std::sync::Arc::new(transport_cfg));

                let listen_addr: std::net::SocketAddr = listen
                    .parse()
                    .map_err(|e| format!("invalid listen address: {}", e))?;
                let endpoint = quinn::Endpoint::server(quic_server, listen_addr)
                    .map_err(|e| format!("create QUIC endpoint: {}", e))?;

                let proxy = self.proxy.clone();
                let dispatcher = dispatcher.clone();
                let tag = self.tag.clone();

                loop {
                    match endpoint.accept().await {
                        Some(connecting) => {
                            let proxy = proxy.clone();
                            let dispatcher = dispatcher.clone();
                            let tag = tag.clone();

                            tokio::spawn(async move {
                                match connecting.await {
                                    Ok(conn) => {
                                        if let Ok((send, recv)) = conn.accept_bi().await {
                                            let stream = astra_core_transport_quic::connection::QuicStream::new(send, recv);
                                            let session = Session {
                                                inbound: Some(Inbound {
                                                    source: Destination {
                                                        address: Address::Ipv4([0, 0, 0, 0]),
                                                        port: Port(0),
                                                        network: Network::Tcp,
                                                    },
                                                    local: None,
                                                    gateway: None,
                                                    tag,
                                                }),
                                                outbound: None,
                                                content: None,
                                            };

                                            if let Err(e) = proxy.process(session, Box::new(stream), dispatcher).await {
                                                tracing::error!("inbound process error: {}", e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!("QUIC accept error: {}", e);
                                    }
                                }
                            });
                        }
                        None => break,
                    }
                }

                Ok(())
            }
            _ => {
                info!(
                    "inbound {} listening on {} ({})",
                    self.tag,
                    listen,
                    self.transport.as_network_type()
                );

                let proxy = self.proxy.clone();
                let dispatcher = dispatcher.clone();
                let tag = self.tag.clone();

                transport::serve_transport(&self.transport, &listen, move |conn| {
                    let proxy = proxy.clone();
                    let dispatcher = dispatcher.clone();
                    let tag = tag.clone();

                    tokio::spawn(async move {
                        let session = Session {
                            inbound: Some(Inbound {
                                source: Destination {
                                    address: Address::Ipv4([0, 0, 0, 0]),
                                    port: Port(0),
                                    network: Network::Tcp,
                                },
                                local: None,
                                gateway: None,
                                tag,
                            }),
                            outbound: None,
                            content: None,
                        };

                        if let Err(e) = proxy.process(session, conn, dispatcher).await {
                            tracing::error!("inbound process error: {}", e);
                        }
                    });
                })
                .await?;

                Ok(())
            }
        }
    }
}
