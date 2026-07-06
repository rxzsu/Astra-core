use std::sync::Arc;

use astra_core_net::{Address, Destination, Network, Port};
use astra_core_proxy::{Conn, Dispatcher, InboundHandler, ProxyResult};
use astra_core_session::{Inbound, Session};
use tokio::net::TcpListener;
use tracing::info;

use crate::transport;

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

    async fn wrap_tls(
        &self,
        conn: tokio::net::TcpStream,
    ) -> ProxyResult<Conn> {
        if let Some(ref tls_cfg) = self.tls {
            if !tls_cfg.cert_data.is_empty() && !tls_cfg.key_data.is_empty() {
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
                return Ok(Box::new(tls_stream));
            }
        }
        Ok(Box::new(conn))
    }

    pub async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> ProxyResult<()> {
        let listen = self.listen_addr.clone();

        match &self.transport {
            transport::Transport::RawTcp => {
                let listener = TcpListener::bind(&listen)
                    .await
                    .map_err(|e| format!("bind {}: {}", listen, e))?;

                info!("inbound {} listening on {} (tcp)", self.tag, listen);

                loop {
                    let (conn, peer) = match listener.accept().await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::error!("accept error: {}", e);
                            continue;
                        }
                    };

                    let conn = self.wrap_tls(conn).await
                        .map_err(|e| format!("wrap_tls: {}", e))?;

                    let proxy = self.proxy.clone();
                    let dispatcher = dispatcher.clone();
                    let tag = self.tag.clone();

                    tokio::spawn(async move {
                        let address = if peer.is_ipv4() {
                            if let std::net::IpAddr::V4(v4) = peer.ip() {
                                Address::Ipv4(v4.octets())
                            } else {
                                unreachable!()
                            }
                        } else {
                            if let std::net::IpAddr::V6(v6) = peer.ip() {
                                Address::Ipv6(v6.octets())
                            } else {
                                unreachable!()
                            }
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
                            content: None,
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
