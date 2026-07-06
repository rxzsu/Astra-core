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
