use std::sync::Arc;

use astra_core_net::{Address, Destination, Network, Port};
use astra_core_proxy::{Dispatcher, InboundHandler, ProxyResult};
use astra_core_session::{Inbound, Session};
use tokio::net::TcpListener;
use tracing::info;

use crate::transport;

pub struct AlwaysOnInboundHandler {
    tag: String,
    proxy: Arc<dyn InboundHandler>,
    listen_addr: String,
    transport: transport::Transport,
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
        }
    }

    pub fn with_transport(mut self, t: transport::Transport) -> Self {
        self.transport = t;
        self
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

                        if let Err(e) = proxy.process(session, Box::new(conn), dispatcher).await {
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
