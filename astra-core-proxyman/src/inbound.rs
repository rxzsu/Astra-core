use std::sync::Arc;

use astra_core_net::{Address, Destination, Network, Port};
use astra_core_proxy::ProxyResult;
use astra_core_proxy::{Dispatcher, InboundHandler};
use astra_core_session::{Inbound, Session};
use tokio::net::TcpListener;
use tracing::info;

pub struct AlwaysOnInboundHandler {
    tag: String,
    proxy: Arc<dyn InboundHandler>,
    listen_addr: String,
}

impl AlwaysOnInboundHandler {
    pub fn new(tag: String, proxy: Arc<dyn InboundHandler>, listen_addr: String) -> Self {
        AlwaysOnInboundHandler {
            tag,
            proxy,
            listen_addr,
        }
    }

    pub async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> ProxyResult<()> {
        let listener = TcpListener::bind(&self.listen_addr)
            .await
            .map_err(|e| format!("bind {}: {}", self.listen_addr, e))?;

        info!("inbound {} listening on {}", self.tag, self.listen_addr);

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

                if let Err(e) = proxy.process(session, conn, dispatcher).await {
                    tracing::error!("inbound process error: {}", e);
                }
            });
        }
    }
}
