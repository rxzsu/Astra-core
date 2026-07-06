use std::sync::{Arc, Mutex};

use astra_core_net::{Destination, Network};
use astra_core_proxy::{async_trait, Dialer, Dispatcher, OutboundHandler, ProxyResult, UdpLink};
use astra_core_session::{Inbound, Outbound, Session};
use astra_core_transport::Link;

/// Shared cell for late-binding the dispatcher.
pub type DispatcherCell = Arc<Mutex<Option<Arc<dyn Dispatcher>>>>;

/// Loops traffic back into another inbound handler specified by inbound_tag.
pub struct Handler {
    inbound_tag: String,
    dispatcher_cell: DispatcherCell,
}

impl Handler {
    pub fn new(inbound_tag: String, dispatcher_cell: DispatcherCell) -> Self {
        Handler { inbound_tag, dispatcher_cell }
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    async fn process(
        &self,
        session: Session,
        link: &mut Link,
        _dialer: &dyn Dialer,
    ) -> ProxyResult<()> {
        let dispatcher = {
            let guard = self.dispatcher_cell
                .lock()
                .map_err(|_| "loopback: mutex poisoned".to_string())?;
            guard.as_ref().cloned()
        }.ok_or_else(|| "loopback: dispatcher not set".to_string())?;

        let target = session
            .outbound
            .as_ref()
            .map(|o| &o.target)
            .ok_or_else(|| "loopback: no target specified".to_string())?
            .clone();

        let mut loopback_session = session.clone();
        let mut inbound = session.inbound.clone().unwrap_or(Inbound {
            source: Destination { address: target.address.clone(), port: target.port, network: Network::Tcp },
            local: None,
            gateway: None,
            tag: String::new(),
        });
        inbound.tag = self.inbound_tag.clone();
        loopback_session.inbound = Some(inbound);
        loopback_session.outbound = Some(Outbound {
            target: target.clone(),
            original_target: target.clone(),
            route_target: None,
            tag: String::new(),
        });

        dispatcher.dispatch_link(loopback_session, target, link).await
    }

    async fn process_udp(&self, _session: Session, link: &mut UdpLink) -> ProxyResult<()> {
        while link.recv().await.is_some() {}
        Ok(())
    }
}

