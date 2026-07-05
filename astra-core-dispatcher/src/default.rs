use std::sync::Arc;

use astra_core_net::Destination;
use astra_core_proxy::{async_trait, Dispatcher, ProxyResult};
use astra_core_routing::{Router, RoutingContext};
use astra_core_session::Session;
use astra_core_transport::{new_link_pair, Link};

use crate::DispatchHandler;

pub struct DefaultDispatcher {
    router: Arc<Router>,
    handler_provider: Arc<dyn HandlerProvider>,
}

pub trait HandlerProvider: Send + Sync {
    fn get_handler(&self, tag: &str) -> Option<Arc<dyn DispatchHandler>>;
    fn get_default_handler(&self) -> Option<Arc<dyn DispatchHandler>>;
}

impl DefaultDispatcher {
    pub fn new(router: Arc<Router>, handler_provider: Arc<dyn HandlerProvider>) -> Self {
        DefaultDispatcher { router, handler_provider }
    }

    fn build_routing_context(session: &Session) -> RoutingContext {
        let mut ctx = RoutingContext::default();
        if let Some(ref ob) = session.outbound {
            ctx.target_domain = ob.target.address.as_domain().map(String::from);
            ctx.target_ip = ob.target.address.as_ip();
            ctx.target_port = ob.target.port.value();
        }
        if let Some(ref ib) = session.inbound {
            ctx.source_ip = ib.source.address.as_ip();
            ctx.source_port = ib.source.port.value();
            ctx.inbound_tag = ib.tag.clone();
        }
        if let Some(ref content) = session.content {
            ctx.protocol = content.protocol.clone();
            ctx.attributes = content.attributes.clone();
        }
        ctx
    }

    async fn routed_dispatch(
        &self,
        mut session: Session,
        mut outbound_link: Link,
        _dest: &Destination,
    ) -> ProxyResult<()> {
        let outbound_tag = {
            let ctx = Self::build_routing_context(&session);
            match self.router.pick_route(&ctx) {
                Some(r) => {
                    session.outbound.as_mut().map(|o| o.tag = r.outbound_tag.clone());
                    r.outbound_tag
                }
                None => String::new(),
            }
        };

        let handler = if !outbound_tag.is_empty() {
            self.handler_provider.get_handler(&outbound_tag)
        } else {
            self.handler_provider.get_default_handler()
        };

        let handler = handler.ok_or_else(|| "no outbound handler available".to_string())?;
        handler.dispatch(session, &mut outbound_link).await
    }
}

#[async_trait]
impl Dispatcher for DefaultDispatcher {
    async fn dispatch(&self, session: Session, dest: Destination) -> ProxyResult<Link> {
        let (inbound_link, outbound_link) = new_link_pair();

        let router = self.router.clone();
        let handler_provider = self.handler_provider.clone();

        tokio::spawn(async move {
            let dispatcher = DefaultDispatcher { router, handler_provider };
            if let Err(e) = dispatcher.routed_dispatch(session, outbound_link, &dest).await {
                tracing::error!("dispatch error: {}", e);
            }
        });

        Ok(inbound_link)
    }
}
