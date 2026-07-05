use std::sync::Arc;

use astra_core_net::Destination;
use astra_core_proxy::{Dispatcher, ProxyResult, async_trait};
use astra_core_routing::Router;
use astra_core_session::{Outbound, Session};
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
    pub fn new(
        router: Arc<Router>,
        handler_provider: Arc<dyn HandlerProvider>,
    ) -> Self {
        DefaultDispatcher {
            router,
            handler_provider,
        }
    }

    async fn routed_dispatch(
        &self,
        mut session: Session,
        mut outbound_link: Link,
        dest: &Destination,
    ) -> ProxyResult<()> {
        session.outbound = Some(Outbound {
            target: dest.clone(),
            original_target: dest.clone(),
            route_target: None,
            tag: String::new(),
        });

        let handler = self
            .handler_provider
            .get_default_handler()
            .ok_or_else(|| "no outbound handler available".to_string())?;

        handler.dispatch(session, &mut outbound_link).await
    }
}

#[async_trait]
impl Dispatcher for DefaultDispatcher {
    async fn dispatch(
        &self,
        session: Session,
        dest: Destination,
    ) -> ProxyResult<Link> {
        let (inbound_link, outbound_link) = new_link_pair();

        let router = self.router.clone();
        let handler_provider = self.handler_provider.clone();

        tokio::spawn(async move {
            let dispatcher = DefaultDispatcher {
                router,
                handler_provider,
            };
            if let Err(e) = dispatcher.routed_dispatch(session, outbound_link, &dest).await {
                tracing::error!("dispatch error: {}", e);
            }
        });

        Ok(inbound_link)
    }
}
