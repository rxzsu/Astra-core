use std::collections::HashMap;
use std::sync::Arc;

use astra_core_dispatcher::DispatchHandler;
use astra_core_net::Destination;
use astra_core_proxy::{async_trait, AsyncConn, Dialer, OutboundHandler, ProxyResult};
use astra_core_session::Session;
use astra_core_transport::Link;
use tokio::net::TcpStream;

pub struct Handler {
    pub tag: String,
    proxy: Arc<dyn OutboundHandler>,
}

impl Handler {
    pub fn new(tag: String, proxy: Arc<dyn OutboundHandler>) -> Self {
        Handler { tag, proxy }
    }
}

#[async_trait]
impl Dialer for Handler {
    async fn dial(
        &self,
        _session: Session,
        dest: Destination,
    ) -> ProxyResult<Box<dyn AsyncConn>> {
        let addr = format!("{}:{}", dest.address, dest.port.value());
        let stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("dial {}: {}", addr, e))?;
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl DispatchHandler for Handler {
    async fn dispatch(&self, session: Session, link: &mut Link) -> ProxyResult<()> {
        self.proxy.process(session, link, self).await
    }
}

pub struct Manager {
    handlers: HashMap<String, Arc<dyn DispatchHandler>>,
    default_handler: Option<Arc<dyn DispatchHandler>>,
}

impl Default for Manager {
    fn default() -> Self {
        Self::new()
    }
}

impl Manager {
    pub fn new() -> Self {
        Manager {
            handlers: HashMap::new(),
            default_handler: None,
        }
    }

    pub fn add_handler(&mut self, tag: String, handler: Arc<dyn DispatchHandler>) {
        if self.default_handler.is_none() {
            self.default_handler = Some(handler.clone());
        }
        self.handlers.insert(tag, handler);
    }

    pub fn get_handler(&self, tag: &str) -> Option<&Arc<dyn DispatchHandler>> {
        self.handlers.get(tag)
    }

    pub fn get_default_handler(&self) -> Option<&Arc<dyn DispatchHandler>> {
        self.default_handler.as_ref()
    }
}
