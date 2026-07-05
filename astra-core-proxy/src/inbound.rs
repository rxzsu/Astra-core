use std::sync::Arc;

use astra_core_session::Session;
use tokio::net::TcpStream;

use crate::dispatcher::Dispatcher;
use crate::ProxyResult;

#[async_trait::async_trait]
pub trait InboundHandler: Send + Sync {
    async fn process(
        &self,
        session: Session,
        conn: TcpStream,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> ProxyResult<()>;
}
