use std::sync::Arc;

use astra_core_session::Session;

use crate::dispatcher::Dispatcher;
use crate::{Conn, ProxyResult};

#[async_trait::async_trait]
pub trait InboundHandler: Send + Sync {
    async fn process(
        &self,
        session: Session,
        conn: Conn,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> ProxyResult<()>;
}
