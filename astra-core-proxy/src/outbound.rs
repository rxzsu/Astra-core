use astra_core_session::Session;
use astra_core_transport::Link;

use crate::dialer::Dialer;
use crate::ProxyResult;

#[async_trait::async_trait]
pub trait OutboundHandler: Send + Sync {
    async fn process(
        &self,
        session: Session,
        link: &mut Link,
        dialer: &dyn Dialer,
    ) -> ProxyResult<()>;
}
