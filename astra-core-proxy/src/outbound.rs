use astra_core_session::Session;
use astra_core_transport::{Link, UdpLink};

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

    /// Process UDP datagrams. Default returns an error.
    async fn process_udp(
        &self,
        _session: Session,
        _link: &mut UdpLink,
    ) -> ProxyResult<()> {
        Err("UDP not supported by this outbound".into())
    }
}
