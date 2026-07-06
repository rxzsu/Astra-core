use astra_core_net::Destination;
use astra_core_session::Session;
use astra_core_transport::{Link, UdpLink};

use crate::ProxyResult;

#[async_trait::async_trait]
pub trait Dispatcher: Send + Sync {
    async fn dispatch(
        &self,
        session: Session,
        dest: Destination,
    ) -> ProxyResult<Link>;

    async fn dispatch_udp(
        &self,
        session: Session,
    ) -> ProxyResult<UdpLink>;

    /// Dispatch using an existing link instead of creating a new one.
    /// Used by loopback outbound for re-dispatching traffic.
    async fn dispatch_link(
        &self,
        session: Session,
        dest: Destination,
        link: &mut Link,
    ) -> ProxyResult<()>;
}
