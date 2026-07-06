mod default;

pub use default::{DefaultDispatcher, HandlerProvider};
pub use astra_core_dns::DnsResolver;

use astra_core_proxy::{async_trait, ProxyResult};
use astra_core_session::Session;
use astra_core_transport::{Link, UdpLink};

/// Higher-level dispatch interface implemented by the proxyman outbound Handler.
/// Wraps the raw OutboundHandler with dialer logic, mux, proxy chaining, etc.
#[async_trait]
pub trait DispatchHandler: Send + Sync {
    async fn dispatch(&self, session: Session, link: &mut Link) -> ProxyResult<()>;

    async fn dispatch_udp(&self, session: Session, link: &mut UdpLink) -> ProxyResult<()>;
}
