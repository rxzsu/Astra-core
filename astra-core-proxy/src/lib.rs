pub mod dialer;
pub mod dispatcher;
pub mod inbound;
pub mod outbound;
pub mod timeout;

pub use astra_core_transport::UdpLink;
pub use dialer::{AsyncConn, Dialer};
pub use dispatcher::Dispatcher;
pub use inbound::InboundHandler;
pub use outbound::OutboundHandler;

pub type ProxyResult<T> = Result<T, String>;

/// Type-erased async connection usable as a bidirectional transport.
pub type Conn = Box<dyn AsyncConn>;

pub use async_trait::async_trait;
