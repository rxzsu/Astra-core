pub mod inbound;
pub mod outbound;
pub mod dispatcher;
pub mod dialer;

pub use inbound::InboundHandler;
pub use outbound::OutboundHandler;
pub use dispatcher::Dispatcher;
pub use dialer::{AsyncConn, Dialer};

pub type ProxyResult<T> = Result<T, String>;

/// Type-erased async connection usable as a bidirectional transport.
pub type Conn = Box<dyn AsyncConn>;

pub use async_trait::async_trait;
