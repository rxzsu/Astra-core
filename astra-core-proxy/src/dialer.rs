use astra_core_net::Destination;
use astra_core_session::Session;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::ProxyResult;

/// Combined trait for an async duplex connection.
pub trait AsyncConn: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncConn for T {}

#[async_trait::async_trait]
pub trait Dialer: Send + Sync {
    async fn dial(
        &self,
        session: Session,
        dest: Destination,
    ) -> ProxyResult<Box<dyn AsyncConn>>;
}
