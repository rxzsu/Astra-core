use std::pin::Pin;
use std::task::{Context, Poll};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

pub mod manager;
pub mod mask;

pub use manager::{TcpmaskManager, UdpmaskManager};
pub use mask::{Tcpmask, Udpmask, TcpMaskConn};
