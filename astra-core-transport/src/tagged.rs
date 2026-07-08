use tokio::io::{AsyncRead, AsyncWrite};

/// Tagged dialer — dial through a specific outbound handler by tag.
/// Go equivalent: `transport/internet/tagged/tagged.go`

pub struct TaggedDialer {
    tag: String,
}

impl TaggedDialer {
    pub fn new(tag: &str) -> Self {
        TaggedDialer { tag: tag.to_string() }
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }
}

/// Combined read+write+unpin+send type for connections.
pub trait IoConn: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoConn for T {}

/// Dial function for tagged outbound.
pub async fn dial_tagged(
    _tag: &str,
    _addr: &str,
) -> Result<Box<dyn IoConn>, String> {
    Err("tagged dialer: not yet integrated with dispatcher".into())
}
