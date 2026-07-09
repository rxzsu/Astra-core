use tokio::io::{AsyncReadExt, AsyncWriteExt};

use astra_core_net::{ParseAddress, Port, TcpDestination};
use astra_core_proxy::{Dialer, OutboundHandler, ProxyResult, async_trait};
use astra_core_session::Session;
use astra_core_transport::Link;

use crate::config::ClientConfig;
use crate::protocol;

const MAX_CHUNK_SIZE: usize = 0x3FFF;

pub struct Handler {
    config: ClientConfig,
}

impl Handler {
    pub fn new(config: ClientConfig) -> Self {
        Handler { config }
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    async fn process(
        &self,
        session: Session,
        link: &mut Link,
        dialer: &dyn Dialer,
    ) -> ProxyResult<()> {
        let target = session
            .outbound
            .as_ref()
            .map(|o| o.target.clone())
            .ok_or_else(|| "trojan outbound: no target".to_string())?;

        let server_addr = ParseAddress(&self.config.server);
        let server_dest = TcpDestination(server_addr, Port(self.config.port));

        let mut conn = dialer.dial(session, server_dest).await?;

        let (mut conn_reader, mut conn_writer) = tokio::io::split(&mut conn);

        let header =
            protocol::write_tcp_header(&self.config.key, &target.address, target.port.value());
        conn_writer
            .write_all(&header)
            .await
            .map_err(|e| format!("trojan outbound: write header: {}", e))?;

        let link_reader = &mut link.reader;
        let link_writer = &mut link.writer;

        // link_reader -> conn_writer
        let to_server = async {
            let mut buf = vec![0u8; MAX_CHUNK_SIZE];
            loop {
                let n = link_reader
                    .read(&mut buf)
                    .await
                    .map_err(|e| format!("trojan outbound: link read: {}", e))?;
                if n == 0 {
                    break;
                }
                conn_writer
                    .write_all(&buf[..n])
                    .await
                    .map_err(|e| format!("trojan outbound: conn write: {}", e))?;
            }
            #[allow(unreachable_code)]
            Ok::<_, String>(())
        };

        // conn_reader -> link_writer
        let to_client = async {
            let mut buf = vec![0u8; MAX_CHUNK_SIZE];
            loop {
                let n = conn_reader
                    .read(&mut buf)
                    .await
                    .map_err(|e| format!("trojan outbound: conn read: {}", e))?;
                if n == 0 {
                    break;
                }
                link_writer
                    .write_all(&buf[..n])
                    .await
                    .map_err(|e| format!("trojan outbound: link write: {}", e))?;
            }
            #[allow(unreachable_code)]
            Ok::<_, String>(())
        };

        tokio::select! {
            r = to_server => r,
            r = to_client => r,
        }
    }
}
