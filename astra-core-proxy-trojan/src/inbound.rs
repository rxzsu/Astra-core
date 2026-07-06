use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use astra_core_proxy::{async_trait, Conn, Dispatcher, InboundHandler, ProxyResult};
use astra_core_session::{Content, Inbound, Outbound, Session};

use crate::config::ServerConfig;
use crate::protocol;

const MAX_CHUNK_SIZE: usize = 0x3FFF;

pub struct Handler {
    config: ServerConfig,
}

impl Handler {
    pub fn new(config: ServerConfig) -> Self {
        Handler { config }
    }

    fn find_user(&self, key: &[u8; 56]) -> Option<usize> {
        self.config.users.iter().position(|u| &u.key == key)
    }
}

#[async_trait]
impl InboundHandler for Handler {
    async fn process(
        &self,
        _session: Session,
        conn: Conn,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> ProxyResult<()> {
        let (mut reader, mut writer) = tokio::io::split(conn);

        let header = protocol::read_header(&mut reader)
            .await
            .map_err(|e| format!("trojan inbound: parse header: {}", e))?;

        let _user_idx = self
            .find_user(&header.key)
            .ok_or_else(|| "trojan inbound: unknown user".to_string())?;

        let target = header.destination;
        let session = Session {
            inbound: Some(Inbound {
                source: target.clone(),
                local: None,
                gateway: None,
                tag: String::new(),
            }),
            outbound: Some(Outbound {
                target: target.clone(),
                original_target: target.clone(),
                route_target: None,
                tag: String::new(),
            }),
            content: Some(Content {
                protocol: Some("trojan".into()),
                ..Default::default()
            }),
        };

        // TCP only for now; UDP support can be added later
        if target.network != astra_core_net::Network::Tcp {
            return Err("trojan inbound: non-TCP not supported yet".into());
        }

        let mut link = dispatcher.dispatch(session, target).await?;

        let link_reader = &mut link.reader;
        let link_writer = &mut link.writer;

        // link_reader -> writer (to client)
        let to_client = async {
            let mut buf = vec![0u8; MAX_CHUNK_SIZE];
            loop {
                let n = link_reader
                    .read(&mut buf)
                    .await
                    .map_err(|e| format!("trojan inbound: link read: {}", e))?;
                if n == 0 {
                    break;
                }
                writer
                    .write_all(&buf[..n])
                    .await
                    .map_err(|e| format!("trojan inbound: conn write: {}", e))?;
            }
            #[allow(unreachable_code)]
            Ok::<_, String>(())
        };

        // reader (from client) -> link_writer
        let to_link = async {
            let mut buf = vec![0u8; MAX_CHUNK_SIZE];
            loop {
                let n = reader
                    .read(&mut buf)
                    .await
                    .map_err(|e| format!("trojan inbound: conn read: {}", e))?;
                if n == 0 {
                    break;
                }
                link_writer
                    .write_all(&buf[..n])
                    .await
                    .map_err(|e| format!("trojan inbound: link write: {}", e))?;
            }
            #[allow(unreachable_code)]
            Ok::<_, String>(())
        };

        tokio::select! {
            r = to_client => r,
            r = to_link => r,
        }
    }
}
