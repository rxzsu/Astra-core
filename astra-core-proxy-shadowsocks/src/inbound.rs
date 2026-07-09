use std::sync::Arc;

use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use astra_core_proxy::{Conn, Dispatcher, InboundHandler, ProxyResult, async_trait};
use astra_core_session::{Content, Inbound, Outbound, Session};

use crate::config::ServerConfig;
use crate::protocol::{self, SessionCipher};

const MAX_CHUNK_SIZE: usize = 0x3FFF;

pub struct Handler {
    config: ServerConfig,
}

impl Handler {
    pub fn new(config: ServerConfig) -> Self {
        Handler { config }
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
        let user = &self.config.users[0];
        let (mut reader, mut writer) = tokio::io::split(conn);

        let iv_size = user.cipher_type.iv_size();
        let mut iv = vec![0u8; iv_size];
        reader
            .read_exact(&mut iv)
            .await
            .map_err(|e| format!("ss inbound: read iv: {}", e))?;

        let (dest, mut decrypting_reader) =
            protocol::read_tcp_session(reader, user.cipher_type, &user.key, &iv)
                .await
                .map_err(|e| format!("ss inbound: read session: {}", e))?;

        let target = dest;
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
                protocol: Some("shadowsocks".into()),
                ..Default::default()
            }),
        };

        let link = dispatcher.dispatch(session, target).await?;

        let mut resp_iv = vec![0u8; iv_size];
        rand::rng().fill_bytes(&mut resp_iv);
        writer
            .write_all(&resp_iv)
            .await
            .map_err(|e| format!("ss inbound: write resp iv: {}", e))?;

        let mut enc_cipher = SessionCipher::new(user.cipher_type, &user.key, &resp_iv);

        let mut link_writer = link.writer;
        let mut link_reader = link.reader;

        // conn -> decrypt -> link_writer
        let to_link = async {
            let mut buf = vec![0u8; MAX_CHUNK_SIZE];
            loop {
                let n = decrypting_reader
                    .read(&mut buf)
                    .await
                    .map_err(|e| format!("ss inbound: decrypt read: {}", e))?;
                if n == 0 {
                    break;
                }
                link_writer
                    .write_all(&buf[..n])
                    .await
                    .map_err(|e| format!("ss inbound: link write: {}", e))?;
            }
            #[allow(unreachable_code)]
            Ok::<_, String>(())
        };

        // link_reader -> encrypt -> conn
        let to_conn = async {
            let mut buf = vec![0u8; MAX_CHUNK_SIZE];
            loop {
                let n = link_reader
                    .read(&mut buf)
                    .await
                    .map_err(|e| format!("ss inbound: link read: {}", e))?;
                if n == 0 {
                    break;
                }
                let chunk = enc_cipher
                    .encrypt_chunk(&buf[..n])
                    .map_err(|e| format!("ss inbound: encrypt: {}", e))?;
                writer
                    .write_all(&chunk)
                    .await
                    .map_err(|e| format!("ss inbound: conn write: {}", e))?;
            }
            #[allow(unreachable_code)]
            Ok::<_, String>(())
        };

        tokio::select! {
            r = to_link => r,
            r = to_conn => r,
        }
    }
}
