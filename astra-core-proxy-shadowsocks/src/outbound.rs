use tokio::io::{AsyncReadExt, AsyncWriteExt};

use astra_core_net::{ParseAddress, Port, TcpDestination};
use astra_core_proxy::{async_trait, Dialer, OutboundHandler, ProxyResult};
use astra_core_session::Session;
use astra_core_transport::Link;

use crate::config::ClientConfig;
use crate::protocol::SessionCipher;

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
            .ok_or_else(|| "ss outbound: no target".to_string())?;

        let server_addr = ParseAddress(&self.config.server);
        let server_dest = TcpDestination(server_addr, Port(self.config.port));

        let mut conn = dialer.dial(session, server_dest).await?;

        let (mut conn_reader, mut conn_writer) = tokio::io::split(&mut conn);

        let iv_size = self.config.cipher_type.iv_size();
        let mut iv = vec![0u8; iv_size];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut iv);

        conn_writer
            .write_all(&iv)
            .await
            .map_err(|e| format!("ss outbound: write iv: {}", e))?;

        let mut enc_cipher = SessionCipher::new(self.config.cipher_type, &self.config.key, &iv);

        // write target address as first chunk (nonce 0 includes port)
        let first_chunk = enc_cipher
            .encrypt_first_chunk(&target.address, target.port.value())
            .map_err(|e| format!("ss outbound: encrypt address: {}", e))?;
        conn_writer
            .write_all(&first_chunk)
            .await
            .map_err(|e| format!("ss outbound: write address: {}", e))?;

        // read response IV
        let mut resp_iv = vec![0u8; iv_size];
        conn_reader
            .read_exact(&mut resp_iv)
            .await
            .map_err(|e| format!("ss outbound: read resp iv: {}", e))?;

        let mut dec_cipher = SessionCipher::new(self.config.cipher_type, &self.config.key, &resp_iv);

        let nonce_size = self.config.cipher_type.nonce_size();
        let link_reader = &mut link.reader;
        let link_writer = &mut link.writer;

        // link_reader -> encrypt -> conn_writer
        let to_conn = async {
            let mut buf = vec![0u8; MAX_CHUNK_SIZE];
            loop {
                let n = link_reader
                    .read(&mut buf)
                    .await
                    .map_err(|e| format!("ss outbound: link read: {}", e))?;
                if n == 0 {
                    break;
                }
                let chunk = enc_cipher
                    .encrypt_chunk(&buf[..n])
                    .map_err(|e| format!("ss outbound: encrypt: {}", e))?;
                conn_writer
                    .write_all(&chunk)
                    .await
                    .map_err(|e| format!("ss outbound: conn write: {}", e))?;
            }
            #[allow(unreachable_code)]
            Ok::<_, String>(())
        };

        // conn_reader -> decrypt -> link_writer
        let to_link = async {
            let mut size_buf = [0u8; 2];
            loop {
                conn_reader
                    .read_exact(&mut size_buf)
                    .await
                    .map_err(|e| format!("ss outbound: read chunk size: {}", e))?;
                let total_len = u16::from_be_bytes(size_buf) as usize;
                if total_len == 0 {
                    break;
                }
                let mut chunk = vec![0u8; total_len];
                conn_reader
                    .read_exact(&mut chunk)
                    .await
                    .map_err(|e| format!("ss outbound: read chunk: {}", e))?;
                let pt = dec_cipher
                    .decrypt_chunk(&chunk[nonce_size..], &size_buf)
                    .map_err(|e| format!("ss outbound: decrypt: {}", e))?;
                link_writer
                    .write_all(&pt)
                    .await
                    .map_err(|e| format!("ss outbound: link write: {}", e))?;
            }
            #[allow(unreachable_code)]
            Ok::<_, String>(())
        };

        tokio::select! {
            r = to_conn => r,
            r = to_link => r,
        }
    }
}
