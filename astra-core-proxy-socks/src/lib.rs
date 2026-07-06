use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use astra_core_net::{Address, Destination, Network, Port};
use astra_core_proxy::{async_trait, Conn, Dispatcher, InboundHandler, ProxyResult};
use astra_core_session::{Outbound, Session};
use astra_core_transport::new_link_stream;

#[derive(Default)]
pub struct Handler;

impl Handler {
    pub fn new() -> Self {
        Handler
    }
}

#[async_trait]
impl InboundHandler for Handler {
    async fn process(
        &self,
        session: Session,
        mut conn: Conn,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> ProxyResult<()> {
        let (mut reader, mut writer) = tokio::io::split(&mut conn);

        // 1. Handshake
        let mut initial = [0u8; 2];
        reader.read_exact(&mut initial).await
            .map_err(|e| format!("socks handshake initial read: {}", e))?;

        if initial[0] != 5 {
            return Err(format!("socks version must be 5, got {}", initial[0]));
        }

        let nmethods = initial[1] as usize;
        let mut methods = vec![0u8; nmethods];
        reader.read_exact(&mut methods).await
            .map_err(|e| format!("socks read methods: {}", e))?;

        // Reply: Version 5, No Auth
        writer.write_all(&[5, 0]).await
            .map_err(|e| format!("socks write auth choice: {}", e))?;

        // 2. Request
        let mut req_header = [0u8; 4];
        reader.read_exact(&mut req_header).await
            .map_err(|e| format!("socks read request header: {}", e))?;

        if req_header[0] != 5 {
            return Err("socks version in request must be 5".into());
        }
        if req_header[1] != 1 {
            // cmd: 1 = CONNECT
            // Reply with CMD not supported (0x07)
            let _ = writer.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            return Err(format!("socks unsupported command: {}", req_header[1]));
        }

        let address = match req_header[3] {
            1 => {
                // IPv4
                let mut ip_buf = [0u8; 4];
                reader.read_exact(&mut ip_buf).await
                    .map_err(|e| format!("socks read ipv4: {}", e))?;
                Address::Ipv4(ip_buf)
            }
            3 => {
                // Domain name
                let len = reader.read_u8().await
                    .map_err(|e| format!("socks read domain len: {}", e))? as usize;
                let mut domain_buf = vec![0u8; len];
                reader.read_exact(&mut domain_buf).await
                    .map_err(|e| format!("socks read domain: {}", e))?;
                let domain_str = String::from_utf8(domain_buf)
                    .map_err(|_| "socks invalid utf-8 domain name".to_string())?;
                Address::Domain(domain_str)
            }
            4 => {
                // IPv6
                let mut ip_buf = [0u8; 16];
                reader.read_exact(&mut ip_buf).await
                    .map_err(|e| format!("socks read ipv6: {}", e))?;
                Address::Ipv6(ip_buf)
            }
            _ => {
                // Address type not supported (0x08)
                let _ = writer.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                return Err(format!("socks unsupported address type: {}", req_header[3]));
            }
        };

        let port_num = reader.read_u16().await
            .map_err(|e| format!("socks read port: {}", e))?;
        let port = Port(port_num);

        let dest = Destination {
            address,
            port,
            network: Network::Tcp,
        };

        // Reply: Success, IPv4 address type, 0.0.0.0:0
        writer.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await
            .map_err(|e| format!("socks reply success: {}", e))?;

        // 3. Dispatch and copy
        let mut outbound_session = session.clone();
        outbound_session.outbound = Some(Outbound {
            target: dest.clone(),
            original_target: dest.clone(),
            route_target: None,
            tag: String::new(),
        });

        let link = dispatcher.dispatch(outbound_session, dest).await?;
        let mut link_stream = new_link_stream(link);

        // Reassemble tokio read/write split back to conn
        let mut conn = reader.unsplit(writer);

        tokio::io::copy_bidirectional(&mut conn, &mut link_stream)
            .await
            .map_err(|e| format!("socks relay copy: {}", e))?;

        Ok(())
    }
}
