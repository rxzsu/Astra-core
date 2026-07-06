use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use astra_core_net::{Destination, Network, Port, ParseAddress};
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
        conn: Conn,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> ProxyResult<()> {
        let mut reader = BufReader::new(conn);
        let mut first_line = String::new();
        reader.read_line(&mut first_line).await
            .map_err(|e| format!("http proxy read request line: {}", e))?;

        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err("invalid HTTP request line".into());
        }

        let method = parts[0];
        let uri = parts[1];

        if method.to_uppercase() != "CONNECT" {
            // Write 405 Method Not Allowed if not CONNECT for simplicity
            let mut conn = reader.into_inner();
            let _ = conn.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n").await;
            return Err(format!("unsupported HTTP method: {}", method));
        }

        // Parse host:port from uri
        let uri_parts: Vec<&str> = uri.split(':').collect();
        if uri_parts.len() != 2 {
            let mut conn = reader.into_inner();
            let _ = conn.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            return Err(format!("invalid HTTP CONNECT URI: {}", uri));
        }

        let host = uri_parts[0];
        let port_num: u16 = uri_parts[1].parse()
            .map_err(|_| format!("invalid port in URI: {}", uri_parts[1]))?;

        let address = ParseAddress(host);
        let dest = Destination {
            address,
            port: Port(port_num),
            network: Network::Tcp,
        };

        // Read and discard remaining headers up to empty line
        loop {
            let mut header_line = String::new();
            reader.read_line(&mut header_line).await
                .map_err(|e| format!("http proxy read header: {}", e))?;
            if header_line == "\r\n" || header_line == "\n" || header_line.is_empty() {
                break;
            }
        }

        let mut conn = reader.into_inner();

        // Write success response
        conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await
            .map_err(|e| format!("http reply success: {}", e))?;

        // Dispatch and copy
        let mut outbound_session = session.clone();
        outbound_session.outbound = Some(Outbound {
            target: dest.clone(),
            original_target: dest.clone(),
            route_target: None,
            tag: String::new(),
        });

        let link = dispatcher.dispatch(outbound_session, dest).await?;
        let mut link_stream = new_link_stream(link);

        tokio::io::copy_bidirectional(&mut conn, &mut link_stream)
            .await
            .map_err(|e| format!("http relay copy: {}", e))?;

        Ok(())
    }
}
