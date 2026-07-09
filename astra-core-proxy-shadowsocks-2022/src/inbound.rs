use std::sync::Arc;

use astra_core_net::{Address, Destination, Network, Port};
use astra_core_proxy::{async_trait, Conn, Dispatcher, InboundHandler, ProxyResult};
use astra_core_session::{Outbound, Session};
use astra_core_transport::new_link_stream;

use crate::protocol::{CipherType, read_chunk};

pub struct Handler {
    pub cipher: CipherType,
    pub key: Vec<u8>,
}

impl Handler {
    pub fn new(cipher: CipherType, key: Vec<u8>) -> Self {
        Handler { cipher, key }
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
        let mut nonce = vec![0u8; self.cipher.nonce_size()];
        let first_chunk = read_chunk(&mut conn, self.cipher, &self.key, &mut nonce)
            .await
            .map_err(|e| format!("ss2022 read first chunk: {}", e))?
            .ok_or_else(|| "ss2022: connection closed".to_string())?;

        if first_chunk.is_empty() {
            return Err("ss2022: empty first chunk".into());
        }

        let target = parse_target_from_bytes(&first_chunk)?;

        let outbound_session = Session {
            outbound: Some(Outbound {
                target: target.clone(),
                original_target: target.clone(),
                route_target: None,
                tag: String::new(),
            }),
            ..session
        };

        let link = dispatcher.dispatch(outbound_session, target).await?;
        let mut link_stream = new_link_stream(link);

        let header_size = socks5_addr_len(&first_chunk);
        if header_size < first_chunk.len() {
            use tokio::io::AsyncWriteExt;
            link_stream.write_all(&first_chunk[header_size..]).await
                .map_err(|e| format!("ss2022 write payload: {}", e))?;
        }

        let (mut cr, mut cw) = tokio::io::split(&mut *conn);
        let (mut lr, mut lw) = tokio::io::split(&mut link_stream);

        let to_remote = async {
            let mut read_nonce = nonce.clone();
            use tokio::io::AsyncWriteExt;
            loop {
                match read_chunk(&mut cr, self.cipher, &self.key, &mut read_nonce).await {
                    Ok(Some(data)) => {
                        if lw.write_all(&data).await.is_err() { break; }
                    }
                    Ok(None) | Err(_) => break,
                }
            }
            Ok::<_, String>(())
        };

        let to_client = tokio::io::copy(&mut lr, &mut cw);

        tokio::select! {
            r = to_remote => r?,
            r = to_client => r.map(|_| ()).map_err(|e| format!("ss2022 copy: {}", e))?,
        }

        Ok(())
    }
}

// ─── Relay Inbound (multi-hop) ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RelayDestination {
    pub key: Vec<u8>,
    pub address: String,
    pub port: u16,
    pub email: String,
}

pub struct RelayInbound {
    pub cipher: CipherType,
    pub destinations: Vec<RelayDestination>,
}

impl RelayInbound {
    pub fn new(cipher: CipherType, destinations: Vec<RelayDestination>) -> Self {
        RelayInbound { cipher, destinations }
    }

    /// Try each destination key to authenticate and get the first successful match.
    /// Returns (matched_dest, decrypted_chunk).
    fn try_each_key(&self, conn: &mut Conn, data: &[u8]) -> Option<(RelayDestination, Vec<u8>)> {
        for dest in &self.destinations {
            let mut nonce = vec![0u8; self.cipher.nonce_size()];
            // Clone the data for each attempt
            let mut test_buf = data.to_vec();
            // Attempt decryption — in a real implementation this would use the AEAD
            // to authenticate. For now, try to read the chunk and verify it parses.
            if let Ok(chunk) = parse_target_from_bytes(data) {
                if chunk.port.value() > 0 {
                    return Some((dest.clone(), data.to_vec()));
                }
            }
        }
        None
    }
}

#[async_trait]
impl InboundHandler for RelayInbound {
    async fn process(
        &self,
        session: Session,
        mut conn: Conn,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> ProxyResult<()> {
        // Read the first chunk with the first reliable key
        let mut nonce = vec![0u8; self.cipher.nonce_size()];
        let key = self.destinations.first().map(|d| d.key.clone()).unwrap_or_default();
        let first_chunk = read_chunk(&mut conn, self.cipher, &key, &mut nonce)
            .await
            .map_err(|e| format!("ss2022 relay: read chunk: {}", e))?
            .ok_or_else(|| "ss2022 relay: connection closed".to_string())?;

        if first_chunk.is_empty() {
            return Err("ss2022 relay: empty first chunk".into());
        }

        let target = parse_target_from_bytes(&first_chunk)?;

        let outbound_session = Session {
            outbound: Some(Outbound {
                target: target.clone(),
                original_target: target.clone(),
                route_target: None,
                tag: String::new(),
            }),
            ..session
        };

        let link = dispatcher.dispatch(outbound_session, target).await?;
        let mut link_stream = new_link_stream(link);

        let header_size = socks5_addr_len(&first_chunk);
        if header_size < first_chunk.len() {
            use tokio::io::AsyncWriteExt;
            link_stream.write_all(&first_chunk[header_size..]).await
                .map_err(|e| format!("ss2022 relay write: {}", e))?;
        }

        let (mut cr, mut cw) = tokio::io::split(&mut *conn);
        let (mut lr, mut lw) = tokio::io::split(&mut link_stream);

        let to_remote = async {
            let mut read_nonce = nonce.clone();
            use tokio::io::AsyncWriteExt;
            loop {
                match read_chunk(&mut cr, self.cipher, &key, &mut read_nonce).await {
                    Ok(Some(data)) => {
                        if lw.write_all(&data).await.is_err() { break; }
                    }
                    Ok(None) | Err(_) => break,
                }
            }
            Ok::<_, String>(())
        };

        let to_client = tokio::io::copy(&mut lr, &mut cw);

        tokio::select! {
            r = to_remote => r?,
            r = to_client => r.map(|_| ()).map_err(|e| format!("ss2022 relay copy: {}", e))?,
        }

        Ok(())
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn parse_target_from_bytes(data: &[u8]) -> Result<Destination, String> {
    if data.is_empty() {
        return Err("empty target".into());
    }
    let atyp = data[0];
    let (address, consumed) = match atyp {
        0x01 => {
            if data.len() < 5 { return Err("short ipv4 target".into()); }
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&data[1..5]);
            (Address::Ipv4(octets), 5)
        }
        0x03 => {
            if data.len() < 2 { return Err("short domain target".into()); }
            let dlen = data[1] as usize;
            if data.len() < 2 + dlen + 2 { return Err("short domain target".into()); }
            let domain = std::str::from_utf8(&data[2..2 + dlen])
                .map_err(|_| "invalid domain utf8".to_string())?;
            (Address::Domain(domain.to_owned()), 2 + dlen + 2)
        }
        0x04 => {
            if data.len() < 17 { return Err("short ipv6 target".into()); }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            (Address::Ipv6(octets), 17)
        }
        _ => return Err(format!("unknown address type: {}", atyp)),
    };

    if data.len() < consumed {
        return Err("missing port".into());
    }
    let port = u16::from_be_bytes([data[consumed - 2], data[consumed - 1]]);

    Ok(Destination { address, port: Port(port), network: Network::Tcp })
}

fn socks5_addr_len(data: &[u8]) -> usize {
    if data.is_empty() { return 0; }
    match data[0] {
        0x01 => 1 + 4 + 2,
        0x03 => {
            if data.len() < 2 { return 1; }
            1 + 1 + data[1] as usize + 2
        }
        0x04 => 1 + 16 + 2,
        _ => data.len(),
    }
}
