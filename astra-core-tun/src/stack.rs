use std::sync::Arc;

use crate::device::TunDevice;
use crate::icmp;

/// Stack interface.
#[async_trait::async_trait]
pub trait Stack: Send + Sync {
    async fn start(&self) -> Result<(), String>;
    async fn close(&self) -> Result<(), String>;
}

/// Simple async TUN packet stack.
/// Reads IP packets from TUN in a tokio loop and handles them:
/// - ICMP echo → reply locally
/// - TCP/UDP → forward to dispatcher (to be implemented)
pub struct SimpleStack {
    tun: Arc<Box<dyn TunDevice>>,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl SimpleStack {
    pub fn new(tun: Arc<Box<dyn TunDevice>>) -> Self {
        SimpleStack {
            tun,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

#[async_trait::async_trait]
impl Stack for SimpleStack {
    async fn start(&self) -> Result<(), String> {
        self.running
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let tun = self.tun.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                if !running.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }

                match tun.recv(&mut buf).await {
                    Ok(n) if n > 0 => {
                        handle_packet(&tun, &buf[..n]).await;
                    }
                    Ok(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                    Err(e) => {
                        tracing::debug!("tun recv: {}", e);
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });

        Ok(())
    }

    async fn close(&self) -> Result<(), String> {
        self.running
            .store(false, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

async fn handle_packet(tun: &Arc<Box<dyn TunDevice>>, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let version = data[0] >> 4;
    match version {
        4 => handle_ipv4(tun, data).await,
        6 => handle_ipv6(tun, data).await,
        _ => {}
    }
}

async fn handle_ipv4(tun: &Arc<Box<dyn TunDevice>>, data: &[u8]) {
    if data.len() < 20 {
        return;
    }
    let protocol = data[9];
    match protocol {
        1 => {
            // ICMP
            if let Some(reply) = icmp::build_echo_reply(data, false) {
                let _ = tun.send(&reply).await;
            }
        }
        6 => {
            // TCP — would need TCP/IP stack
            tracing::trace!("tun: TCP packet");
        }
        17 => {
            // UDP
            tracing::trace!("tun: UDP packet");
        }
        _ => {}
    }
}

async fn handle_ipv6(tun: &Arc<Box<dyn TunDevice>>, data: &[u8]) {
    if data.len() < 40 {
        return;
    }
    let next_hdr = data[6];
    if next_hdr == 58 {
        // ICMPv6
        if let Some(reply) = icmp::build_echo_reply(data, true) {
            let _ = tun.send(&reply).await;
        }
    }
}
