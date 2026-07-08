use std::sync::Arc;
use tokio::sync::Mutex;

use crate::config::Config;
use crate::device::TunDevice;
use crate::stack::{SimpleStack, Stack};

/// TUN Handler - manages TUN device, IP stack, and dispatches connections.
/// Mirrors Go's `proxy/tun/handler.go`.
pub struct TunHandler {
    config: Config,
    stack: Arc<tokio::sync::Mutex<Option<SimpleStack>>>,
}

impl TunHandler {
    pub fn new(config: Config) -> Self {
        TunHandler {
            config,
            stack: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Start the TUN handler: create TUN device, start IP stack.
    pub async fn start(&self) -> Result<(), String> {
        let tun_device = crate::device::create_tun(&self.config).await?;
        
        // Start the TUN device
        tun_device.start().await?;
        
        // Create and start the IP stack
        let tun_arc = Arc::new(tokio::sync::Mutex::new(tun_device));
        let stack = SimpleStack::new(tun_arc);
        stack.start().await?;
        
        *self.stack.lock().await = Some(stack);
        
        tracing::info!("TUN handler started on {}", self.config.name);
        Ok(())
    }

    /// Stop the TUN handler.
    pub async fn stop(&self) -> Result<(), String> {
        if let Some(stack) = self.stack.lock().await.take() {
            stack.close().await?;
        }
        tracing::info!("TUN handler stopped");
        Ok(())
    }
}
