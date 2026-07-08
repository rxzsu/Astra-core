use std::sync::Arc;

use crate::config::Config;
use crate::device::TunDevice;
use crate::stack::{SimpleStack, Stack};

/// TUN Handler — fully async.
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

    pub async fn start(&self) -> Result<(), String> {
        let tun = crate::device::create_tun(&self.config).await?;
        tun.start().await?;

        let tun_arc: Arc<Box<dyn TunDevice>> = Arc::new(tun);
        let stack = SimpleStack::new(tun_arc);
        stack.start().await?;

        *self.stack.lock().await = Some(stack);

        tracing::info!("TUN handler started on {}", self.config.name);
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), String> {
        if let Some(s) = self.stack.lock().await.take() {
            s.close().await?;
        }
        tracing::info!("TUN handler stopped");
        Ok(())
    }
}
