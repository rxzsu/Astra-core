use std::sync::Arc;

use crate::device::TunDevice;

/// Stack interface - wraps the TCP/IP stack.
#[async_trait::async_trait]
pub trait Stack: Send + Sync {
    async fn start(&self) -> Result<(), String>;
    async fn close(&self) -> Result<(), String>;
}

pub struct SimpleStack {
    tun: Arc<tokio::sync::Mutex<Box<dyn TunDevice>>>,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl SimpleStack {
    pub fn new(tun: Arc<tokio::sync::Mutex<Box<dyn TunDevice>>>) -> Self {
        SimpleStack {
            tun,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

#[async_trait::async_trait]
impl Stack for SimpleStack {
    async fn start(&self) -> Result<(), String> {
        self.running.store(true, std::sync::atomic::Ordering::Relaxed);
        let tun = self.tun.clone();
        let running = self.running.clone();
        
        tokio::spawn(async move {
            loop {
                if !running.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                // Lock tun and read
                // For async reading, we'd use a proper async interface
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        });
        
        Ok(())
    }

    async fn close(&self) -> Result<(), String> {
        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}


