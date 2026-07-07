use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::time::sleep;

/// Result of a health probe.
#[derive(Debug, Clone)]
pub struct OutboundStatus {
    pub tag: String,
    pub alive: bool,
    pub last_seen: std::time::Instant,
}

/// Observatory: health checks outbounds and reports status.
pub struct Observatory {
    /// Tags under observation.
    selector: Vec<String>,
    /// Shared set of tags currently considered alive.
    alive: Arc<RwLock<HashSet<String>>>,
    /// Probe target host (e.g. "1.1.1.1").
    probe_host: String,
    /// Probe target port (e.g. 80).
    probe_port: u16,
    /// Interval between probes (seconds).
    interval_secs: u64,
}

impl Observatory {
    pub fn new(
        selector: Vec<String>,
        alive: Arc<RwLock<HashSet<String>>>,
        probe_host: String,
        probe_port: u16,
        interval_secs: u64,
    ) -> Self {
        // Initially mark all selected outbounds as alive
        {
            let mut a = alive.write().unwrap();
            for tag in &selector {
                a.insert(tag.clone());
            }
        }

        Observatory { selector, alive, probe_host, probe_port, interval_secs }
    }

    /// Start the health check loop in a background task.
    pub fn start(self) {
        tokio::spawn(async move {
            self.run().await;
        });
    }

    async fn run(&self) {
        loop {
            sleep(Duration::from_secs(self.interval_secs)).await;

            let probe_ok = self.probe().await;

            let mut alive = self.alive.write().unwrap();
            if probe_ok {
                for tag in &self.selector {
                    alive.insert(tag.clone());
                }
            } else {
                for tag in &self.selector {
                    alive.remove(tag);
                }
            }
            drop(alive);

            let count = self.alive.read().unwrap().len();
            tracing::debug!("observatory: {}/{} outbounds alive", count, self.selector.len());
        }
    }

    /// Simple TCP probe to check connectivity.
    async fn probe(&self) -> bool {
        let addr = format!("{}:{}", self.probe_host, self.probe_port);
        match tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => true,
            _ => false,
        }
    }

    pub fn get_alive(&self) -> Arc<RwLock<HashSet<String>>> {
        self.alive.clone()
    }

    pub fn get_status(&self) -> Vec<OutboundStatus> {
        let alive = self.alive.read().unwrap();
        self.selector.iter().map(|tag| OutboundStatus {
            tag: tag.clone(),
            alive: alive.contains(tag),
            last_seen: std::time::Instant::now(),
        }).collect()
    }
}
