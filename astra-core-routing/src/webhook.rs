use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Configuration for the webhook notifier.
#[derive(Debug, Clone, Default)]
pub struct WebhookConfig {
    pub url: String,
    pub deduplication_secs: u32,
    pub headers: HashMap<String, String>,
}

/// Event payload sent to the webhook URL.
#[derive(Debug, serde::Serialize)]
pub struct WebhookEvent {
    pub email: Option<String>,
    pub level: Option<u32>,
    pub protocol: Option<String>,
    pub network: Option<String>,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub original_target: Option<String>,
    pub route_target: Option<String>,
    pub inbound_tag: Option<String>,
    pub inbound_local: Option<String>,
    pub outbound_tag: Option<String>,
    pub ts: i64,
}

/// Notifies external services via HTTP POST when routing rules match.
pub struct WebhookNotifier {
    url: String,
    headers: HashMap<String, String>,
    deduplication_secs: u32,
    client: reqwest::Client,
    seen: Arc<Mutex<HashMap<String, Instant>>>,
    closed: Arc<AtomicBool>,
}

impl WebhookNotifier {
    pub fn new(cfg: &WebhookConfig) -> Option<Self> {
        if cfg.url.is_empty() {
            return None;
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        Some(WebhookNotifier {
            url: cfg.url.clone(),
            headers: cfg.headers.clone(),
            deduplication_secs: cfg.deduplication_secs,
            client,
            seen: Arc::new(Mutex::new(HashMap::new())),
            closed: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Fire a webhook event for a routing match.
    pub fn fire(&self, ctx: &crate::RoutingContext, outbound_tag: &str) {
        if self.closed.load(Ordering::Relaxed) {
            return;
        }

        let email = ctx.user.clone().unwrap_or_default();
        if self.is_duplicate(&email) {
            return;
        }

        let ev = self.build_event(ctx, outbound_tag);
        let client = self.client.clone();
        let url = self.url.clone();
        let headers = self.headers.clone();
        let closed = self.closed.clone();

        tokio::spawn(async move {
            if closed.load(Ordering::Relaxed) {
                return;
            }
            match serde_json::to_string(&ev) {
                Ok(body) => {
                    let mut req = client.post(&url).header("Content-Type", "application/json");
                    for (k, v) in &headers {
                        req = req.header(k.as_str(), v.as_str());
                    }
                    match req.body(body).send().await {
                        Ok(resp) => {
                            if resp.status().as_u16() >= 400 {
                                tracing::warn!("webhook returned status {}", resp.status());
                            }
                        }
                        Err(e) => {
                            tracing::debug!("webhook POST failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("webhook marshal failed: {}", e);
                }
            }
        });
    }

    fn build_event(&self, ctx: &crate::RoutingContext, outbound_tag: &str) -> WebhookEvent {
        let source = ctx.source_ip.map(|ip| format!("{}:{}", ip, ctx.source_port));
        let destination = ctx.target_domain.clone()
            .or_else(|| ctx.target_ip.map(|ip| ip.to_string()))
            .map(|host| format!("{}:{}", host, ctx.target_port));
        let network = Some(ctx.network.clone());
        let protocol = ctx.protocol.clone();
        let user = ctx.user.clone();

        WebhookEvent {
            email: user.clone().filter(|u| !u.is_empty()),
            level: None,
            protocol,
            network,
            source,
            destination,
            original_target: None,
            route_target: None,
            inbound_tag: Some(ctx.inbound_tag.clone()).filter(|t| !t.is_empty()),
            inbound_local: None,
            outbound_tag: Some(outbound_tag.to_string()),
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        }
    }

    fn is_duplicate(&self, email: &str) -> bool {
        if self.deduplication_secs == 0 || email.is_empty() {
            return false;
        }
        let mut seen = self.seen.lock().unwrap();
        let now = Instant::now();
        if let Some(last) = seen.get(email)
            && now.duration_since(*last) < Duration::from_secs(self.deduplication_secs as u64) {
                return true;
            }
        seen.insert(email.to_string(), now);
        false
    }
}
