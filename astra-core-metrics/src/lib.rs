use std::sync::Arc;

use astra_core_stats::StatsManager;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Exposes stats counters via HTTP /metrics endpoint in Prometheus text format.
pub struct MetricsServer {
    stats: Arc<StatsManager>,
    listen_addr: String,
}

impl MetricsServer {
    pub fn new(stats: Arc<StatsManager>, listen_addr: String) -> Self {
        MetricsServer { stats, listen_addr }
    }

    pub async fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        tracing::info!("metrics server listening on {}", self.listen_addr);

        loop {
            let (mut stream, _) = listener.accept().await?;
            let stats = self.stats.clone();

            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = match stream.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(n) => n,
                    Err(_) => return,
                };

                let request = String::from_utf8_lossy(&buf[..n]);
                if request.starts_with("GET /metrics ") || request.starts_with("GET / HTTP") {
                    let body = render_metrics(&stats);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(), body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                } else {
                    let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(response.as_bytes()).await;
                }
            });
        }
    }
}

fn render_metrics(stats: &StatsManager) -> String {
    let mut output = String::new();
    output.push_str("# HELP astra_traffic Traffic counters\n");
    output.push_str("# TYPE astra_traffic counter\n");

    for counter in stats.all_counters() {
        let name = sanitize_name(counter.name());
        output.push_str(&format!("astra_traffic{{{}}} {}\n", name, counter.get()));
    }

    for ch in stats.all_channels() {
        let name = sanitize_name(ch.name());
        output.push_str(&format!("astra_traffic{{{}}} {}\n", name, ch.get()));
    }

    output
}

fn sanitize_name(name: &str) -> String {
    // Prometheus label format: replace special chars with underscores
    let sanitized: String = name.chars().map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' }).collect();
    format!("name=\"{}\"", sanitized)
}
