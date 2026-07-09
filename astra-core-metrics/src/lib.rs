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
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                } else {
                    let response =
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(response.as_bytes()).await;
                }
            });
        }
    }
}

fn render_metrics(stats: &StatsManager) -> String {
    let mut output = String::new();
    output.push_str("# HELP astra_traffic_bytes Traffic counters in bytes\n");
    output.push_str("# TYPE astra_traffic_bytes counter\n");

    for counter in stats.all_counters() {
        output.push_str(&format_metric_line(counter.name(), counter.get()));
    }
    for ch in stats.all_channels() {
        output.push_str(&format_metric_line(ch.name(), ch.get()));
    }

    output
}

/// Parse Xray-style names `outbound>>>tag>>>traffic>>>uplink` into Prometheus labels.
fn format_metric_line(name: &str, value: i64) -> String {
    let labels = parse_traffic_name(name);
    format!("astra_traffic_bytes{{{}}} {}\n", labels, value)
}

fn parse_traffic_name(name: &str) -> String {
    // Expected: {inbound|outbound|user}>>>{tag}>>>traffic>>>{uplink|downlink}
    let parts: Vec<&str> = name.split(">>>").collect();
    if parts.len() >= 4 && parts[2] == "traffic" {
        let kind = sanitize_label_value(parts[0]);
        let tag = sanitize_label_value(parts[1]);
        let direction = sanitize_label_value(parts[3]);
        return format!(
            "kind=\"{}\",tag=\"{}\",direction=\"{}\",name=\"{}\"",
            kind,
            tag,
            direction,
            sanitize_label_value(name)
        );
    }
    format!("name=\"{}\"", sanitize_label_value(name))
}

fn sanitize_label_value(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '"' | '\\' | '\n' => '_',
            c => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_outbound_name() {
        let line = format_metric_line("outbound>>>proxy>>>traffic>>>uplink", 42);
        assert!(line.contains("kind=\"outbound\""));
        assert!(line.contains("tag=\"proxy\""));
        assert!(line.contains("direction=\"uplink\""));
        assert!(line.contains(" 42"));
    }

    #[test]
    fn parse_fallback_name() {
        let line = format_metric_line("custom.stat", 1);
        assert!(line.contains("name=\"custom.stat\""));
    }
}
