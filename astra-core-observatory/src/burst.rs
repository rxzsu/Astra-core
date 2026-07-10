use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::sleep;

fn simple_jitter() -> Duration {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    Duration::from_millis((c % 1000) + 1)
}

use crate::{OutboundStatus, ProbeMethod};

// ─── HealthPingRTTS (circular buffer for RTT measurements) ──────────────────

#[derive(Debug, Clone)]
pub struct HealthPingStats {
    pub all: u64,
    pub fail: u64,
    pub deviation_ms: f64,
    pub average_ms: f64,
    pub max_ms: f64,
    pub min_ms: f64,
}

#[derive(Debug, Clone)]
enum RttValue {
    Untested,
    Failed,
    Success(Duration),
}

#[derive(Debug, Clone)]
struct PingRTT {
    time: Instant,
    value: RttValue,
}

#[derive(Debug, Clone)]
pub struct HealthPingRTTS {
    idx: usize,
    cap: usize,
    validity: Duration,
    rtts: Vec<PingRTT>,
    stats_cache: Option<HealthPingStats>,
    last_update_at: Instant,
}

impl HealthPingRTTS {
    pub fn new(cap: usize, validity: Duration) -> Self {
        let mut rtts = Vec::with_capacity(cap);
        for _ in 0..cap {
            rtts.push(PingRTT {
                time: Instant::now(),
                value: RttValue::Untested,
            });
        }
        HealthPingRTTS {
            idx: 0,
            cap,
            validity,
            rtts,
            stats_cache: None,
            last_update_at: Instant::now(),
        }
    }

    pub fn put(&mut self, value: Duration) {
        self.idx = (self.idx + 1) % self.cap;
        self.rtts[self.idx] = PingRTT {
            time: Instant::now(),
            value: RttValue::Success(value),
        };
        self.stats_cache = None;
    }

    pub fn put_fail(&mut self) {
        self.idx = (self.idx + 1) % self.cap;
        self.rtts[self.idx] = PingRTT {
            time: Instant::now(),
            value: RttValue::Failed,
        };
        self.stats_cache = None;
    }

    pub fn get_stats(&mut self) -> HealthPingStats {
        if let Some(ref cached) = self.stats_cache {
            let mut needs_recalc = false;
            for rtt in &self.rtts {
                if rtt.time > self.last_update_at {
                    needs_recalc = true;
                    break;
                }
            }
            if !needs_recalc {
                return cached.clone();
            }
        }
        let stats = self.compute_stats();
        self.stats_cache = Some(stats.clone());
        self.last_update_at = Instant::now();
        stats
    }

    fn compute_stats(&self) -> HealthPingStats {
        let mut fail = 0u64;
        let mut max_ms = 0.0f64;
        let mut min_ms = f64::MAX;
        let mut sum_ms = 0.0f64;
        let mut count = 0u64;
        let mut valid_rtts: Vec<f64> = Vec::new();

        for rtt in &self.rtts {
            if rtt.time.elapsed() > self.validity {
                continue;
            }
            match rtt.value {
                RttValue::Untested => continue,
                RttValue::Failed => fail += 1,
                RttValue::Success(d) => {
                    let ms = d.as_secs_f64() * 1000.0;
                    sum_ms += ms;
                    valid_rtts.push(ms);
                    if ms > max_ms {
                        max_ms = ms;
                    }
                    if ms < min_ms {
                        min_ms = ms;
                    }
                    count += 1;
                }
            }
        }

        let all = count + fail;
        if count == 0 {
            return HealthPingStats {
                all,
                fail,
                deviation_ms: 0.0,
                average_ms: 0.0,
                max_ms: 0.0,
                min_ms: 0.0,
            };
        }

        let average_ms = sum_ms / count as f64;
        let deviation_ms = if count < 2 {
            average_ms / 2.0
        } else {
            let variance: f64 = valid_rtts
                .iter()
                .map(|v| (v - average_ms).powi(2))
                .sum::<f64>()
                / count as f64;
            variance.sqrt()
        };

        HealthPingStats {
            all,
            fail,
            deviation_ms,
            average_ms,
            max_ms,
            min_ms,
        }
    }
}

// ─── Ping Client ────────────────────────────────────────────────────────────

struct PingClient {
    dispatcher_config: ProbeMethod,
    #[allow(dead_code)]
    tag: String,
    connect_timeout: Duration,
}

impl PingClient {
    fn new(dispatcher_config: ProbeMethod, tag: String, timeout: Duration) -> Self {
        PingClient {
            dispatcher_config,
            tag,
            connect_timeout: timeout,
        }
    }

    async fn measure_delay(&self) -> Result<Duration, String> {
        match &self.dispatcher_config {
            ProbeMethod::Tcp { host, port } => {
                let addr = format!("{}:{}", host, port);
                let start = Instant::now();
                tokio::time::timeout(self.connect_timeout, TcpStream::connect(&addr))
                    .await
                    .map_err(|_| format!("timeout connecting to {}", addr))?
                    .map_err(|e| format!("connect {}: {}", addr, e))?;
                Ok(start.elapsed())
            }
            ProbeMethod::Http { url } => {
                let start = Instant::now();
                // Use the outbound tag for routing — this is a simplified version
                // that directly connects to the URL via TCP
                let stripped = url
                    .trim_start_matches("https://")
                    .trim_start_matches("http://");
                let host_port = stripped.split('/').next().unwrap_or(stripped);
                let addr = if host_port.contains(':') {
                    host_port.to_string()
                } else {
                    format!("{}:80", host_port)
                };
                tokio::time::timeout(self.connect_timeout, TcpStream::connect(&addr))
                    .await
                    .map_err(|_| format!("timeout http ping {}", url))?
                    .map_err(|e| format!("http ping {}: {}", url, e))?;
                Ok(start.elapsed())
            }
        }
    }
}

// ─── HealthPing ────────────────────────────────────────────────────────────

pub struct HealthPing {
    settings: HealthPingSettings,
    results: Arc<Mutex<HashMap<String, HealthPingRTTS>>>,
}

#[derive(Debug, Clone)]
pub struct HealthPingSettings {
    pub destination: String,
    pub connectivity: String,
    pub interval: Duration,
    pub sampling_count: usize,
    pub timeout: Duration,
    pub http_method: String,
}

impl Default for HealthPingSettings {
    fn default() -> Self {
        HealthPingSettings {
            destination: "https://connectivitycheck.gstatic.com/generate_204".into(),
            connectivity: String::new(),
            interval: Duration::from_secs(60),
            sampling_count: 10,
            timeout: Duration::from_secs(5),
            http_method: "HEAD".into(),
        }
    }
}

impl HealthPing {
    pub fn new(settings: Option<HealthPingSettings>) -> Self {
        let settings = settings.unwrap_or_default();
        let interval = if settings.interval < Duration::from_secs(10) {
            Duration::from_secs(10)
        } else {
            settings.interval
        };
        HealthPing {
            settings: HealthPingSettings {
                interval,
                ..settings
            },
            results: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start the periodic health check scheduler.
    pub async fn start_scheduler<F>(&self, selector: F)
    where
        F: Fn() -> Vec<String> + Send + 'static,
    {
        let settings = self.settings.clone();
        let results = self.results.clone();

        // Immediate first check
        let tags = selector();
        self.check(&tags).await;

        // Periodic checks
        tokio::spawn(async move {
            let interval = settings.interval * settings.sampling_count as u32;
            loop {
                sleep(interval).await;
                let tags = selector();
                if tags.is_empty() {
                    continue;
                }
                Self::do_check(&tags, &settings, &results).await;
                // Cleanup stale results
                let mut res = results.lock().await;
                res.retain(|tag, _| tags.contains(tag));
            }
        });
    }

    /// One-shot health check for the given tags.
    pub async fn check(&self, tags: &[String]) {
        if tags.is_empty() {
            return;
        }
        Self::do_check(tags, &self.settings, &self.results).await;
    }

    async fn do_check(
        tags: &[String],
        settings: &HealthPingSettings,
        results: &Arc<Mutex<HashMap<String, HealthPingRTTS>>>,
    ) {
        let count = tags.len() * settings.sampling_count;
        if count == 0 {
            return;
        }

        let sampling_count = settings.sampling_count;
        let result_validity = settings.interval * settings.sampling_count as u32 * 2;

        // Collect results with jittered timing
        let mut handles = Vec::with_capacity(count);
        for tag in tags {
            let tag = tag.clone();
            let dest = settings.destination.clone();
            let timeout = settings.timeout;
            let results = results.clone();

            for _ in 0..sampling_count {
                let tag = tag.clone();
                let dest = dest.clone();
                let results = results.clone();
                let jitter = simple_jitter();

                handles.push(tokio::spawn(async move {
                    sleep(jitter).await;
                    let client = PingClient::new(
                        ProbeMethod::Http { url: dest.clone() },
                        tag.clone(),
                        timeout,
                    );
                    tokio::time::timeout(timeout, client.measure_delay())
                        .await
                        .ok()
                        .and_then(|r| r.ok())
                        .map(|delay| {
                            let mut r = results.blocking_lock();
                            let entry = r.entry(tag).or_insert_with(|| {
                                HealthPingRTTS::new(sampling_count, result_validity)
                            });
                            entry.put(delay);
                        });
                }));
            }
        }

        for h in handles {
            let _ = h.await;
        }
    }

    pub async fn get_results(&self) -> Vec<(String, HealthPingStats)> {
        let mut res = self.results.lock().await;
        res.iter_mut()
            .map(|(tag, rtts)| {
                let stats = rtts.get_stats();
                (tag.clone(), stats)
            })
            .collect()
    }
}

// ─── BurstObserver ─────────────────────────────────────────────────────────

pub struct BurstObserver {
    pub health_ping: HealthPing,
}

impl BurstObserver {
    pub fn new(settings: Option<HealthPingSettings>) -> Self {
        BurstObserver {
            health_ping: HealthPing::new(settings),
        }
    }

    pub fn with_health_ping(hp: HealthPing) -> Self {
        BurstObserver { health_ping: hp }
    }

    pub async fn get_observation(&self) -> Vec<OutboundStatus> {
        let results = self.health_ping.get_results().await;
        results
            .into_iter()
            .map(|(tag, stats)| OutboundStatus {
                tag: tag.clone(),
                alive: stats.all != stats.fail,
                delay_ms: stats.average_ms as u64,
                last_error: if stats.fail > 0 {
                    Some("ping failures".into())
                } else {
                    None
                },
                last_seen: Instant::now(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_ping_rtts_basic() {
        let mut rtts = HealthPingRTTS::new(5, Duration::from_secs(3600));
        rtts.put(Duration::from_millis(100));
        rtts.put(Duration::from_millis(200));
        rtts.put(Duration::from_millis(300));
        let stats = rtts.get_stats();
        assert_eq!(stats.all, 3);
        assert_eq!(stats.fail, 0);
        assert!((stats.average_ms - 200.0).abs() < 1.0);
    }

    #[test]
    fn test_health_ping_rtts_with_failures() {
        let mut rtts = HealthPingRTTS::new(5, Duration::from_secs(3600));
        rtts.put(Duration::from_millis(100));
        rtts.put_fail();
        rtts.put(Duration::from_millis(200));
        let stats = rtts.get_stats();
        assert_eq!(stats.all, 3);
        assert_eq!(stats.fail, 1);
    }

    #[test]
    fn test_health_ping_rtts_wrap_around() {
        let mut rtts = HealthPingRTTS::new(3, Duration::from_secs(3600));
        rtts.put(Duration::from_millis(100));
        rtts.put(Duration::from_millis(200));
        rtts.put(Duration::from_millis(300));
        rtts.put(Duration::from_millis(400)); // wraps around
        let stats = rtts.get_stats();
        assert_eq!(stats.all, 3);
    }

    #[test]
    fn test_health_ping_settings_default() {
        let settings = HealthPingSettings::default();
        assert_eq!(
            settings.destination,
            "https://connectivitycheck.gstatic.com/generate_204"
        );
        assert_eq!(settings.sampling_count, 10);
        assert_eq!(settings.http_method, "HEAD");
    }
}
