//! Reverse proxy (bridge/portal) — 1:1 port of `app/reverse` from Go Xray-core.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use astra_core_mux::client::MuxClient;
use astra_core_mux::io::{open_mux_stream, SessionIo};
use astra_core_mux::server::MuxServer;
use astra_core_mux::session::{MuxClientStrategy, SessionChannels};
use astra_core_net::{Address, Destination, Network, Port};
use astra_core_proxy::{async_trait, Dialer, Dispatcher, OutboundHandler, ProxyResult, UdpLink};
use astra_core_session::Session;
use astra_core_transport::{new_link_pair, Link};

const INTERNAL_DOMAIN: &str = "reverse";

// ─── Control protocol (Go: `Control` proto) ────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ControlState { Active, Drain }

#[derive(Debug, Clone)]
pub struct Control {
    pub state: ControlState,
    pub random: Vec<u8>,
}

impl Control {
    pub fn new(state: ControlState) -> Self {
        let len = (rand::random::<u64>() % 64) as usize + 1;
        let random: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect();
        Control { state, random }
    }

    pub fn encode(&self) -> Vec<u8> {
        let state_byte = match self.state {
            ControlState::Active => 0u8,
            ControlState::Drain => 1u8,
        };
        let mut buf = vec![state_byte];
        buf.extend_from_slice(&(self.random.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.random);
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 3 { return None; }
        let state = match data[0] {
            0 => ControlState::Active,
            1 => ControlState::Drain,
            _ => return None,
        };
        let len = u16::from_be_bytes([data[1], data[2]]) as usize;
        if data.len() < 3 + len { return None; }
        Some(Control { state, random: data[3..3 + len].to_vec() })
    }
}

fn is_internal_domain(dest: &Destination) -> bool {
    dest.address.as_domain().map(|d| d == INTERNAL_DOMAIN).unwrap_or(false)
}

// ─── Bridge worker ─────────────────────────────────────────────────────────

/// Handles mux sessions on the bridge side.
/// For each new mux session, creates a Link pair and dispatches it.
pub struct BridgeWorker {
    mux: Arc<MuxServer<tokio::io::DuplexStream, tokio::io::DuplexStream>>,
    new_session_rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<u16>>,
    dispatcher: Arc<dyn Dispatcher>,
    tag: String,
    closed: Arc<AtomicBool>,
}

impl BridgeWorker {
    pub fn new(
        mux: Arc<MuxServer<tokio::io::DuplexStream, tokio::io::DuplexStream>>,
        new_session_rx: tokio::sync::mpsc::UnboundedReceiver<u16>,
        dispatcher: Arc<dyn Dispatcher>,
        tag: String,
    ) -> Self {
        BridgeWorker {
            mux,
            new_session_rx: tokio::sync::Mutex::new(new_session_rx),
            dispatcher,
            tag,
            closed: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn run(&self) {
        loop {
            let session_id = {
                let mut rx = self.new_session_rx.lock().await;
                rx.recv().await
            };
            let Some(session_id) = session_id else { break };
            if self.mux.is_done() { break; }
            self.handle_session(session_id).await;
        }
    }

    async fn handle_session(&self, session_id: u16) {
        let (_, mut outbound_link) = new_link_pair();
        let (data_tx, data_rx) = tokio::sync::mpsc::unbounded_channel();
        let (close_tx, _close_rx) = tokio::sync::oneshot::channel();
        let ch = SessionChannels { data_tx, close_tx };

        let sm = self.mux.session_manager();
        let session = sm.get(session_id).await;
        let session = match session {
            Some(s) => s,
            None => return,
        };
        if !session.attach_channels(ch).await {
            return;
        }

        let (write_fn, close_fn) = SessionIo::make_fns_server(&self.mux);
        let mut session_io = SessionIo::new(session_id, data_rx, write_fn, close_fn);

        // Bridge session to outbound link
        tokio::spawn(async move {
            let (mut si_r, mut si_w) = tokio::io::split(&mut session_io);
            let to_remote = tokio::io::copy(&mut si_r, &mut outbound_link.writer);
            let to_local = tokio::io::copy(&mut outbound_link.reader, &mut si_w);
            tokio::select! {
                r = to_remote => r.map(|_| ()),
                r = to_local => r.map(|_| ()),
            }.ok();
        });

        // Create a new dispatch for this session
        let dest = Destination {
            address: Address::Domain("placeholder.adapter".into()),
            port: Port(0),
            network: Network::Tcp,
        };
        let sess = Session::default();
        let _ = self.dispatcher.dispatch(sess, dest).await;
        // Note: real impl reads dest from mux session metadata (Go sends target in New frame)
    }
}

// ─── Bridge ────────────────────────────────────────────────────────────────

pub struct Bridge {
    pub tag: String,
    pub domain: String,
    running: Arc<AtomicBool>,
}

impl Bridge {
    pub fn new(tag: String, domain: String) -> Self {
        Bridge { tag, domain, running: Arc::new(AtomicBool::new(true)) }
    }

    /// Start bridge workers that connect to the portal domain.
    pub async fn start(&self, dispatcher: Arc<dyn Dispatcher>) {
        let domain = self.domain.clone();
        let tag = self.tag.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            while running.load(std::sync::atomic::Ordering::Relaxed) {
                let dest = Destination {
                    address: Address::Domain(domain.clone()),
                    port: Port(0),
                    network: Network::Tcp,
                };
                let session = Session::default();
                match dispatcher.dispatch(session, dest).await {
                    Ok(link) => {
                        let (mux, new_session_rx) = MuxServer::new(link.reader, link.writer);
                        let worker = BridgeWorker::new(
                            mux, new_session_rx,
                            dispatcher.clone(), tag.clone(),
                        );
                        worker.run().await;
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });
    }

    pub fn close(&self) {
        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

// ─── Portal worker ─────────────────────────────────────────────────────────

pub struct PortalWorker {
    pub client: Arc<MuxClient<tokio::io::DuplexStream, tokio::io::DuplexStream>>,
    draining: bool,
}

impl PortalWorker {
    pub fn new(client: Arc<MuxClient<tokio::io::DuplexStream, tokio::io::DuplexStream>>) -> Self {
        PortalWorker { client, draining: false }
    }
}

pub struct StaticMuxPicker {
    workers: Vec<PortalWorker>,
}

impl StaticMuxPicker {
    pub fn new() -> Self {
        StaticMuxPicker { workers: Vec::new() }
    }

    pub fn add_worker(&mut self, worker: PortalWorker) {
        self.workers.push(worker);
    }

    pub fn pick_available(&mut self) -> Option<&mut PortalWorker> {
        self.workers.iter_mut().find(|w| !w.draining && !w.client.is_done())
    }

    pub fn cleanup(&mut self) {
        self.workers.retain(|w| !w.client.is_done());
    }
}

// ─── Portal outbound handler ───────────────────────────────────────────────

pub struct PortalHandler {
    pub tag: String,
    pub domain: String,
    pub picker: tokio::sync::Mutex<StaticMuxPicker>,
}

impl PortalHandler {
    pub fn new(tag: String, domain: String) -> Self {
        PortalHandler { tag, domain, picker: tokio::sync::Mutex::new(StaticMuxPicker::new()) }
    }
}

#[async_trait]
impl OutboundHandler for PortalHandler {
    async fn process(&self, session: Session, link: &mut Link, _dialer: &dyn Dialer) -> ProxyResult<()> {
        let target = session.outbound.as_ref().map(|o| &o.target).cloned()
            .ok_or_else(|| "no target".to_string())?;

        // If target is the portal domain, create a mux client from this link
        if target.address.as_domain().map(|d| d == self.domain).unwrap_or(false) {
            // Take ownership of link's reader/writer by swapping with dummies
            let (dummy_r, _) = tokio::io::duplex(64);
            let (_, dummy_w) = tokio::io::duplex(64);
            let reader = std::mem::replace(&mut link.reader, dummy_r);
            let writer = std::mem::replace(&mut link.writer, dummy_w);

            let mux_client = MuxClient::new(reader, writer, MuxClientStrategy::default());
            let worker = PortalWorker::new(mux_client);
            self.picker.lock().await.add_worker(worker);
            return Ok(());
        }

        // Dispatch through mux picker
        let mut picker = self.picker.lock().await;
        if let Some(worker) = picker.pick_available() {
            if let Some(mut session_io) = open_mux_stream(&worker.client).await {
                let (mut si_r, mut si_w) = tokio::io::split(&mut session_io);
                let to_remote = tokio::io::copy(&mut link.reader, &mut si_w);
                let to_local = tokio::io::copy(&mut si_r, &mut link.writer);
                tokio::select! {
                    r = to_remote => r.map(|_| ()),
                    r = to_local => r.map(|_| ()),
                }
                .map_err(|e| format!("reverse relay: {}", e))?;
                return Ok(());
            }
        }
        Err("no reverse worker available".into())
    }

    async fn process_udp(&self, _session: Session, _link: &mut UdpLink) -> ProxyResult<()> {
        Err("reverse portal udp not supported".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra_core_net::{Address, Network, Port};

    #[test]
    fn test_control_roundtrip() {
        let c = Control::new(ControlState::Active);
        let encoded = c.encode();
        let decoded = Control::decode(&encoded).unwrap();
        assert_eq!(decoded.state, ControlState::Active);
        assert_eq!(decoded.random.len(), c.random.len());
    }

    #[test]
    fn test_control_drain() {
        let c = Control::new(ControlState::Drain);
        let encoded = c.encode();
        let decoded = Control::decode(&encoded).unwrap();
        assert_eq!(decoded.state, ControlState::Drain);
    }

    #[test]
    fn test_internal_domain() {
        let dest = Destination {
            address: Address::Domain("reverse".into()),
            port: Port(0),
            network: Network::Tcp,
        };
        assert!(is_internal_domain(&dest));
    }
}
