use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::time::Instant;

use bytes::BytesMut;
use tokio::sync::Mutex;
use tokio::time::{Duration, MissedTickBehavior, interval};

use crate::config::Config;
use crate::receiving::ReceivingWorker;
use crate::segment::*;
use crate::sending::SendingWorker;

fn now_millisec() -> i64 {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    d.as_millis() as i64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Active = 0,
    ReadyToClose = 1,
    PeerClosed = 2,
    Terminating = 3,
    PeerTerminating = 4,
    Terminated = 5,
}

impl State {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => State::Active,
            1 => State::ReadyToClose,
            2 => State::PeerClosed,
            3 => State::Terminating,
            4 => State::PeerTerminating,
            5 => State::Terminated,
            _ => State::Active,
        }
    }

    pub fn is(&self, states: &[State]) -> bool {
        states.contains(self)
    }
}

pub struct RoundTripInfo {
    variation: u32,
    srtt: u32,
    rto: u32,
    min_rtt: u32,
    updated_timestamp: AtomicU32,
}

impl RoundTripInfo {
    pub fn new(min_rtt: u32) -> Self {
        Self {
            variation: 0,
            srtt: 0,
            rto: 100,
            min_rtt,
            updated_timestamp: AtomicU32::new(0),
        }
    }

    pub fn update_peer_rto(&mut self, rto: u32, current: u32) {
        if current.wrapping_sub(self.updated_timestamp.load(Ordering::Relaxed)) < 3000 {
            return;
        }
        self.updated_timestamp.store(current, Ordering::Relaxed);
        self.rto = rto;
    }

    pub fn update(&mut self, rtt: u32, current: u32) {
        if rtt > 0x7FFFFFFF {
            return;
        }
        if self.srtt == 0 {
            self.srtt = rtt;
            self.variation = rtt / 2;
        } else {
            let delta = rtt.abs_diff(self.srtt);
            self.variation = (3 * self.variation + delta) / 4;
            self.srtt = (7 * self.srtt + rtt) / 8;
            if self.srtt < self.min_rtt {
                self.srtt = self.min_rtt;
            }
        }
        let rto = if self.min_rtt < 4 * self.variation {
            self.srtt + 4 * self.variation
        } else {
            self.srtt + self.variation
        };
        let rto = rto.min(10000);
        self.rto = rto * 5 / 4;
        self.updated_timestamp.store(current, Ordering::Relaxed);
    }

    pub fn timeout(&self) -> u32 {
        self.rto
    }
}

#[async_trait::async_trait]
pub trait PacketWriter: Send + Sync {
    async fn write_packet(&self, buf: &[u8]) -> std::io::Result<()>;
}

#[async_trait::async_trait]
pub trait PacketCloser: Send + Sync {
    async fn close(&self);
}

#[derive(Clone)]
pub struct ConnMetadata {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub conversation: u16,
}

struct Inner {
    state: AtomicI32,
    state_begin_time: AtomicU32,
    last_incoming_time: AtomicU32,
    last_ping_time: AtomicU32,
    since: i64,
    mss: u32,
    data_input: tokio::sync::Notify,
    data_output: tokio::sync::Notify,
    round_trip: Mutex<RoundTripInfo>,
    receiving_worker: Mutex<ReceivingWorker>,
    sending_worker: Mutex<SendingWorker>,
    rd: Mutex<Option<Instant>>,
    wd: Mutex<Option<Instant>>,
    writer: Arc<dyn PacketWriter>,
    closer: Arc<dyn PacketCloser>,
}

pub struct Connection {
    pub meta: ConnMetadata,
    pub config: Config,
    inner: Arc<Inner>,
}

impl Connection {
    pub fn new(
        meta: ConnMetadata,
        writer: Arc<dyn PacketWriter>,
        closer: Arc<dyn PacketCloser>,
        config: Config,
    ) -> Arc<Self> {
        let mss = config.mss();
        let inner = Arc::new(Inner {
            state: AtomicI32::new(State::Active as i32),
            state_begin_time: AtomicU32::new(0),
            last_incoming_time: AtomicU32::new(0),
            last_ping_time: AtomicU32::new(0),
            since: now_millisec(),
            mss,
            data_input: tokio::sync::Notify::new(),
            data_output: tokio::sync::Notify::new(),
            round_trip: Mutex::new(RoundTripInfo::new(config.tti)),
            receiving_worker: Mutex::new(ReceivingWorker::new(mss)),
            sending_worker: Mutex::new(SendingWorker::new(&config)),
            rd: Mutex::new(None),
            wd: Mutex::new(None),
            writer,
            closer,
        });

        let conn = Arc::new(Self {
            meta,
            config,
            inner,
        });

        let c = conn.clone();
        tokio::spawn(async move {
            c.data_updater_loop().await;
        });
        let c = conn.clone();
        tokio::spawn(async move {
            c.ping_updater_loop().await;
        });

        conn
    }

    pub fn elapsed(&self) -> u32 {
        (now_millisec() - self.inner.since) as u32
    }

    pub fn state(&self) -> State {
        State::from_i32(self.inner.state.load(Ordering::Relaxed))
    }

    pub fn set_state(&self, state: State) {
        let current = self.elapsed();
        self.inner.state.store(state as i32, Ordering::Relaxed);
        self.inner
            .state_begin_time
            .store(current, Ordering::Relaxed);

        match state {
            State::ReadyToClose => {
                let mut rw = self.inner.receiving_worker.blocking_lock();
                rw.close_read();
            }
            State::PeerClosed => {
                let mut sw = self.inner.sending_worker.blocking_lock();
                sw.close_write();
            }
            State::Terminating => {
                let mut rw = self.inner.receiving_worker.blocking_lock();
                rw.close_read();
                let mut sw = self.inner.sending_worker.blocking_lock();
                sw.close_write();
            }
            State::PeerTerminating => {
                let mut sw = self.inner.sending_worker.blocking_lock();
                sw.close_write();
            }
            State::Terminated => {
                let mut rw = self.inner.receiving_worker.blocking_lock();
                rw.close_read();
                let mut sw = self.inner.sending_worker.blocking_lock();
                sw.close_write();
                self.inner.data_input.notify_one();
                self.inner.data_output.notify_one();
            }
            _ => {}
        }
    }

    async fn data_updater_loop(self: Arc<Self>) {
        let mut timer = interval(self.config.tti_duration());
        timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            timer.tick().await;
            let s = self.state();
            if s == State::Terminated || s.is(&[State::Terminating, State::Terminated]) {
                break;
            }
            let needs_update = {
                let rw = self.inner.receiving_worker.blocking_lock();
                let sw = self.inner.sending_worker.blocking_lock();
                sw.update_necessary() || rw.update_necessary()
            };
            if !needs_update && self.state() == State::Active {
                continue;
            }
            self.flush().await;
        }
    }

    async fn ping_updater_loop(self: Arc<Self>) {
        let mut timer = interval(Duration::from_secs(5));
        timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            timer.tick().await;
            if self.state() == State::Terminated {
                break;
            }
            self.flush().await;
        }
    }

    pub async fn flush(&self) {
        let current = self.elapsed();

        if self.state() == State::Terminated {
            return;
        }

        if self.state() == State::Active
            && current.wrapping_sub(self.inner.last_incoming_time.load(Ordering::Relaxed)) >= 30000
        {
            self.close().await;
        }

        if self.state() == State::ReadyToClose && {
            let sw = self.inner.sending_worker.blocking_lock();
            sw.is_empty()
        } {
            self.set_state(State::Terminating);
        }

        if self.state() == State::Terminating {
            self.ping(current, Command::Terminate).await;
            if current.wrapping_sub(self.inner.state_begin_time.load(Ordering::Relaxed)) > 8000 {
                self.set_state(State::Terminated);
            }
            return;
        }

        if self.state() == State::PeerTerminating
            && current.wrapping_sub(self.inner.state_begin_time.load(Ordering::Relaxed)) > 4000
        {
            self.set_state(State::Terminating);
        }

        if self.state() == State::ReadyToClose
            && current.wrapping_sub(self.inner.state_begin_time.load(Ordering::Relaxed)) > 15000
        {
            self.set_state(State::Terminating);
        }

        let rto = {
            let rt = self.inner.round_trip.blocking_lock();
            rt.timeout()
        };
        let conv = self.meta.conversation;

        let ack_segments = {
            let mut rw = self.inner.receiving_worker.blocking_lock();
            rw.flush_acks(current, rto, conv)
        };
        for seg in ack_segments {
            let mut buf = BytesMut::new();
            seg.serialize(&mut buf);
            let _ = self.inner.writer.write_packet(&buf).await;
        }

        let has_close = self.state() == State::ReadyToClose;
        let (first_una, data_segments) = {
            let mut sw = self.inner.sending_worker.blocking_lock();
            let una = sw.first_unacknowledged();
            let segs = sw.flush(current, &self.config, rto);
            (una, segs)
        };
        for mut seg in data_segments {
            seg.conv = conv;
            seg.sending_next = first_una;
            seg.option = if has_close {
                SegmentOption::CLOSE
            } else {
                SegmentOption(0)
            };
            let mut buf = BytesMut::new();
            seg.serialize(&mut buf);
            let _ = self.inner.writer.write_packet(&buf).await;
        }

        let last_ping = self.inner.last_ping_time.load(Ordering::Relaxed);
        if current.wrapping_sub(last_ping) >= 3000 {
            self.ping(current, Command::Ping).await;
        }
    }

    async fn ping(&self, current: u32, cmd: Command) {
        let mut seg = CmdOnlySegment::new(cmd);
        seg.conv = self.meta.conversation;
        seg.receiving_next = {
            let rw = self.inner.receiving_worker.blocking_lock();
            rw.next_number()
        };
        seg.sending_next = {
            let sw = self.inner.sending_worker.blocking_lock();
            sw.first_unacknowledged()
        };
        seg.peer_rto = {
            let rt = self.inner.round_trip.blocking_lock();
            rt.timeout()
        };
        if self.state() == State::ReadyToClose {
            seg.option = SegmentOption::CLOSE;
        }
        let mut buf = BytesMut::new();
        seg.serialize(&mut buf);
        let _ = self.inner.writer.write_packet(&buf).await;
        self.inner.last_ping_time.store(current, Ordering::Relaxed);
    }

    pub async fn input(&self, segments: Vec<Segment>) {
        let current = self.elapsed();
        self.inner
            .last_incoming_time
            .store(current, Ordering::Relaxed);

        for seg in &segments {
            match seg {
                Segment::Data(ds) => {
                    if ds.conv != self.meta.conversation {
                        continue;
                    }
                    self.handle_option(ds.option);

                    let mut rw = self.inner.receiving_worker.blocking_lock();
                    rw.process_segment(ds);
                    let has_data = rw.is_data_available();
                    drop(rw);

                    if has_data {
                        self.inner.data_input.notify_one();
                    }
                }
                Segment::Ack(ack) => {
                    if ack.conv != self.meta.conversation {
                        continue;
                    }
                    self.handle_option(ack.option);

                    let rto = {
                        let rt = self.inner.round_trip.blocking_lock();
                        rt.timeout()
                    };
                    let mut sw = self.inner.sending_worker.blocking_lock();
                    sw.process_segment(current, ack, rto);
                    drop(sw);

                    self.inner.data_output.notify_one();
                }
                Segment::CmdOnly(cmd) => {
                    if cmd.conv != self.meta.conversation {
                        continue;
                    }
                    self.handle_option(cmd.option);
                    if cmd.cmd == Command::Terminate {
                        match self.state() {
                            State::Active | State::PeerClosed => {
                                self.set_state(State::PeerTerminating);
                            }
                            State::ReadyToClose => {
                                self.set_state(State::Terminating);
                            }
                            State::Terminating => {
                                self.set_state(State::Terminated);
                            }
                            _ => {}
                        }
                    }
                    if cmd.option.contains_close() || cmd.cmd == Command::Terminate {
                        self.inner.data_input.notify_one();
                        self.inner.data_output.notify_one();
                    }
                    {
                        let mut sw = self.inner.sending_worker.blocking_lock();
                        sw.process_receiving_next(cmd.receiving_next);
                    }
                    {
                        let mut rw = self.inner.receiving_worker.blocking_lock();
                        rw.process_sending_next(cmd.sending_next);
                    }
                    {
                        let mut rt = self.inner.round_trip.blocking_lock();
                        rt.update_peer_rto(cmd.peer_rto, current);
                    }
                }
            }
        }
    }

    fn handle_option(&self, opt: SegmentOption) {
        if opt.contains_close() {
            match self.state() {
                State::ReadyToClose => {
                    self.set_state(State::Terminating);
                }
                State::Active => {
                    self.set_state(State::PeerClosed);
                }
                _ => {}
            }
        }
    }

    pub async fn close(&self) {
        self.inner.data_input.notify_one();
        self.inner.data_output.notify_one();

        match self.state() {
            State::Active => {
                self.set_state(State::ReadyToClose);
            }
            State::PeerClosed => {
                self.set_state(State::Terminating);
            }
            State::PeerTerminating => {
                self.set_state(State::Terminated);
            }
            _ => {}
        }
    }

    pub async fn terminate(&self) {
        self.inner.data_input.notify_one();
        self.inner.data_output.notify_one();
        self.inner.closer.close().await;
    }

    pub async fn read_bytes(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self
                .state()
                .is(&[State::ReadyToClose, State::Terminating, State::Terminated])
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "connection closed",
                ));
            }

            let mut rw = self.inner.receiving_worker.blocking_lock();
            let chunks = rw.read_multi_buffer();
            drop(rw);

            if !chunks.is_empty() {
                let mut written = 0;
                for chunk in &chunks {
                    let to_copy = chunk.len().min(buf.len() - written);
                    buf[written..written + to_copy].copy_from_slice(&chunk[..to_copy]);
                    written += to_copy;
                    if written >= buf.len() {
                        break;
                    }
                }
                if written > 0 {
                    return Ok(written);
                }
            }

            if self.state() == State::PeerTerminating {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "peer terminating",
                ));
            }

            self.wait_for_data_input().await?;
        }
    }

    async fn wait_for_data_input(&self) -> std::io::Result<()> {
        let duration = {
            let rd = self.inner.rd.lock().await;
            rd.map(|d| {
                let now = Instant::now();
                if d <= now { Duration::ZERO } else { d - now }
            })
            .unwrap_or(Duration::from_secs(16))
        };

        tokio::time::timeout(duration, self.inner.data_input.notified())
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout"))?;

        Ok(())
    }

    async fn wait_for_data_output(&self) -> std::io::Result<()> {
        let duration = {
            let wd = self.inner.wd.lock().await;
            wd.map(|d| {
                let now = Instant::now();
                if d <= now { Duration::ZERO } else { d - now }
            })
            .unwrap_or(Duration::from_secs(16))
        };

        tokio::time::timeout(duration, self.inner.data_output.notified())
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "write timeout"))?;

        Ok(())
    }

    pub async fn write_bytes(&self, buf: &[u8]) -> std::io::Result<usize> {
        let mss = self.inner.mss as usize;
        let mut offset = 0;

        loop {
            if self.state() != State::Active {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "connection closed",
                ));
            }

            let end = (offset + mss).min(buf.len());
            let chunk = &buf[offset..end];

            if chunk.is_empty() {
                break;
            }

            let pushed = {
                let mut sw = self.inner.sending_worker.blocking_lock();
                sw.push(bytes::Bytes::copy_from_slice(chunk))
            };

            if pushed {
                offset = end;
            } else {
                self.wait_for_data_output().await?;
            }
        }

        Ok(offset)
    }

    pub fn set_read_deadline(&self, deadline: Option<Instant>) {
        let mut rd = self.inner.rd.blocking_lock();
        *rd = deadline;
    }

    pub fn set_write_deadline(&self, deadline: Option<Instant>) {
        let mut wd = self.inner.wd.blocking_lock();
        *wd = deadline;
    }
}
