use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

// ── Done ────────────────────────────────────────────────────────────────────

/// Channel-based done notification. Thread-safe, may be closed once.
/// Go equivalent: `common/signal/done.Instance`
#[derive(Debug)]
pub struct Done {
    inner: Arc<DoneInner>,
}

#[derive(Debug)]
struct DoneInner {
    notified: Notify,
    closed: AtomicBool,
}

impl Done {
    pub fn new() -> Self {
        Done {
            inner: Arc::new(DoneInner {
                notified: Notify::new(),
                closed: AtomicBool::new(false),
            }),
        }
    }

    pub fn done(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    pub async fn wait(&self) {
        if !self.done() {
            let notified = self.inner.notified.notified();
            tokio::pin!(notified);
            // Check again after pinning
            if !self.done() {
                notified.await;
            }
        }
    }

    pub fn close(&self) -> Result<(), String> {
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return Ok(()); // already closed
        }
        self.inner.notified.notify_waiters();
        Ok(())
    }
}

impl Clone for Done {
    fn clone(&self) -> Self {
        Done {
            inner: self.inner.clone(),
        }
    }
}

impl Default for Done {
    fn default() -> Self {
        Self::new()
    }
}

// ── Notifier ────────────────────────────────────────────────────────────────

/// Non-blocking signal notifier with a buffered channel of capacity 1.
/// Go equivalent: `common/signal.Notifier`
#[derive(Debug)]
pub struct Notifier {
    inner: Arc<Notify>,
}

impl Notifier {
    pub fn new() -> Self {
        Notifier {
            inner: Arc::new(Notify::new()),
        }
    }

    /// Signal a change. Non-blocking — if no consumer is waiting the signal is lost.
    pub fn signal(&self) {
        self.inner.notify_one();
    }

    /// Wait for the next signal.
    pub async fn wait(&self) {
        let notified = self.inner.notified();
        tokio::pin!(notified);
        notified.await;
    }
}

impl Clone for Notifier {
    fn clone(&self) -> Self {
        Notifier {
            inner: self.inner.clone(),
        }
    }
}

impl Default for Notifier {
    fn default() -> Self {
        Self::new()
    }
}

// ── Semaphore ───────────────────────────────────────────────────────────────

/// Semaphore with N permits.
/// Go equivalent: `common/signal/semaphore.Instance`
#[derive(Debug)]
pub struct Semaphore {
    permits: tokio::sync::Semaphore,
}

impl Semaphore {
    pub fn new(n: usize) -> Self {
        Semaphore {
            permits: tokio::sync::Semaphore::new(n),
        }
    }

    /// Wait for a permit. Returns a permit guard that releases on drop.
    pub async fn wait(&self) -> tokio::sync::SemaphorePermit<'_> {
        self.permits.acquire().await.unwrap()
    }

    /// Try to acquire a permit without blocking.
    pub fn try_wait(&self) -> Option<tokio::sync::SemaphorePermit<'_>> {
        self.permits.try_acquire().ok()
    }

    /// Add `n` permits back.
    pub fn signal_n(&self, n: usize) {
        self.permits.add_permits(n);
    }
}

// ── PubSub ──────────────────────────────────────────────────────────────────

/// Publish/subscribe messaging service.
/// Go equivalent: `common/signal/pubsub.Service`
pub struct PubSub {
    tx: tokio::sync::broadcast::Sender<String>,
}

pub struct Subscription {
    rx: tokio::sync::broadcast::Receiver<String>,
    done: Done,
}

impl Subscription {
    pub async fn recv(&mut self) -> Option<String> {
        tokio::select! {
            result = self.rx.recv() => result.ok(),
            _ = self.done.wait() => None,
        }
    }

    pub fn close(&self) {
        let _ = self.done.close();
    }
}

impl PubSub {
    pub fn new() -> Self {
        let (tx, _rx) = tokio::sync::broadcast::channel(256);
        PubSub { tx }
    }

    pub fn subscribe(&self) -> Subscription {
        Subscription {
            rx: self.tx.subscribe(),
            done: Done::new(),
        }
    }

    pub fn publish(&self, message: String) {
        let _ = self.tx.send(message);
    }

    /// Remove closed subscribers — broadcast channels handle this automatically.
    pub fn cleanup(&self) {}
}

impl Default for PubSub {
    fn default() -> Self {
        Self::new()
    }
}

// ── ActivityTimer ───────────────────────────────────────────────────────────

/// Timer that fires after a period of inactivity.
/// Go equivalent: `common/signal.ActivityTimer`
pub struct ActivityTimer {
    updated: Notifier,
    consumed: Arc<AtomicBool>,
    task_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl ActivityTimer {
    pub fn new() -> Self {
        ActivityTimer {
            updated: Notifier::new(),
            consumed: Arc::new(AtomicBool::new(false)),
            task_handle: Arc::new(Mutex::new(None)),
        }
    }

    /// Signal activity — resets the inactivity timer.
    pub fn update(&self) {
        self.updated.signal();
    }

    /// Set the inactivity timeout. When no `update()` is called for `timeout`,
    /// `on_timeout` is invoked.
    pub fn set_timeout<F>(&self, timeout: Duration, on_timeout: F)
    where
        F: Fn() + Send + 'static,
    {
        if self.consumed.load(Ordering::Acquire) {
            return;
        }
        if timeout.is_zero() {
            on_timeout();
            return;
        }

        let updated = self.updated.clone();
        let consumed = self.consumed.clone();

        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = updated.wait() => {
                        continue;
                    }
                    _ = tokio::time::sleep(timeout) => {
                        if consumed.swap(true, Ordering::AcqRel) {
                            return;
                        }
                        on_timeout();
                        return;
                    }
                }
            }
        });

        *self.task_handle.lock().unwrap() = Some(join);
    }

    /// Cancel the timer.
    pub async fn cancel(&self) {
        self.consumed.store(true, Ordering::Release);
        if let Some(h) = self.task_handle.lock().unwrap().take() {
            h.abort();
        }
    }
}

impl Default for ActivityTimer {
    fn default() -> Self {
        Self::new()
    }
}

/// Create an `ActivityTimer` that invokes `on_timeout` after inactivity.
/// Go equivalent: `CancelAfterInactivity`
pub fn cancel_after_inactivity<F>(on_timeout: F, timeout: Duration) -> ActivityTimer
where
    F: Fn() + Send + 'static,
{
    let timer = ActivityTimer::new();
    timer.set_timeout(timeout, on_timeout);
    timer
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[tokio::test]
    async fn test_done() {
        let d = Done::new();
        assert!(!d.done());
        d.close().unwrap();
        assert!(d.done());
        d.close().unwrap(); // double close ok
    }

    #[tokio::test]
    async fn test_done_wait() {
        let d = Done::new();
        let d2 = d.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            d2.close().unwrap();
        });
        tokio::time::timeout(Duration::from_secs(1), d.wait())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_notifier() {
        let n = Notifier::new();
        let n2 = n.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            n2.signal();
        });
        tokio::time::timeout(Duration::from_secs(1), n.wait())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_semaphore() {
        let s = Semaphore::new(2);
        let p1 = s.wait().await;
        let p2 = s.wait().await;
        drop(p1);
        drop(p2);
        let _p3 = s.wait().await;
    }

    #[tokio::test]
    async fn test_activity_timer() {
        let fired = Arc::new(AtomicBool::new(false));
        let f = fired.clone();
        let timer = ActivityTimer::new();
        timer.set_timeout(Duration::from_millis(20), move || {
            f.store(true, Ordering::SeqCst);
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(fired.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_activity_timer_reset() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let timer = ActivityTimer::new();
        timer.set_timeout(Duration::from_millis(30), move || {
            c.fetch_add(1, Ordering::SeqCst);
        });
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            timer.update();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "should fire once after activity stops"
        );
    }
}
