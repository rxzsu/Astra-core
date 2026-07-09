use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;

/// Run `f()`, and if it succeeds run `g()`.
/// Go equivalent: `task.OnSuccess`
pub fn on_success<F, G>(f: F, g: G) -> impl FnOnce() -> Result<(), String>
where
    F: FnOnce() -> Result<(), String>,
    G: FnOnce() -> Result<(), String>,
{
    move || {
        f()?;
        g()
    }
}

/// Run a list of async tasks concurrently, returning the first error (or `Ok(())`).
/// Uses a semaphore to bound concurrency to `n` tasks at a time.
/// Go equivalent: `task.Run`
pub async fn run<I, Fut>(tasks: I) -> Result<(), String>
where
    I: IntoIterator<Item = Fut>,
    Fut: Future<Output = Result<(), String>> + Send + 'static,
{
    let tasks: Vec<Fut> = tasks.into_iter().collect();
    let n = tasks.len();
    if n == 0 {
        return Ok(());
    }
    let sem = Arc::new(Semaphore::new(n));
    let done: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let mut handles = Vec::with_capacity(n);

    for task in tasks {
        let sem = sem.clone();
        let done = done.clone();
        let permit = sem.acquire_owned().await.map_err(|e| e.to_string())?;
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let result = task.await;
            if let Err(e) = result {
                let mut lock = done.lock().unwrap();
                if lock.is_none() {
                    *lock = Some(e);
                }
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let lock = done.lock().unwrap();
    match lock.as_ref() {
        Some(e) => Err(e.clone()),
        None => Ok(()),
    }
}

/// Periodic task runner.
/// Go equivalent: `task.Periodic`
pub struct Periodic {
    interval: Duration,
    execute: Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> + Send + Sync>,
    running: Arc<AtomicBool>,
    join_handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Periodic {
    pub fn new<F, Fut>(interval: Duration, execute: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        Periodic {
            interval,
            execute: Arc::new(move || Box::pin(execute())),
            running: Arc::new(AtomicBool::new(false)),
            join_handle: tokio::sync::Mutex::new(None),
        }
    }

    pub async fn start(self: Arc<Self>) -> Result<(), String> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let running = self.running.clone();
        let interval = self.interval;
        let execute = self.execute.clone();

        let handle = tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            timer.tick().await;
            while running.load(Ordering::SeqCst) {
                timer.tick().await;
                if let Err(e) = execute().await {
                    tracing::error!("periodic task error: {}", e);
                }
            }
        });

        let mut lock = self.join_handle.lock().await;
        *lock = Some(handle);
        Ok(())
    }

    pub async fn close(&self) {
        self.running.store(false, Ordering::SeqCst);
        let mut lock = self.join_handle.lock().await;
        if let Some(h) = lock.take() {
            h.abort();
        }
    }
}

/// Run `fn(i)` for `i in 0..n` in parallel with bounded workers.
/// Go equivalent: `task.ParallelForN`
pub async fn parallel_for_n<F, Fut>(n: usize, workers: Option<usize>, f: Arc<F>) -> Result<(), String>
where
    F: Fn(usize) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), String>> + Send + 'static,
{
    if n == 0 {
        return Ok(());
    }
    let max_workers = workers.unwrap_or_else(|| {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
    });
    let num_workers = max_workers.min(n);
    let chunk = (n + num_workers - 1) / num_workers;

    let err: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let mut handles = Vec::with_capacity(num_workers);

    for w in 0..num_workers {
        let start = w * chunk;
        let end = (start + chunk).min(n);
        if start >= end {
            break;
        }
        let err = err.clone();
        let f = f.clone();
        handles.push(tokio::spawn(async move {
            for i in start..end {
                {
                    let lock = err.lock().unwrap();
                    if lock.is_some() {
                        return;
                    }
                }
                if let Err(e) = f(i).await {
                    let mut lock = err.lock().unwrap();
                    if lock.is_none() {
                        *lock = Some(e);
                    }
                    return;
                }
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let lock = err.lock().unwrap();
    match lock.as_ref() {
        Some(e) => Err(e.clone()),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_on_success_ok() {
        let result = on_success(
            || Ok(()),
            || Ok(()),
        )();
        assert!(result.is_ok());
    }

    #[test]
    fn test_on_success_fail_first() {
        let result = on_success(
            || Err("first fail".into()),
            || Ok(()),
        )();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "first fail");
    }

    #[tokio::test]
    async fn test_run_empty() {
        let result: Result<(), String> = run(vec![] as Vec<std::future::Ready<Result<(), String>>>).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_all_ok() {
        async fn ok_task() -> Result<(), String> { Ok(()) }
        let result = run(vec![ok_task(), ok_task()]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_first_error() {
        let tasks: Vec<Pin<Box<dyn Future<Output = Result<(), String>> + Send>>> = vec![
            Box::pin(async { Ok(()) }),
            Box::pin(async { Err("fail".into()) }),
        ];
        let result = run(tasks).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_periodic_start_stop() {
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = counter.clone();
        let periodic = Arc::new(Periodic::new(Duration::from_millis(10), move || {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }));
        periodic.clone().start().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        periodic.close().await;
        let count = counter.load(Ordering::SeqCst);
        assert!(count >= 2, "expected >=2 ticks, got {}", count);
    }

    #[tokio::test]
    async fn test_parallel_for_n() {
        let results = Arc::new(std::sync::Mutex::new(Vec::new()));
        let r = results.clone();
        let f = Arc::new(move |i: usize| {
            let r = r.clone();
            async move {
                r.lock().unwrap().push(i);
                Ok(())
            }
        });
        parallel_for_n(10, Some(4), f).await.unwrap();
        let mut vals = results.lock().unwrap().clone();
        vals.sort();
        assert_eq!(vals, (0..10).collect::<Vec<_>>());
    }
}
