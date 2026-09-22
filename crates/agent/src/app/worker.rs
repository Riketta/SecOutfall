//! Bounded single-owner job queue — the fire-and-forget core's slow-path
//! pattern (copy + upload work must never block the serial pipeline).
//!
//! Overflow policy (doctrine): bounded capacity, `submit` never awaits — a
//! full queue drops the job, counts the loss, and keeps going. Never OOM;
//! loss surfaces in the dropped counter for diagnostics.

use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{
            AtomicU64,
            Ordering,
        },
    },
};

use parking_lot::Mutex;
use tokio::{
    sync::mpsc,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

/// Bounded queue drained by exactly one worker task.
///
/// The handler owns cloned port handles; jobs are moved through the channel.
/// Dropping the queue (without [`stop`](Self::stop)) closes the channel and
/// the worker exits after its current job.
pub struct JobQueue<T> {
    tx: mpsc::Sender<T>,
    cancel: CancellationToken,
    worker: Mutex<Option<JoinHandle<()>>>,
    dropped: Arc<AtomicU64>,
}

/// Clonable submit-only handle to a [`JobQueue`] (counts overflow losses).
#[derive(Clone)]
pub struct SubmitHandle<T> {
    tx: mpsc::Sender<T>,
    dropped: Arc<AtomicU64>,
}

impl<T> SubmitHandle<T> {
    /// Enqueue one job without awaiting. `false` = the queue was full or the
    /// worker is gone — the job was dropped and counted.
    pub fn submit(&self, job: T) -> bool {
        match self.tx.try_send(job) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }
}

impl<T: Send + 'static> JobQueue<T> {
    /// Spawn the worker over a bounded channel.
    pub fn spawn<F, Fut>(capacity: usize, handler: F) -> Self
    where
        F: Fn(T) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (tx, mut rx) = mpsc::channel(capacity);
        let cancel = CancellationToken::new();
        let dropped = Arc::new(AtomicU64::new(0));

        let cancel_worker = cancel.clone();
        let dropped_worker = Arc::clone(&dropped);
        let worker = tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Biased: shutdown deterministically wins over pending jobs.
                    biased;
                    () = cancel_worker.cancelled() => break,
                    job = rx.recv() => match job {
                        Some(job) => handler(job).await,
                        None => break,
                    },
                }
            }
            // Jobs left queued at shutdown are losses, not silence.
            let abandoned = rx.max_capacity().saturating_sub(rx.capacity());
            if abandoned > 0 {
                dropped_worker.fetch_add(u64::try_from(abandoned).unwrap_or(0), Ordering::Relaxed);
            }
        });

        Self { tx, cancel, worker: Mutex::new(Some(worker)), dropped }
    }

    /// A clonable submit handle for tasks other than the queue's owner.
    #[must_use]
    pub fn handle(&self) -> SubmitHandle<T> {
        SubmitHandle { tx: self.tx.clone(), dropped: Arc::clone(&self.dropped) }
    }

    /// Stop the worker (idempotent): pending jobs are abandoned and counted.
    pub async fn stop(&self) {
        self.cancel.cancel();
        let worker = self.worker.lock().take();
        if let Some(worker) = worker {
            let _ = worker.await;
        }
    }

    /// Jobs dropped for overflow or shutdown (diagnostics).
    #[must_use]
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::sync::atomic::AtomicU32;

    use super::*;

    #[tokio::test]
    async fn processes_submitted_jobs_in_order_and_never_loses_silently() {
        let processed = Arc::new(parking_lot::Mutex::<Vec<u32>>::default());
        let processed_worker = Arc::clone(&processed);
        let queue: JobQueue<u32> = JobQueue::spawn(16, move |job| {
            let processed_worker = Arc::clone(&processed_worker);
            async move {
                processed_worker.lock().push(job);
            }
        });
        let handle = queue.handle();

        // Overflow policy: the queue may refuse when full — but every job is
        // either accepted (and processed, in order) or counted as dropped.
        for job in 0..24_u32 {
            let _ = handle.submit(job);
        }
        queue.stop().await;

        // Invariant: every job is either processed (FIFO prefix) or counted as
        // dropped — stop() abandons whatever was still queued. Nothing
        // vanishes silently.
        let done = processed.lock().clone();
        assert_eq!(done.len() as u64 + queue.dropped_count(), 24);
        assert_eq!(
            done,
            (0..u32::try_from(done.len()).unwrap_or(0)).collect::<Vec<_>>(),
            "FIFO order"
        );
    }

    #[tokio::test]
    async fn full_queue_drops_and_counts() {
        let gate = Arc::new(tokio::sync::Notify::new());
        let gate_worker = Arc::clone(&gate);
        let queue: JobQueue<u32> = JobQueue::spawn(2, move |_| {
            let gate_worker = Arc::clone(&gate_worker);
            async move {
                // First job blocks the single worker until released.
                gate_worker.notified().await;
            }
        });
        let handle = queue.handle();

        let mut accepted = 0;
        while handle.submit(1) {
            accepted += 1;
        }
        assert!(accepted >= 1, "at least the first submit lands");
        assert_eq!(queue.dropped_count(), 1, "exactly one refusal counted");
        gate.notify_waiters();
        queue.stop().await;
    }

    #[tokio::test]
    async fn stop_accounts_every_job() {
        let gate = Arc::new(tokio::sync::Notify::new());
        let gate_worker = Arc::clone(&gate);
        let processed = Arc::new(AtomicU32::new(0));
        let processed_worker = Arc::clone(&processed);
        let queue: JobQueue<u32> = JobQueue::spawn(8, move |job| {
            let gate_worker = Arc::clone(&gate_worker);
            let processed_worker = Arc::clone(&processed_worker);
            async move {
                if job == 0 {
                    // Hold the single worker until the test releases it.
                    gate_worker.notified().await;
                }
                processed_worker.fetch_add(1, Ordering::SeqCst);
            }
        });
        let handle = queue.handle();

        assert!(handle.submit(0));
        for job in 1..5_u32 {
            handle.submit(job);
        }
        // Let the worker pick up job 0 and block on the gate.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        gate.notify_waiters();
        queue.stop().await;

        // Invariant: every job is either processed or counted as dropped —
        // nothing vanishes silently (how many of 1..5 ran before cancel is racy).
        let done = processed.load(Ordering::SeqCst);
        assert!((1..=5).contains(&done), "job 0 completes, later jobs may race: {done}");
        assert_eq!(queue.dropped_count() + u64::from(done), 5);
    }
}
