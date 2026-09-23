//! Fake clock: fully deterministic time for tests and the study simulator.

use std::sync::atomic::{
    AtomicI64,
    Ordering,
};

use crate::ports::clock::{
    ClockShiftError,
    ClockShiftPort,
    SystemClockPort,
};

/// Injectable clock. Advance it manually — a 24-session study simulates in
/// milliseconds.
#[derive(Debug)]
pub struct FakeClock {
    now_ms: AtomicI64,
}

impl FakeClock {
    /// Clock pinned at `start_ms`.
    #[must_use]
    pub fn new(start_ms: i64) -> Self {
        Self { now_ms: AtomicI64::new(start_ms) }
    }

    /// Move the clock forward (or backward) by `delta_ms`.
    pub fn advance_ms(&self, delta_ms: i64) {
        self.now_ms.fetch_add(delta_ms, Ordering::SeqCst);
    }

    /// Hard-set the clock (fake system time manipulation).
    pub fn set_ms(&self, value_ms: i64) {
        self.now_ms.store(value_ms, Ordering::SeqCst);
    }
}

impl SystemClockPort for FakeClock {
    fn now_ms(&self) -> i64 {
        self.now_ms.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl ClockShiftPort for FakeClock {
    async fn set_unix_ms(&self, unix_ms: i64) -> Result<(), ClockShiftError> {
        self.set_ms(unix_ms);
        Ok(())
    }
}
