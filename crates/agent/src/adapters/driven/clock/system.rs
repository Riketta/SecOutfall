//! Real wall-clock adapter (used by the real agent; time is deliberately fake
//! inside analysis VMs, which is this adapter's problem, not the port's).

use std::time::{
    SystemTime,
    UNIX_EPOCH,
};

use crate::ports::driven::clock::SystemClockPort;

/// `SystemTime`-backed clock.
#[derive(Debug, Default)]
pub struct SystemClock;

impl SystemClockPort for SystemClock {
    fn now_ms(&self) -> i64 {
        let elapsed =
            SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_millis());
        i64::try_from(elapsed).unwrap_or(i64::MAX)
    }
}
