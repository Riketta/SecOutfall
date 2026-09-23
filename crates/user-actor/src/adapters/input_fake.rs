//! Fake input synthesis: records Enter presses instead of touching the
//! desktop. Tests and dev builds.

use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::ports::{
    InputError,
    InputSynthesisPort,
};

/// Always-succeeding fake recording hold durations.
#[derive(Debug, Default)]
pub struct FakeInput {
    /// Completed presses (hold durations in ms), for assertions.
    pub holds_ms: Mutex<Vec<u64>>,
}

impl FakeInput {
    /// Singleton.
    #[must_use]
    pub const fn new() -> Self {
        Self { holds_ms: Mutex::new(Vec::new()) }
    }

    /// Recorded hold durations in milliseconds.
    #[must_use]
    pub fn holds(&self) -> Vec<u64> {
        self.holds_ms.lock().clone()
    }
}

#[async_trait]
impl InputSynthesisPort for FakeInput {
    async fn press_enter(&self, hold: Duration) -> Result<(), InputError> {
        self.holds_ms.lock().push(u64::try_from(hold.as_millis()).unwrap_or(u64::MAX));
        Ok(())
    }
}

/// Placeholder for binaries built without the `input` feature: every press
/// fails with a clear error.
#[derive(Debug, Default)]
pub struct UnavailableInput;

#[async_trait]
impl InputSynthesisPort for UnavailableInput {
    async fn press_enter(&self, _hold: Duration) -> Result<(), InputError> {
        Err(InputError::Failed("built without the input feature".to_owned()))
    }
}
