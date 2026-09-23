//! Fake and stand-in process killers: the fake records sweeps for assertions;
//! the unavailable variant explains itself to the finalizer's log.

use std::sync::atomic::{
    AtomicU32,
    Ordering,
};

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::ports::process_killer::{
    KillOutcome,
    ProcessKillerPort,
};

/// Records every sweep and simulates the given outcome. Matches nothing —
/// the names in the last sweep are what the caller asked for.
#[derive(Debug, Default)]
pub struct FakeProcessKiller {
    sweeps: Mutex<Vec<Vec<String>>>,
    killed_per_name: AtomicU32,
}

impl FakeProcessKiller {
    /// Killer that reports `killed` per matching name (for outcome tests).
    #[must_use]
    pub fn with_killed_per_name(killed: u32) -> Self {
        Self { killed_per_name: AtomicU32::new(killed), ..Self::default() }
    }

    /// Every sweep, in order (each sweep is the requested name list).
    #[must_use]
    pub fn sweeps(&self) -> Vec<Vec<String>> {
        self.sweeps.lock().clone()
    }
}

#[async_trait]
impl ProcessKillerPort for FakeProcessKiller {
    async fn kill_by_image_names(&self, image_names: &[String]) -> anyhow::Result<KillOutcome> {
        self.sweeps.lock().push(image_names.to_vec());
        let per_name = self.killed_per_name.load(Ordering::SeqCst);
        let total = u32::try_from(image_names.len()).unwrap_or(u32::MAX).saturating_mul(per_name);
        Ok(KillOutcome { killed: total, failed: 0 })
    }
}

/// Production stand-in when the Toolhelp killer is not compiled in: reports a
/// zero outcome — the finalizer logs that cleanup did not happen.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableProcessKiller;

#[async_trait]
impl ProcessKillerPort for UnavailableProcessKiller {
    async fn kill_by_image_names(&self, _image_names: &[String]) -> anyhow::Result<KillOutcome> {
        anyhow::bail!("process killer unavailable (build with --features killer on Windows)")
    }
}
