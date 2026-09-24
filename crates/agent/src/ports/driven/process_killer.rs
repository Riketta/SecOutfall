//! Process termination port — the finalizer's cleanup of known Office-style
//! helper processes before the VM bounces.

use async_trait::async_trait;

/// Termination outcome for one finalize sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KillOutcome {
    /// Processes terminated.
    pub killed: u32,
    /// Processes found but not terminated (access denied, race with exit).
    pub failed: u32,
}

impl KillOutcome {
    /// Were any processes found at all?
    #[must_use]
    pub fn found_any(&self) -> bool {
        self.killed + self.failed > 0
    }
}

/// Driven port: terminate every running process whose image name matches one
/// of the configured names (case-insensitive, `.exe`-tolerant).
///
/// The agent must never terminate itself; adapters enforce that.
#[async_trait]
pub trait ProcessKillerPort: Send + Sync + 'static {
    /// Sweep all matching processes.
    ///
    /// # Errors
    /// Only for a sweep that could not run at all (adapter unavailable,
    /// snapshot failure) — individual process failures are counted in the
    /// outcome, not raised.
    async fn kill_by_image_names(&self, image_names: &[String]) -> anyhow::Result<KillOutcome>;
}
