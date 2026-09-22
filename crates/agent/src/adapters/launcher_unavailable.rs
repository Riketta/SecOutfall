//! Production stand-in when no launch adapter is compiled or configured
//! (e.g. `TokenProcessLauncher` requires the `launcher` feature; the legacy
//! `SchedTaskLauncher` adapter is not built yet): every launch fails with a
//! typed, explanatory error. Never a silent no-op.

use async_trait::async_trait;

use crate::ports::process_launcher::{
    LaunchError,
    LaunchOutcome,
    LaunchSpec,
    ProcessLauncherPort,
};

/// Always-failing launcher.
#[derive(Debug, Clone)]
pub struct UnavailableLauncher {
    reason: String,
}

impl UnavailableLauncher {
    /// Explain why launching is unavailable.
    #[must_use]
    pub fn new(reason: &str) -> Self {
        Self { reason: reason.to_owned() }
    }
}

#[async_trait]
impl ProcessLauncherPort for UnavailableLauncher {
    async fn launch(&self, _spec: &LaunchSpec) -> Result<LaunchOutcome, LaunchError> {
        Err(LaunchError::Spawn(format!("launcher unavailable: {}", self.reason)))
    }
}
