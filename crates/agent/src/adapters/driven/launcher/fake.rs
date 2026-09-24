//! Fake launcher: records launch specs for assertions.

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::ports::driven::process_launcher::{
    LaunchError,
    LaunchOutcome,
    LaunchSpec,
    ProcessLauncherPort,
};

/// Records every launch request; never fails.
#[derive(Debug, Default)]
pub struct FakeLauncher {
    launched: Mutex<Vec<LaunchSpec>>,
    next_pid: std::sync::atomic::AtomicU32,
}

impl FakeLauncher {
    /// All launch requests, in order.
    #[must_use]
    pub fn launched(&self) -> Vec<LaunchSpec> {
        self.launched.lock().clone()
    }
}

#[async_trait]
impl ProcessLauncherPort for FakeLauncher {
    async fn launch(&self, spec: &LaunchSpec) -> Result<LaunchOutcome, LaunchError> {
        self.launched.lock().push(spec.clone());
        let pid = self.next_pid.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(LaunchOutcome { pid: Some(pid) })
    }
}
