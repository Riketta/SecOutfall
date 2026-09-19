//! Process launch port — detonating the target inside the interactive session.

use async_trait::async_trait;

/// What to launch, resolved (path may be a non-executable resolved through
/// shell associations by the caller).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSpec {
    /// Executable path (post association resolution).
    pub path: String,
    /// Argument list (quoted by the adapter for the platform).
    pub args: Vec<String>,
    /// Working directory; `None` = the launched binary's directory.
    pub working_dir: Option<String>,
}

/// Launch outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchOutcome {
    /// Launched process id, when the mechanism reported one.
    pub pid: Option<u32>,
}

/// Launch failures. Adapters map native errors onto this.
#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    /// No interactive session exists (marker process absent / no console session).
    #[error("no interactive session to launch into")]
    NoInteractiveSession,
    /// Token acquisition/duplication failed (privilege or session state).
    #[error("token acquisition failed: {0}")]
    Token(String),
    /// Process creation failed after a usable token existed.
    #[error("process creation failed: {0}")]
    Spawn(String),
}

/// Driven port: launch a process in the interactive user session.
///
/// Two swappable adapters (per resolved config `platform.launch_mechanism`):
/// `TokenProcessLauncher` (native `CreateProcessAsUser`) and the legacy
/// `SchedTaskLauncher` (EventID-777 scheduled-task trick).
#[async_trait]
pub trait ProcessLauncherPort: Send + Sync + 'static {
    /// Launch one process; returns after spawn (does not wait for exit).
    ///
    /// # Errors
    /// [`LaunchError`] describing the failure stage.
    async fn launch(&self, spec: &LaunchSpec) -> Result<LaunchOutcome, LaunchError>;
}
