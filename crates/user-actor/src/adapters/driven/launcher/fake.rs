//! Fake app launcher: records launch requests instead of creating processes.
//! Tests and dev builds.

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::watch;

use crate::ports::driven::{
    AppLaunchError,
    AppLauncherPort,
};

/// One recorded launch request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedLaunch {
    /// Program as requested (unquoted).
    pub program: String,
    /// Arguments as requested.
    pub args: Vec<String>,
}

/// Fake launcher keeping every request; exposes a `watch` channel so tests
/// can await the Nth launch deterministically.
#[derive(Debug)]
pub struct FakeAppLauncher {
    launches: Mutex<Vec<RecordedLaunch>>,
    count_tx: watch::Sender<usize>,
    /// When true, every launch fails (desktop-gone simulation).
    pub fail_launches: std::sync::atomic::AtomicBool,
}

impl Default for FakeAppLauncher {
    fn default() -> Self {
        let (count_tx, _) = watch::channel(0);
        Self {
            launches: Mutex::new(Vec::new()),
            count_tx,
            fail_launches: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl FakeAppLauncher {
    /// Fresh fake.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Recorded launches in request order.
    #[must_use]
    pub fn launches(&self) -> Vec<RecordedLaunch> {
        self.launches.lock().clone()
    }

    /// A receiver for the launch count (tests await thresholds on it).
    #[must_use]
    pub fn count_rx(&self) -> watch::Receiver<usize> {
        self.count_tx.subscribe()
    }
}

#[async_trait]
impl AppLauncherPort for FakeAppLauncher {
    async fn launch(&self, program: &str, args: &[String]) -> Result<u32, AppLaunchError> {
        if self.fail_launches.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(AppLaunchError::Create("fake failure".to_owned()));
        }
        self.launches
            .lock()
            .push(RecordedLaunch { program: program.to_owned(), args: args.to_vec() });
        self.count_tx.send_replace(self.launches.lock().len());
        Ok(4_000 + u32::try_from(self.launches.lock().len()).unwrap_or(0))
    }
}

/// Placeholder for binaries built without the `apps` feature: every launch
/// fails with a clear error.
#[derive(Debug, Default)]
pub struct UnavailableAppLauncher;

#[async_trait]
impl AppLauncherPort for UnavailableAppLauncher {
    async fn launch(&self, _program: &str, _args: &[String]) -> Result<u32, AppLaunchError> {
        Err(AppLaunchError::Create("built without the apps feature".to_owned()))
    }
}
