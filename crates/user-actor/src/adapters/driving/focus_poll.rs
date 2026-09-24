//! Polling focus source: `GetForegroundWindow` every `interval` (legacy: 50 ms).
//!
//! Driving adapter: normalizes snapshots into [`ActorEvent::FocusChanged`]
//! (deduplicated) and hands them to the kernel inlet.

use std::time::Duration;

use kernel::app::api_ports::EventInletPort;
use tokio_util::sync::CancellationToken;

use crate::{
    adapters::driving::focus_shared::resolve_foreground,
    domain::{
        ActorEvent,
        FocusDedup,
    },
};

/// Legacy polling cadence.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Polling focus adapter.
#[derive(Debug)]
pub struct PollingFocusAdapter {
    interval: Duration,
    cancel: CancellationToken,
}

impl PollingFocusAdapter {
    /// Assemble with an explicit cadence.
    #[must_use]
    pub fn new(interval: Duration, cancel: CancellationToken) -> Self {
        Self { interval, cancel }
    }
}

impl PollingFocusAdapter {
    /// Poll until cancelled.
    ///
    /// # Errors
    /// Never currently; the signature keeps driving adapters uniform.
    pub async fn run(
        &self,
        inlet: std::sync::Arc<dyn EventInletPort<ActorEvent>>,
    ) -> Result<(), std::io::Error> {
        let mut dedup = FocusDedup::default();
        loop {
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => return Ok(()),
                () = tokio::time::sleep(self.interval) => {
                    if let Some(focus) = resolve_foreground()
                        && let Some(focus) = dedup.changed(focus)
                    {
                        inlet.accept(ActorEvent::FocusChanged(focus)).await;
                    }
                }
            }
        }
    }
}
