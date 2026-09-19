//! Event source port — the driving contract shared by ETW (today), the future
//! kernel driver, and the simulation harness.

use std::sync::Arc;

use async_trait::async_trait;
use kernel::app::api_ports::EventInletPort;

use crate::app::event::SandboxEvent;

/// Source failures. Adapters map native errors onto this.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    /// The source stopped before it was asked to.
    #[error("event source stopped unexpectedly: {0}")]
    Stopped(String),
}

/// Driving port: emits normalized [`SandboxEvent`]s into the kernel inlet.
/// Implementations run until stopped or failed; one instance per source.
#[async_trait]
pub trait EventSourcePort: Send + Sync + 'static {
    /// Run the source, feeding every event into `inlet`. Returns when the
    /// source's script/session ends (fakes) or on failure (real adapters).
    ///
    /// # Errors
    /// [`SourceError`] when the underlying trace/session machinery fails.
    async fn run(&self, inlet: Arc<dyn EventInletPort<SandboxEvent>>) -> Result<(), SourceError>;
}
