//! Fake event source: replays a scripted [`SandboxEvent`] sequence into the
//! inlet. This is the "fake ETW" of the walking skeleton and the simulator.

use std::sync::Arc;

use async_trait::async_trait;
use kernel::app::api_ports::EventInletPort;

use crate::{
    app::event::SandboxEvent,
    ports::driving::event_source::{
        EventSourcePort,
        SourceError,
    },
};

/// Scripted source; `run` clones the script so one instance can feed many boots.
#[derive(Debug, Clone, Default)]
pub struct FakeEventSource {
    script: Vec<SandboxEvent>,
}

impl FakeEventSource {
    /// Source replaying `script` in order.
    #[must_use]
    pub fn new(script: Vec<SandboxEvent>) -> Self {
        Self { script }
    }
}

#[async_trait]
impl EventSourcePort for FakeEventSource {
    async fn run(&self, inlet: Arc<dyn EventInletPort<SandboxEvent>>) -> Result<(), SourceError> {
        for event in &self.script {
            inlet.accept(event.clone()).await;
        }
        Ok(())
    }
}
