//! `reactive` — presses Enter on foreground changes (dialog click-through).
//!
//! Bus-only plugin: it subscribes to `ForegroundChanged` (published by the
//! focus-watch plugin) and synthesizes the key when reactive mode is enabled
//! in the pushed config. Legacy cadence: hold Enter down for 300 ms.

use std::time::Duration;

use async_trait::async_trait;
use kernel::{
    app::plugin_ports::{
        event_bus_port::EventBusPort,
        plugin_port::PluginPort,
    },
    bus::InMemoryEventBus,
};

use crate::{
    domain::{
        ActorBusEvent,
        SharedRuntime,
    },
    ports::InputSynthesisPort,
};

/// Legacy Enter-hold duration.
pub const ENTER_HOLD: Duration = Duration::from_millis(300);

/// Reactive input plugin (bus subscriber, not pipeline middleware).
pub struct ReactivePlugin {
    bus: InMemoryEventBus<ActorBusEvent>,
    input: std::sync::Arc<dyn InputSynthesisPort>,
    runtime: SharedRuntime,
    hold: Duration,
}

impl ReactivePlugin {
    /// Assemble with the legacy hold duration.
    #[must_use]
    pub fn new(
        bus: InMemoryEventBus<ActorBusEvent>,
        input: std::sync::Arc<dyn InputSynthesisPort>,
        runtime: SharedRuntime,
    ) -> Self {
        Self { bus, input, runtime, hold: ENTER_HOLD }
    }

    /// Assemble with an explicit hold duration (tests).
    #[must_use]
    pub const fn with_hold(
        bus: InMemoryEventBus<ActorBusEvent>,
        input: std::sync::Arc<dyn InputSynthesisPort>,
        runtime: SharedRuntime,
        hold: Duration,
    ) -> Self {
        Self { bus, input, runtime, hold }
    }

    /// Consume bus events until the bus closes; lag skips events (loss
    /// counted, never a crash).
    pub async fn run(self: std::sync::Arc<Self>) {
        let mut rx = self.bus.subscribe();
        loop {
            match rx.recv().await {
                Ok(ActorBusEvent::ForegroundChanged { .. }) => {
                    let Some(config) = self.runtime.lock().config.clone() else { continue };
                    if !config.reactive {
                        continue;
                    }
                    if let Err(error) = self.input.press_enter(self.hold).await {
                        tracing::warn!(%error, "reactive Enter press failed");
                    } else {
                        tracing::debug!(
                            hold_ms = u64::try_from(self.hold.as_millis()).unwrap_or(u64::MAX),
                            "reactive Enter"
                        );
                    }
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                    tracing::warn!(missed, "reactive plugin lagged; events skipped");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    }
}

#[async_trait]
impl PluginPort for ReactivePlugin {
    fn name(&self) -> &'static str {
        "reactive"
    }
}
