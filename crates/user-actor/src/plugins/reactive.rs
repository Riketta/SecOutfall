//! `reactive` — presses Enter on foreground changes (dialog click-through).
//!
//! Bus-only plugin: it subscribes to `ForegroundChanged` (published by the
//! focus-watch plugin) and synthesizes the key when reactive mode is enabled
//! in the pushed config. Legacy cadence: hold Enter down for 300 ms.
//!
//! Storm gate: an adversarial window-flicker storm (trivially manufactured by
//! the analyzed malware) would otherwise keep Enter held down nearly
//! continuously — real desktop input during analysis. Presses are therefore
//! rate-limited to at most one per [`PRESS_MIN_INTERVAL`]; skipped events are
//! counted and reported at debug.

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
    ports::driven::InputSynthesisPort,
};

/// Legacy Enter-hold duration.
pub const ENTER_HOLD: Duration = Duration::from_millis(300);

/// Minimum interval between reactive presses (storm gate): at most one press
/// per window no matter how fast the foreground flips.
pub const PRESS_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// Pure storm-gate decision: a press is allowed only when the previous press
/// (if any) is at least `min_interval` old.
#[must_use]
fn press_allowed(
    last_press: Option<std::time::Instant>,
    now: std::time::Instant,
    min_interval: Duration,
) -> bool {
    last_press.is_none_or(|last| now.duration_since(last) >= min_interval)
}

/// The bus consumer: presses Enter on enabled foreground changes until the
/// bus closes; lag skips events (loss counted, never a crash). The storm
/// gate is task-local state — the consumer is the single task, so a plain
/// local is the whole guard.
async fn consume_bus_events(
    bus: InMemoryEventBus<ActorBusEvent>,
    input: std::sync::Arc<dyn InputSynthesisPort>,
    runtime: SharedRuntime,
    hold: Duration,
) {
    let mut receiver = bus.subscribe();
    let mut last_press: Option<std::time::Instant> = None;
    loop {
        match receiver.recv().await {
            Ok(ActorBusEvent::ForegroundChanged { .. }) => {
                let Some(config) = runtime.lock().config.clone() else { continue };
                if !config.reactive {
                    continue;
                }
                // Storm gate BEFORE synthesizing: at most one press per
                // window, whatever the foreground flicker rate.
                let now = std::time::Instant::now();
                if !press_allowed(last_press, now, PRESS_MIN_INTERVAL) {
                    tracing::debug!("reactive press skipped: storm gate");
                    continue;
                }
                last_press = Some(now);
                if let Err(error) = input.press_enter(hold).await {
                    tracing::warn!(%error, "reactive Enter press failed");
                } else {
                    tracing::debug!(
                        hold_ms = u64::try_from(hold.as_millis()).unwrap_or(u64::MAX),
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

/// Reactive input plugin (bus subscriber, not pipeline middleware).
pub struct ReactivePlugin {
    bus: InMemoryEventBus<ActorBusEvent>,
    input: std::sync::Arc<dyn InputSynthesisPort>,
    runtime: SharedRuntime,
    hold: Duration,
    /// The consumer task spawned at [`PluginPort::start`] — the plugin is
    /// inert without it (the historical bug: only tests ever spawned the
    /// loop).
    consumer: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl ReactivePlugin {
    /// Assemble with the legacy hold duration.
    #[must_use]
    pub fn new(
        bus: InMemoryEventBus<ActorBusEvent>,
        input: std::sync::Arc<dyn InputSynthesisPort>,
        runtime: SharedRuntime,
    ) -> Self {
        Self { bus, input, runtime, hold: ENTER_HOLD, consumer: parking_lot::Mutex::new(None) }
    }

    /// Assemble with an explicit hold duration (tests).
    #[must_use]
    pub fn with_hold(
        bus: InMemoryEventBus<ActorBusEvent>,
        input: std::sync::Arc<dyn InputSynthesisPort>,
        runtime: SharedRuntime,
        hold: Duration,
    ) -> Self {
        Self { bus, input, runtime, hold, consumer: parking_lot::Mutex::new(None) }
    }
}

#[async_trait]
impl PluginPort for ReactivePlugin {
    fn name(&self) -> &'static str {
        "reactive"
    }

    /// Spawns the bus consumer. The loop ends by itself when the bus closes
    /// (kernel shutdown drops it); `stop` aborts it explicitly so shutdown
    /// never depends on drop timing.
    async fn start(&self) -> Result<(), kernel::models::PluginError> {
        let handle = tokio::spawn(consume_bus_events(
            self.bus.clone(),
            std::sync::Arc::clone(&self.input),
            self.runtime.clone(),
            self.hold,
        ));
        *self.consumer.lock() = Some(handle);
        Ok(())
    }

    async fn stop(&self) -> Result<(), kernel::models::PluginError> {
        if let Some(handle) = self.consumer.lock().take() {
            handle.abort();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    #[test]
    fn storm_gate_rates_limit_presses() {
        let now = std::time::Instant::now();
        assert!(super::press_allowed(None, now, super::PRESS_MIN_INTERVAL));
        // Pressed 1 ms short of the interval: still gated.
        let one_ms = std::time::Duration::from_millis(1);
        let recent = now
            .checked_sub(super::PRESS_MIN_INTERVAL.checked_sub(one_ms).unwrap_or(one_ms))
            .expect("test offset within Instant range");
        assert!(!super::press_allowed(Some(recent), now, super::PRESS_MIN_INTERVAL));
        // Exactly the interval has elapsed: allowed again.
        let just_elapsed = now.checked_sub(super::PRESS_MIN_INTERVAL).unwrap();
        assert!(super::press_allowed(Some(just_elapsed), now, super::PRESS_MIN_INTERVAL));
    }
}
