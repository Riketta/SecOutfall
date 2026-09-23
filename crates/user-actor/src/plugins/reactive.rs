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
    ports::InputSynthesisPort,
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

/// Reactive input plugin (bus subscriber, not pipeline middleware).
pub struct ReactivePlugin {
    bus: InMemoryEventBus<ActorBusEvent>,
    input: std::sync::Arc<dyn InputSynthesisPort>,
    runtime: SharedRuntime,
    hold: Duration,
    /// Instant of the last accepted press (storm gate). The run loop is a
    /// single task; the guard is taken only around a check-and-set, never
    /// across the `press_enter` await.
    last_press: parking_lot::Mutex<Option<std::time::Instant>>,
}

impl ReactivePlugin {
    /// Assemble with the legacy hold duration.
    #[must_use]
    pub fn new(
        bus: InMemoryEventBus<ActorBusEvent>,
        input: std::sync::Arc<dyn InputSynthesisPort>,
        runtime: SharedRuntime,
    ) -> Self {
        Self { bus, input, runtime, hold: ENTER_HOLD, last_press: parking_lot::Mutex::new(None) }
    }

    /// Assemble with an explicit hold duration (tests).
    #[must_use]
    pub const fn with_hold(
        bus: InMemoryEventBus<ActorBusEvent>,
        input: std::sync::Arc<dyn InputSynthesisPort>,
        runtime: SharedRuntime,
        hold: Duration,
    ) -> Self {
        Self { bus, input, runtime, hold, last_press: parking_lot::Mutex::new(None) }
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
                    // Storm gate BEFORE synthesizing: at most one press per
                    // window, whatever the foreground flicker rate.
                    let allowed = {
                        let mut last = self.last_press.lock();
                        let allowed =
                            press_allowed(*last, std::time::Instant::now(), PRESS_MIN_INTERVAL);
                        if allowed {
                            *last = Some(std::time::Instant::now());
                        }
                        allowed
                    };
                    if !allowed {
                        tracing::debug!("reactive press skipped: storm gate");
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
