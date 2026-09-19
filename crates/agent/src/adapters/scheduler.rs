//! Scheduler adapter — the driving port for time-driven events.
//!
//! Emits `SandboxEvent::SessionDeadline` once the current session's scheduled
//! uptime elapses, and owns the control-plane heartbeat (`control.keepalive`,
//! every 15 s, legacy parity). The keepalive bypasses the pipeline on purpose:
//! it is pure periodic wire output, not sandbox telemetry. The deadline is a
//! pipeline event because it drives the core session state machine.
//!
//! Timers use tokio's clock (pausable in tests); durations are computed from
//! the injected `SystemClockPort`'s view of session start.

use std::{
    sync::{
        Arc,
        atomic::AtomicU64,
    },
    time::Duration,
};

use async_trait::async_trait;
use kernel::app::api_ports::EventInletPort;
use protocol::{
    events::EventType,
    payload::{
        ControlKeepaliveData,
        Payload,
    },
};
use tokio_util::sync::CancellationToken;

use crate::{
    app::event::SandboxEvent,
    domain::scope::SharedScopeState,
    plugins::wire,
    ports::{
        broker::{
            BrokerPort,
            Channel,
        },
        clock::SystemClockPort,
        event_source::{
            EventSourcePort,
            SourceError,
        },
    },
};

/// Heartbeat period (legacy parity: 15 s).
pub const KEEPALIVE_PERIOD_SECS: u64 = 15;

/// Time-driven event source: deadline (once) + keepalive (periodic).
pub struct SchedulerAdapter {
    state: SharedScopeState,
    clock: Arc<dyn SystemClockPort>,
    broker: Arc<dyn BrokerPort>,
    seq: Arc<AtomicU64>,
    cancel: CancellationToken,
}

impl SchedulerAdapter {
    /// Assemble the adapter over shared state and wire output.
    #[must_use]
    pub fn new(
        state: SharedScopeState,
        clock: Arc<dyn SystemClockPort>,
        broker: Arc<dyn BrokerPort>,
        seq: Arc<AtomicU64>,
    ) -> Self {
        Self { state, clock, broker, seq, cancel: CancellationToken::new() }
    }

    /// Stop the adapter (idempotent). `run` returns shortly after.
    pub fn stop(&self) {
        self.cancel.cancel();
    }

    /// Seconds from now until the current session's deadline (`None` = dynamic).
    fn deadline_delay_secs(&self) -> Option<u64> {
        let state = self.state.lock();
        let session = state.current_session()?;
        let scheduled = session.scheduled_duration_secs?;
        let elapsed_ms = (self.clock.now_ms() - session.started_at_ms).max(0);
        let elapsed = u64::try_from(elapsed_ms).unwrap_or(0);
        Some(scheduled.saturating_sub(elapsed / 1000))
    }

    async fn keepalive_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(KEEPALIVE_PERIOD_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => break,
                _ = interval.tick() => {
                    let (study_id, session_id) = {
                        let state = self.state.lock();
                        let session_id = state.current_session().map_or(0, |s| s.id);
                        (state.study_id, session_id)
                    };
                    let envelope = wire::envelope_raw(
                        self.clock.now_ms(),
                        wire::next_seq(&self.seq),
                        study_id,
                        session_id,
                        EventType::ControlKeepalive,
                        Payload::ControlKeepalive(ControlKeepaliveData {}),
                    );
                    if let Err(error) = self.broker.publish(Channel::Control, &envelope).await {
                        tracing::error!(%error, "keepalive publish failed");
                    }
                }
            }
        }
    }

    async fn deadline_task(&self, inlet: &Arc<dyn EventInletPort<SandboxEvent>>) {
        let Some(delay_secs) = self.deadline_delay_secs() else {
            // Dynamic session: no scheduled deadline; the scope-die path or an
            // external stop ends the session instead. Park until cancelled.
            self.cancel.cancelled().await;
            return;
        };
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => {}
            () = tokio::time::sleep(Duration::from_secs(delay_secs)) => {
                inlet.accept(SandboxEvent::SessionDeadline).await;
            }
        }
    }
}

#[async_trait]
impl EventSourcePort for SchedulerAdapter {
    /// Runs until the deadline fires (then returns) or [`stop`](Self::stop) is
    /// called. Returning signals the host that the time-driven part of the
    /// session is over.
    ///
    /// # Errors
    /// Never fails; deadline/keepalive failures are logged, not fatal.
    async fn run(&self, inlet: Arc<dyn EventInletPort<SandboxEvent>>) -> Result<(), SourceError> {
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => {}
            () = self.keepalive_loop() => {}
            () = self.deadline_task(&inlet) => {}
        }
        Ok(())
    }
}
