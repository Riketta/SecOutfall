//! Scheduler adapter — the driving port for time-driven events.
//!
//! Emits `SandboxEvent::SessionDeadline` once the current session's scheduled
//! uptime elapses, and owns the control-plane heartbeat (`control.keepalive`,
//! every 15 s, legacy parity). The keepalive bypasses the pipeline on purpose:
//! it is pure periodic wire output, not sandbox telemetry. The deadline is a
//! pipeline event because it drives the core session state machine.
//!
//! Timers use tokio's clock (pausable in tests). The deadline measures
//! BOOT-LOCAL monotonic time, not the injected clock's view of the session:
//! the wall clock inside the VM is deliberately fake and the study start may
//! jump it by any amount — a forward-dated `time.timestamp` made the old
//! `now - started_at` elapsed enormous and finalized session 0 instantly.

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
        driven::{
            broker::{
                BrokerPort,
                Channel,
            },
            clock::SystemClockPort,
        },
        driving::event_source::{
            EventSourcePort,
            SourceError,
        },
    },
};

/// Heartbeat period (legacy parity: 15 s).
pub const KEEPALIVE_PERIOD_SECS: u64 = 15;
/// Periodic scope persistence (legacy parity: 15 s scope save).
pub const PERSIST_PERIOD_SECS: u64 = 15;
/// Periodic statistics summary.
pub const STATS_PERIOD_SECS: u64 = 60;

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

    /// The current session's scheduled uptime, if any (`None` = dynamic).
    fn scheduled_secs(&self) -> Option<u64> {
        let state = self.state.lock();
        state.current_session()?.scheduled_duration_secs
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

    async fn persist_loop(&self, inlet: &Arc<dyn EventInletPort<SandboxEvent>>) {
        let mut interval = tokio::time::interval(Duration::from_secs(PERSIST_PERIOD_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => break,
                _ = interval.tick() => {
                    inlet.accept(SandboxEvent::PersistTick).await;
                }
            }
        }
    }

    async fn stats_loop(&self, inlet: &Arc<dyn EventInletPort<SandboxEvent>>) {
        let mut interval = tokio::time::interval(Duration::from_secs(STATS_PERIOD_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => break,
                _ = interval.tick() => {
                    inlet.accept(SandboxEvent::StatsTick).await;
                }
            }
        }
    }

    async fn deadline_task(&self, inlet: &Arc<dyn EventInletPort<SandboxEvent>>) {
        let Some(scheduled) = self.scheduled_secs() else {
            // Dynamic session: no scheduled deadline; the scope-die path or an
            // external stop ends the session instead. Park until cancelled.
            self.cancel.cancelled().await;
            return;
        };
        // Monotonic uptime from scheduler start: the wall clock is a plaything
        // of the study (see the module doc) — boot-local time is immune to it
        // by construction. The scheduler starts within the same assembly as
        // the session open, so the skew against `started_at_ms` is sub-second.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(scheduled);
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => {}
            () = tokio::time::sleep_until(deadline) => {
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
            () = self.persist_loop(&inlet) => {}
            () = self.stats_loop(&inlet) => {}
            () = self.deadline_task(&inlet) => {}
        }
        Ok(())
    }
}
