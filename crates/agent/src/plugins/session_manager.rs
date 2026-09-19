//! `session-manager` — the session lifecycle state machine (early version of the
//! planned `finalizer`; score/drops reports, clock offset and process kills land
//! with their adapters in later phases).
//!
//! Fixes applied vs legacy:
//! - `uptimes` overrun no longer panics: a session beyond the planned table runs
//!   dynamic (no scheduled deadline) and finalize resolves to a clean decision
//!   instead of `IndexOutOfRangeException`.
//! - Dead-scope early finalization only fires when the scope actually died.

use std::sync::{
    Arc,
    atomic::{
        AtomicBool,
        AtomicU64,
        Ordering,
    },
};

use async_trait::async_trait;
use kernel::{
    app::plugin_ports::{
        event_bus_port::EventBusPort,
        middleware_plugin_port::{
            MiddlewarePluginPort,
            Next,
        },
        plugin_port::PluginPort,
    },
    bus::InMemoryEventBus,
};
use parking_lot::Mutex;
use protocol::{
    events::EventType,
    payload::{
        AgentStateData,
        FinalizeReason,
        Payload,
        SessionEndedData,
        SessionFinalizingData,
        SessionStartedData,
        StudyRebootRequestedData,
        StudyShutdownRequestedData,
    },
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{
    app::{
        builder::AgentServices,
        event::{
            AgentBusEvent,
            SandboxEvent,
        },
    },
    domain::scope::{
        SessionRecord,
        SharedScopeState,
    },
    ports::{
        broker::{
            BrokerPort,
            Channel,
        },
        clock::SystemClockPort,
        scope_repository::ScopeRepository,
    },
};

/// Constructor dependencies (kept a struct — the plugin needs many ports).
pub struct SessionManagerDeps {
    /// Shared scope state (loaded from the repository by the composition root).
    pub state: SharedScopeState,
    /// Durable storage for finalization.
    pub repo: Arc<dyn ScopeRepository>,
    /// Wire output.
    pub broker: Arc<dyn BrokerPort>,
    /// Time source.
    pub clock: Arc<dyn SystemClockPort>,
    /// Planned session durations, seconds.
    pub uptimes: Arc<Vec<u64>>,
    /// Finalize early when the scope dies.
    pub autoshutdown: bool,
    /// Agent version for `agent.state`.
    pub agent_version: String,
    /// Bus handle for the dead-scope subscription.
    pub bus: InMemoryEventBus<AgentBusEvent>,
    /// Shared per-boot wire sequence counter.
    pub seq: Arc<AtomicU64>,
}

/// Session lifecycle plugin.
pub struct SessionManagerPlugin {
    deps: SessionManagerDeps,
    finalized: Arc<AtomicBool>,
    consumer: Mutex<Option<JoinHandle<()>>>,
    cancel: CancellationToken,
}

impl SessionManagerPlugin {
    /// Assemble the plugin.
    #[must_use]
    pub fn new(deps: SessionManagerDeps) -> Self {
        Self {
            deps,
            finalized: Arc::new(AtomicBool::new(false)),
            consumer: Mutex::new(None),
            cancel: CancellationToken::new(),
        }
    }

    /// Finalize the current session (idempotent per boot).
    async fn finalize(&self, reason: FinalizeReason) {
        let ctx = FinalizeCtx {
            state: &self.deps.state,
            repo: &self.deps.repo,
            broker: &self.deps.broker,
            clock: &self.deps.clock,
            uptimes: &self.deps.uptimes,
            seq: &self.deps.seq,
            finalized: &self.finalized,
        };
        finalize_session(&ctx, reason).await;
    }
}

/// Open the session exactly once per boot: after a finalized last session, or on
/// a fresh/absent scope DB. Called from `init`.
fn open_session_if_needed(deps: &SessionManagerDeps) {
    let now_ms = deps.clock.now_ms();
    let mut state = deps.state.lock();
    let need_new = state.sessions.last().is_none_or(|session| session.ended_at_ms.is_some());
    if !need_new {
        return;
    }
    let id = u32::try_from(state.sessions.len()).unwrap_or(u32::MAX);
    let scheduled = deps.uptimes.get(id as usize).copied();
    state.sessions.push(SessionRecord {
        id,
        scheduled_duration_secs: scheduled,
        started_at_ms: now_ms,
        ended_at_ms: None,
        scoped_processes: Vec::new(),
        observed_drops: std::collections::BTreeSet::default(),
    });
}

/// The finalize sequence: close records -> `session.finalizing` -> persist ->
/// `session.ended` -> reboot/shutdown request on the control channel.
///
/// Idempotent via `finalized`; failures of individual publishes are logged, not
/// fatal (the broker may be down — the request is retried by no one, which is
/// the same contract legacy had, minus the silent swallow).
/// Everything the finalize sequence touches, borrowed.
struct FinalizeCtx<'a> {
    state: &'a SharedScopeState,
    repo: &'a Arc<dyn ScopeRepository>,
    broker: &'a Arc<dyn BrokerPort>,
    clock: &'a Arc<dyn SystemClockPort>,
    uptimes: &'a [u64],
    seq: &'a AtomicU64,
    finalized: &'a AtomicBool,
}

async fn finalize_session(ctx: &FinalizeCtx<'_>, reason: FinalizeReason) {
    let FinalizeCtx { state, repo, broker, clock, uptimes, seq, finalized } = ctx;
    if finalized.swap(true, Ordering::SeqCst) {
        return;
    }
    let now_ms = clock.now_ms();
    {
        let mut guard = state.lock();
        let Some(session) = guard.current_session_mut() else {
            tracing::error!("finalize requested with no open session");
            return;
        };
        session.ended_at_ms = Some(now_ms);
        for process in &mut session.scoped_processes {
            if process.ended_at_ms.is_none() {
                process.ended_at_ms = Some(now_ms);
            }
        }
    }

    let (study_id, session_id, session_count) = {
        let guard = state.lock();
        let Some(session) = guard.current_session() else {
            return;
        };
        (guard.study_id, session.id, guard.sessions.len())
    };

    // Reports -> persist -> reboot/shutdown request (legacy order, kept).
    let finalizing = crate::plugins::wire::envelope_raw(
        now_ms,
        crate::plugins::wire::next_seq(seq),
        study_id,
        session_id,
        EventType::SessionFinalizing,
        Payload::SessionFinalizing(SessionFinalizingData { reason }),
    );
    if let Err(error) = broker.publish(Channel::Event, &finalizing).await {
        tracing::error!(%error, "session.finalizing publish failed");
    }

    let snapshot = state.lock().clone();
    if let Err(error) = repo.save(&snapshot).await {
        // Persisting is critical, but a lost save must not wedge the VM: log
        // loudly and continue — the study effectively restarts from scratch.
        tracing::error!(%error, "scope persistence failed; continuing");
    }

    let ended = crate::plugins::wire::envelope_raw(
        now_ms,
        crate::plugins::wire::next_seq(seq),
        study_id,
        session_id,
        EventType::SessionEnded,
        Payload::SessionEnded(SessionEndedData {}),
    );
    if let Err(error) = broker.publish(Channel::Event, &ended).await {
        tracing::error!(%error, "session.ended publish failed");
    }

    // FIXED decision logic: an empty/dynamic table never overruns; the study
    // shuts down exactly when the planned session count is exhausted.
    let shutdown = !uptimes.is_empty() && session_count >= uptimes.len();
    let reason_text = format!("{reason:?}").to_lowercase();
    let request = if shutdown {
        crate::plugins::wire::envelope_raw(
            now_ms,
            crate::plugins::wire::next_seq(seq),
            study_id,
            session_id,
            EventType::StudyShutdownRequested,
            Payload::StudyShutdownRequested(StudyShutdownRequestedData {
                reason: Some(reason_text),
            }),
        )
    } else {
        crate::plugins::wire::envelope_raw(
            now_ms,
            crate::plugins::wire::next_seq(seq),
            study_id,
            session_id,
            EventType::StudyRebootRequested,
            Payload::StudyRebootRequested(StudyRebootRequestedData { reason: Some(reason_text) }),
        )
    };
    if let Err(error) = broker.publish(Channel::Control, &request).await {
        tracing::error!(%error, "reboot/shutdown request publish failed");
    }
}

#[async_trait]
impl PluginPort for SessionManagerPlugin {
    fn name(&self) -> &'static str {
        "session-manager"
    }

    async fn init(&self) -> Result<(), kernel::models::PluginError> {
        open_session_if_needed(&self.deps);
        Ok(())
    }

    async fn start(&self) -> Result<(), kernel::models::PluginError> {
        let (study_id, session_id, scheduled) = {
            let state = self.deps.state.lock();
            let Some(session) = state.current_session() else {
                return Ok(());
            };
            (state.study_id, session.id, session.scheduled_duration_secs)
        };
        let now = self.deps.clock.now_ms();
        let state_report = crate::plugins::wire::envelope_raw(
            now,
            crate::plugins::wire::next_seq(&self.deps.seq),
            study_id,
            session_id,
            EventType::AgentState,
            Payload::AgentState(AgentStateData { agent_version: self.deps.agent_version.clone() }),
        );
        let _ = self.deps.broker.publish(Channel::Event, &state_report).await;
        let started = crate::plugins::wire::envelope_raw(
            now,
            crate::plugins::wire::next_seq(&self.deps.seq),
            study_id,
            session_id,
            EventType::SessionStarted,
            Payload::SessionStarted(SessionStartedData { scheduled_duration_secs: scheduled }),
        );
        let _ = self.deps.broker.publish(Channel::Event, &started).await;

        // Dead-scope subscription: finalize early only under autoshutdown.
        let mut receiver = self.deps.bus.subscribe();
        let cancel = self.cancel.clone();
        let state = Arc::clone(&self.deps.state);
        let repo = Arc::clone(&self.deps.repo);
        let broker = Arc::clone(&self.deps.broker);
        let clock = Arc::clone(&self.deps.clock);
        let uptimes = Arc::clone(&self.deps.uptimes);
        let autoshutdown = self.deps.autoshutdown;
        let finalized = Arc::clone(&self.finalized);
        let seq = Arc::clone(&self.deps.seq);
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Biased: shutdown deterministically wins over pending events.
                    biased;
                    () = cancel.cancelled() => break,
                    event = receiver.recv() => match event {
                        Ok(AgentBusEvent::ScopeDied) => {
                            if autoshutdown {
                                let ctx = FinalizeCtx {
                                    state: &state,
                                    repo: &repo,
                                    broker: &broker,
                                    clock: &clock,
                                    uptimes: &uptimes,
                                    seq: &seq,
                                    finalized: &finalized,
                                };
                                finalize_session(&ctx, FinalizeReason::DeadScope).await;
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                            tracing::warn!(lost = count, "session-manager bus lag");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        });
        *self.consumer.lock() = Some(handle);
        Ok(())
    }

    async fn stop(&self) -> Result<(), kernel::models::PluginError> {
        self.cancel.cancel();
        // Take the handle in a guard-free statement: the parking_lot guard is
        // not Send and must not live across the await below.
        let handle = self.consumer.lock().take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
        Ok(())
    }
}

#[async_trait]
impl MiddlewarePluginPort<SandboxEvent, AgentServices> for SessionManagerPlugin {
    async fn pre(&self, event: &mut SandboxEvent, _services: &AgentServices) -> Next {
        match event {
            SandboxEvent::SessionDeadline => self.finalize(FinalizeReason::Deadline).await,
            SandboxEvent::ServiceStop => self.finalize(FinalizeReason::InboundRequest).await,
            _ => {}
        }
        Next::Continue
    }
}
