//! `session-manager` — the session lifecycle state machine and **full
//! finalizer**.
//!
//! Finalize sequence (legacy order, kept): reports (`study.score` = session
//! maximum from the scoring plugin, `study.drops_summary` histogram) →
//! `session.finalizing` → clock offset (`clock.adjusted`) → kill configured
//! helper processes → persist → `session.ended` → reboot/shutdown request on
//! the control channel.
//!
//! Fixes applied vs legacy:
//! - `uptimes` overrun no longer panics: a session beyond the planned table
//!   runs dynamic (no scheduled deadline) and finalize resolves to a clean
//!   decision instead of `IndexOutOfRangeException`.
//! - Dead-scope early finalization only fires when the scope actually died.
//! - An unclean reboot (hard VM reset) can no longer stall the study: the
//!   leftover open session is stamped `abandoned` at the next boot and a
//!   fresh session opens — ids always advance one-per-boot.
//! - Clock offset math is pure UTC at the port level (bug #11: legacy mixed
//!   `SetSystemTime` UTC with local `DateTime.Now`).
//! - The periodic persist tick (`PersistTick`) keeps the scope DB fresh so a
//!   VM power loss cannot erase the whole study.

use std::sync::{
    Arc,
    atomic::{
        AtomicBool,
        AtomicU32,
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
    config::TimeConfig,
    events::EventType,
    nats::Envelope,
    payload::{
        AgentStateData,
        ClockAdjustedData,
        ClockCause,
        FinalizeReason,
        Payload,
        SessionEndedData,
        SessionFinalizingData,
        SessionStartedData,
        StudyDropsSummaryData,
        StudyRebootRequestedData,
        StudyScoreData,
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
        clock::{
            ClockShiftPort,
            SystemClockPort,
        },
        process_killer::ProcessKillerPort,
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
    /// Clock manipulation (fake timestamp at study start, finalize offset).
    pub shifter: Arc<dyn ClockShiftPort>,
    /// Finalize-time process cleanup.
    pub killer: Arc<dyn ProcessKillerPort>,
    /// Kill cleanup: configured image names for the finalize sweep.
    pub processes_to_terminate: Arc<Vec<String>>,
    /// Planned session durations, seconds.
    pub uptimes: Arc<Vec<u64>>,
    /// Finalize early when the scope dies.
    pub autoshutdown: bool,
    /// Time manipulation policy (fake start timestamp, finalize offset).
    pub time: TimeConfig,
    /// Debug gate for all clock manipulation.
    pub skip_time_manipulation: bool,
    /// Agent version for `agent.state`.
    pub agent_version: String,
    /// Bus handle: score raises in, dead-scope + score subscriptions out.
    pub bus: InMemoryEventBus<AgentBusEvent>,
    /// Shared per-boot wire sequence counter.
    pub seq: Arc<AtomicU64>,
}

/// Session lifecycle plugin.
pub struct SessionManagerPlugin {
    deps: SessionManagerDeps,
    finalized: Arc<AtomicBool>,
    /// Session maximum score (raised by the scoring plugin over the bus).
    max_score: Arc<AtomicU32>,
    consumers: Mutex<Vec<JoinHandle<()>>>,
    cancel: CancellationToken,
}

impl SessionManagerPlugin {
    /// Assemble the plugin.
    #[must_use]
    pub fn new(deps: SessionManagerDeps) -> Self {
        Self {
            deps,
            finalized: Arc::new(AtomicBool::new(false)),
            max_score: Arc::new(AtomicU32::new(0)),
            consumers: Mutex::new(Vec::new()),
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
            shifter: &self.deps.shifter,
            killer: &self.deps.killer,
            time: &self.deps.time,
            skip_time_manipulation: self.deps.skip_time_manipulation,
            processes_to_terminate: &self.deps.processes_to_terminate,
            uptimes: &self.deps.uptimes,
            seq: &self.deps.seq,
            finalized: &self.finalized,
            max_score: &self.max_score,
        };
        finalize_session(&ctx, reason).await;
    }
}

/// Open the session exactly once per boot: stamp a leftover open session as
/// abandoned, then always push a fresh record. Called from `init`.
///
/// An open session at init time can only be an unclean-reboot leftover: the
/// finalize path always stamps `ended_at_ms` BEFORE the reboot/shutdown
/// request, so a persisted session without an end timestamp means the VM lost
/// power or was hard-reset mid-session. Reusing that record would stall the
/// study (the second boot would re-publish `session.started` for the same id);
/// instead the stale record is closed as `abandoned` evidence and a fresh
/// session opens, keeping ids one-per-boot.
fn open_session_if_needed(deps: &SessionManagerDeps) {
    let now_ms = deps.clock.now_ms();
    let mut state = deps.state.lock();
    if let Some(session) = state.sessions.last_mut() {
        if session.ended_at_ms.is_none() {
            tracing::warn!(
                abandoned_session = session.id,
                "unclean reboot: session still open at boot; stamping abandoned"
            );
            session.ended_at_ms = Some(now_ms);
            session.abandoned = true;
        }
    }
    let id = u32::try_from(state.sessions.len()).unwrap_or(u32::MAX);
    let scheduled = deps.uptimes.get(id as usize).copied();
    state.sessions.push(SessionRecord {
        id,
        scheduled_duration_secs: scheduled,
        started_at_ms: now_ms,
        ended_at_ms: None,
        abandoned: false,
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
    shifter: &'a Arc<dyn ClockShiftPort>,
    killer: &'a Arc<dyn ProcessKillerPort>,
    time: &'a TimeConfig,
    skip_time_manipulation: bool,
    processes_to_terminate: &'a [String],
    uptimes: &'a [u64],
    seq: &'a AtomicU64,
    finalized: &'a AtomicBool,
    max_score: &'a AtomicU32,
}

async fn finalize_session(ctx: &FinalizeCtx<'_>, reason: FinalizeReason) {
    let FinalizeCtx {
        state,
        repo,
        broker,
        clock,
        shifter,
        killer,
        time,
        skip_time_manipulation,
        processes_to_terminate,
        uptimes,
        seq,
        finalized,
        max_score,
    } = ctx;
    if finalized.swap(true, Ordering::SeqCst) {
        return;
    }
    // One coherent timestamp for the whole finalize: the offset shift below
    // must not skew the reports' wire time.
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
    let emit = |event_type, data| {
        crate::plugins::wire::envelope_raw(
            now_ms,
            crate::plugins::wire::next_seq(seq),
            study_id,
            session_id,
            event_type,
            data,
        )
    };

    // Reports -> offset -> kills -> persist -> ended -> reboot/shutdown
    // (legacy order, kept).
    let finalizing = emit(
        EventType::SessionFinalizing,
        Payload::SessionFinalizing(SessionFinalizingData { reason }),
    );
    if let Err(error) = broker.publish(Channel::Event, &finalizing).await {
        tracing::error!(%error, "session.finalizing publish failed");
    }

    publish_finalize_reports(broker, emit, state, max_score).await;
    shift_clock_at_finalize(broker, emit, shifter, time, *skip_time_manipulation, now_ms).await;

    // Kill configured helper processes (best-effort; the VM bounces anyway).
    if !processes_to_terminate.is_empty() {
        match killer.kill_by_image_names(processes_to_terminate).await {
            Ok(outcome) => {
                tracing::info!(
                    killed = outcome.killed,
                    failed = outcome.failed,
                    "finalize process cleanup"
                );
            }
            Err(error) => {
                tracing::warn!(%error, "finalize process cleanup unavailable/failed");
            }
        }
    }

    let snapshot = state.lock().clone();
    if let Err(error) = repo.save(&snapshot).await {
        // Persisting is critical, but a lost save must not wedge the VM: log
        // loudly and continue — the study effectively restarts from scratch.
        tracing::error!(%error, "scope persistence failed; continuing");
    }

    let ended = emit(EventType::SessionEnded, Payload::SessionEnded(SessionEndedData {}));
    if let Err(error) = broker.publish(Channel::Event, &ended).await {
        tracing::error!(%error, "session.ended publish failed");
    }

    // FIXED decision logic: an empty/dynamic table never overruns; the study
    // shuts down exactly when the planned session count is exhausted.
    let shutdown = !uptimes.is_empty() && session_count >= uptimes.len();
    let reason_text = format!("{reason:?}").to_lowercase();
    let request = if shutdown {
        emit(
            EventType::StudyShutdownRequested,
            Payload::StudyShutdownRequested(StudyShutdownRequestedData {
                reason: Some(reason_text),
            }),
        )
    } else {
        emit(
            EventType::StudyRebootRequested,
            Payload::StudyRebootRequested(StudyRebootRequestedData { reason: Some(reason_text) }),
        )
    };
    if let Err(error) = broker.publish(Channel::Control, &request).await {
        tracing::error!(%error, "reboot/shutdown request publish failed");
    }
}

/// `study.score` (session maximum) + `study.drops_summary` (extension
/// histogram) — the legacy finalize reports, now structured.
async fn publish_finalize_reports(
    broker: &Arc<dyn BrokerPort>,
    emit: impl Fn(EventType, Payload) -> Envelope<Payload>,
    state: &SharedScopeState,
    max_score: &AtomicU32,
) {
    let drops_histogram = drops_histogram(&state.lock());
    let score = max_score.load(Ordering::SeqCst);
    for (event_type, data) in [
        (
            EventType::StudyScore,
            Payload::StudyScore(StudyScoreData { score, reason: Some("Total".to_owned()) }),
        ),
        (
            EventType::StudyDropsSummary,
            Payload::StudyDropsSummary(StudyDropsSummaryData { extensions: drops_histogram }),
        ),
    ] {
        if let Err(error) = broker.publish(Channel::Event, &emit(event_type, data)).await {
            tracing::error!(%error, event = %event_type, "finalize report publish failed");
        }
    }
}

/// Legacy finalize offset: `time.offset_secs` added per finalize (UTC-safe at
/// the port level — bug #11), reported as `clock.adjusted`.
async fn shift_clock_at_finalize(
    broker: &Arc<dyn BrokerPort>,
    emit: impl Fn(EventType, Payload) -> Envelope<Payload>,
    shifter: &Arc<dyn ClockShiftPort>,
    time: &TimeConfig,
    skip_time_manipulation: bool,
    now_ms: i64,
) {
    if skip_time_manipulation || time.offset_secs == 0 {
        return;
    }
    let target = now_ms + time.offset_secs * 1000;
    match shifter.set_unix_ms(target).await {
        Ok(()) => {
            tracing::info!(to_ts = target, offset_secs = time.offset_secs, "clock shifted");
            let adjusted = emit(
                EventType::ClockAdjusted,
                Payload::ClockAdjusted(ClockAdjustedData {
                    to_ts: target,
                    offset_secs: time.offset_secs,
                    cause: ClockCause::SessionOffset,
                }),
            );
            if let Err(error) = broker.publish(Channel::Event, &adjusted).await {
                tracing::error!(%error, "clock.adjusted publish failed");
            }
        }
        Err(error) => {
            tracing::warn!(%error, "finalize clock offset failed; study time drifts");
        }
    }
}

/// Extension histogram over the session's observed drops (`""` =
/// extensionless), the structured successor of the legacy string histogram.
fn drops_histogram(
    state: &crate::domain::scope::ScopeState,
) -> std::collections::BTreeMap<String, u32> {
    let mut histogram = std::collections::BTreeMap::new();
    let Some(session) = state.current_session() else {
        return histogram;
    };
    for path in &session.observed_drops {
        let extension = std::path::Path::new(path)
            .extension()
            .map(|ext| ext.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        *histogram.entry(extension).or_insert(0) += 1;
    }
    histogram
}

/// Session-0 fake timestamp: `time.timestamp` set through the shifter and
/// reported as `clock.adjusted` (legacy `system_time_timestamp`, skipped under
/// `debug.skip_time_manipulation`).
async fn apply_study_start_timestamp(
    plugin: &SessionManagerPlugin,
    session_count: usize,
    study_id: uuid::Uuid,
    session_id: u32,
) {
    if session_count != 1 || plugin.deps.skip_time_manipulation || plugin.deps.time.timestamp == 0 {
        return;
    }
    let target_ms = i64::try_from(plugin.deps.time.timestamp).unwrap_or(0).saturating_mul(1000);
    let real_now = plugin.deps.clock.now_ms();
    match plugin.deps.shifter.set_unix_ms(target_ms).await {
        Ok(()) => {
            tracing::info!(to_ts = target_ms, "fake study timestamp applied");
            let adjusted = crate::plugins::wire::envelope_raw(
                target_ms,
                crate::plugins::wire::next_seq(&plugin.deps.seq),
                study_id,
                session_id,
                EventType::ClockAdjusted,
                Payload::ClockAdjusted(ClockAdjustedData {
                    to_ts: target_ms,
                    offset_secs: (target_ms - real_now) / 1000,
                    cause: ClockCause::StudyStart,
                }),
            );
            let _ = plugin.deps.broker.publish(Channel::Event, &adjusted).await;
        }
        Err(error) => {
            tracing::warn!(%error, "study timestamp could not be applied");
        }
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
        let (study_id, session_id, scheduled, session_count) = {
            let state = self.deps.state.lock();
            let Some(session) = state.current_session() else {
                return Ok(());
            };
            (state.study_id, session.id, session.scheduled_duration_secs, state.sessions.len())
        };

        apply_study_start_timestamp(self, session_count, study_id, session_id).await;

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

        // Bus subscriptions: dead-scope finalize (autoshutdown) + score raises.
        let mut receiver = self.deps.bus.subscribe();
        let cancel = self.cancel.clone();
        let state = Arc::clone(&self.deps.state);
        let repo = Arc::clone(&self.deps.repo);
        let broker = Arc::clone(&self.deps.broker);
        let clock = Arc::clone(&self.deps.clock);
        let shifter = Arc::clone(&self.deps.shifter);
        let killer = Arc::clone(&self.deps.killer);
        let processes_to_terminate = Arc::clone(&self.deps.processes_to_terminate);
        let time = self.deps.time;
        let skip_time_manipulation = self.deps.skip_time_manipulation;
        let uptimes = Arc::clone(&self.deps.uptimes);
        let autoshutdown = self.deps.autoshutdown;
        let finalized = Arc::clone(&self.finalized);
        let max_score = Arc::clone(&self.max_score);
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
                                    shifter: &shifter,
                                    killer: &killer,
                                    time: &time,
                                    skip_time_manipulation,
                                    processes_to_terminate: &processes_to_terminate,
                                    uptimes: &uptimes,
                                    seq: &seq,
                                    finalized: &finalized,
                                    max_score: &max_score,
                                };
                                finalize_session(&ctx, FinalizeReason::DeadScope).await;
                                break;
                            }
                        }
                        Ok(AgentBusEvent::SessionScoreRaised { score }) => {
                            max_score.fetch_max(score, Ordering::SeqCst);
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                            tracing::warn!(lost = count, "session-manager bus lag");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    },
                }
            }
        });
        self.consumers.lock().push(handle);
        Ok(())
    }

    async fn stop(&self) -> Result<(), kernel::models::PluginError> {
        self.cancel.cancel();
        // Take the handles in a guard-free statement: the parking_lot guard is
        // not Send and must not live across the await below.
        let handles = self.consumers.lock().drain(..).collect::<Vec<_>>();
        for handle in handles {
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
            SandboxEvent::PersistTick if !self.finalized.load(Ordering::SeqCst) => {
                let snapshot = self.deps.state.lock().clone();
                if let Err(error) = self.deps.repo.save(&snapshot).await {
                    tracing::warn!(%error, "periodic scope persistence failed");
                }
            }
            _ => {}
        }
        Next::Continue
    }
}
