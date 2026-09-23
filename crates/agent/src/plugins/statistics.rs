//! `statistics` — session counters and a periodic summary log.
//!
//! Legacy had a telemetry timer that was never started (bug #9); the rewrite
//! wires the cadence (`StatsTick` from the scheduler) and counts what the
//! pipeline actually sees. Counters live in a shared [`SessionStatistics`]
//! handle so tests and ops can read them without scraping logs.

use std::sync::{
    Arc,
    atomic::{
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
    domain::scope::SharedScopeState,
};

/// Live session counters. Cheap to clone (`Arc` inside counts).
#[derive(Debug, Default)]
pub struct SessionStatistics {
    source_events: AtomicU64,
    screenshots: AtomicU64,
    lifecycle_events: AtomicU64,
    drops_observed: AtomicU64,
    scope_entered: AtomicU64,
    scope_exited: AtomicU64,
    ticks: AtomicU32,
}

/// Point-in-time counter snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatisticsSnapshot {
    /// Raw source telemetry events seen.
    pub source_events: u64,
    /// Screenshot frames received.
    pub screenshots: u64,
    /// Lifecycle events (deadline, ticks, stop).
    pub lifecycle_events: u64,
    /// Drops observed in the scope.
    pub drops_observed: u64,
    /// Processes that joined the scope.
    pub scope_entered: u64,
    /// Processes that left the scope.
    pub scope_exited: u64,
    /// Statistics ticks so far (including this one, when logged from a tick).
    pub ticks: u32,
}

impl SessionStatistics {
    /// Snapshot of all counters.
    #[must_use]
    pub fn snapshot(&self) -> StatisticsSnapshot {
        StatisticsSnapshot {
            source_events: self.source_events.load(Ordering::Relaxed),
            screenshots: self.screenshots.load(Ordering::Relaxed),
            lifecycle_events: self.lifecycle_events.load(Ordering::Relaxed),
            drops_observed: self.drops_observed.load(Ordering::Relaxed),
            scope_entered: self.scope_entered.load(Ordering::Relaxed),
            scope_exited: self.scope_exited.load(Ordering::Relaxed),
            ticks: self.ticks.load(Ordering::Relaxed),
        }
    }
}

/// Statistics plugin (middleware counter + bus consumer).
pub struct StatisticsPlugin {
    state: SharedScopeState,
    bus: InMemoryEventBus<AgentBusEvent>,
    stats: Arc<SessionStatistics>,
    consumer: Mutex<Option<JoinHandle<()>>>,
    cancel: CancellationToken,
}

impl StatisticsPlugin {
    /// Assemble the plugin over a shared counters handle.
    #[must_use]
    pub fn new(
        scope_state: SharedScopeState,
        bus: InMemoryEventBus<AgentBusEvent>,
        counters: Arc<SessionStatistics>,
    ) -> Self {
        Self {
            state: scope_state,
            bus,
            stats: counters,
            consumer: Mutex::new(None),
            cancel: CancellationToken::new(),
        }
    }

    /// The shared counters handle.
    #[must_use]
    pub fn snapshot(&self) -> StatisticsSnapshot {
        self.stats.snapshot()
    }
}

#[async_trait]
impl PluginPort for StatisticsPlugin {
    fn name(&self) -> &'static str {
        "statistics"
    }

    async fn start(&self) -> Result<(), kernel::models::PluginError> {
        let mut receiver = self.bus.subscribe();
        let cancel = self.cancel.clone();
        let stats = Arc::clone(&self.stats);
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    event = receiver.recv() => match event {
                        Ok(AgentBusEvent::DropObserved { .. }) => {
                            stats.drops_observed.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(AgentBusEvent::ProcessEnteredScope { .. }) => {
                            stats.scope_entered.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(AgentBusEvent::ProcessExitedScope { .. }) => {
                            stats.scope_exited.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                            tracing::warn!(lost = count, "statistics bus lag");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    },
                }
            }
        });
        *self.consumer.lock() = Some(handle);
        Ok(())
    }

    async fn stop(&self) -> Result<(), kernel::models::PluginError> {
        self.cancel.cancel();
        let handle = self.consumer.lock().take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
        Ok(())
    }
}

#[async_trait]
impl MiddlewarePluginPort<SandboxEvent, AgentServices> for StatisticsPlugin {
    async fn pre(&self, event: &mut SandboxEvent, _services: &AgentServices) -> Next {
        match event {
            SandboxEvent::Source(_) => {
                self.stats.source_events.fetch_add(1, Ordering::Relaxed);
            }
            SandboxEvent::ScreenshotReceived(_) => {
                self.stats.screenshots.fetch_add(1, Ordering::Relaxed);
            }
            SandboxEvent::StatsTick => {
                let ticks = self.stats.ticks.fetch_add(1, Ordering::Relaxed) + 1;
                let snapshot = self.stats.snapshot();
                let (study_id, session_id) = {
                    let state = self.state.lock();
                    let session_id = state.current_session().map_or(0, |session| session.id);
                    (state.study_id, session_id)
                };
                tracing::info!(
                    study = %study_id,
                    session = session_id,
                    tick = ticks,
                    source_events = snapshot.source_events,
                    drops = snapshot.drops_observed,
                    scope_entered = snapshot.scope_entered,
                    scope_exited = snapshot.scope_exited,
                    screenshots = snapshot.screenshots,
                    "session statistics"
                );
            }
            SandboxEvent::PersistTick
            | SandboxEvent::SessionDeadline
            | SandboxEvent::ServiceStop => {
                self.stats.lifecycle_events.fetch_add(1, Ordering::Relaxed);
            }
            SandboxEvent::InteractiveSessionReady => {}
        }
        Next::Continue
    }
}
