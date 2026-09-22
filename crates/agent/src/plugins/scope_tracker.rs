//! `scope-tracker` — process-tree membership and drop detection.
//!
//! Publishes derived bus events (`TargetLaunched`, `ProcessEnteredScope`,
//! `ProcessExitedScope`, `DropObserved`, `DropClosed`, `ScopeDied`); the dead-
//! scope check is the FIXED logic (empty session != dead).

use std::sync::Arc;

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
    app::event::{
        AgentBusEvent,
        SandboxEvent,
        SourceEvent,
    },
    domain::{
        drop_filter::DropFilter,
        scope::{
            ScopeTracker,
            SharedScopeState,
        },
    },
    ports::clock::SystemClockPort,
};

/// Membership + drop detection plugin. Owns the non-persisted tracking state;
/// mutates the shared [`crate::domain::scope::ScopeState`].
pub struct ScopeTrackerPlugin {
    state: SharedScopeState,
    tracker: Arc<Mutex<ScopeTracker>>,
    filter: Arc<DropFilter>,
    target_name: String,
    every_session: bool,
    bus: InMemoryEventBus<AgentBusEvent>,
    clock: Arc<dyn SystemClockPort>,
    /// Bus consumer for `ExtendScopeExpectation` (from the target launcher).
    consumer: Mutex<Option<JoinHandle<()>>>,
    cancel: CancellationToken,
}

impl ScopeTrackerPlugin {
    /// Assemble the plugin.
    #[must_use]
    pub fn new(
        state: SharedScopeState,
        target_name: String,
        every_session: bool,
        filter: Arc<DropFilter>,
        bus: InMemoryEventBus<AgentBusEvent>,
        clock: Arc<dyn SystemClockPort>,
    ) -> Self {
        Self {
            state,
            tracker: Arc::new(Mutex::new(ScopeTracker::default())),
            filter,
            target_name,
            every_session,
            bus,
            clock,
            consumer: Mutex::new(None),
            cancel: CancellationToken::new(),
        }
    }
}

#[async_trait]
impl PluginPort for ScopeTrackerPlugin {
    fn name(&self) -> &'static str {
        "scope-tracker"
    }

    async fn start(&self) -> Result<(), kernel::models::PluginError> {
        // Legacy policy: the target seeds the scope in session 0, or in every
        // session under `every_session`. Runs after session-manager.init opened
        // the session (registration order), so the count is already correct.
        let session_count = self.state.lock().sessions.len();
        if session_count == 1 || self.every_session {
            self.tracker.lock().expect(&self.target_name);
        }

        // The launcher resolves non-exe targets through interpreters (a `.js`
        // sample runs as `wscript.exe`) and tells us over the bus which image
        // to expect next.
        let mut receiver = self.bus.subscribe();
        let cancel = self.cancel.clone();
        let tracker = Arc::clone(&self.tracker);
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    event = receiver.recv() => match event {
                        Ok(AgentBusEvent::ExtendScopeExpectation { name }) => {
                            tracker.lock().expect(&name);
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                            tracing::warn!(lost = count, "scope-tracker bus lag");
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
impl MiddlewarePluginPort<SandboxEvent, crate::app::builder::AgentServices> for ScopeTrackerPlugin {
    async fn pre(
        &self,
        event: &mut SandboxEvent,
        _services: &crate::app::builder::AgentServices,
    ) -> Next {
        match event {
            SandboxEvent::Source(SourceEvent::ProcessStarted(data)) => {
                let now = self.clock.now_ms();
                let entered = {
                    let mut state = self.state.lock();
                    self.tracker.lock().process_entered(&mut state, data, now)
                };
                if entered {
                    if data.name.eq_ignore_ascii_case(&self.target_name) {
                        self.bus.publish(AgentBusEvent::TargetLaunched { name: data.name.clone() });
                    }
                    self.bus.publish(AgentBusEvent::ProcessEnteredScope {
                        pid: data.pid,
                        name: data.name.clone(),
                    });
                }
            }
            SandboxEvent::Source(SourceEvent::ProcessStopped(data)) => {
                let now = self.clock.now_ms();
                let was_scoped = {
                    let mut state = self.state.lock();
                    self.tracker.lock().process_exited(&mut state, data, now)
                };
                let dead = ScopeTracker::scope_dead(&self.state.lock());
                if was_scoped {
                    self.bus.publish(AgentBusEvent::ProcessExitedScope {
                        pid: data.pid,
                        name: data.name.clone(),
                    });
                    if dead {
                        self.bus.publish(AgentBusEvent::ScopeDied);
                    }
                }
            }
            SandboxEvent::Source(SourceEvent::FileWritten(data)) => {
                let mut state = self.state.lock();
                let observed = self.tracker.lock().drop_observed(&mut state, data, &self.filter);
                drop(state);
                if let Some(path) = observed {
                    self.bus.publish(AgentBusEvent::DropObserved { path, pid: Some(data.pid) });
                }
            }
            SandboxEvent::Source(
                SourceEvent::FileClosed(data) | SourceEvent::FileCleanedUp(data),
            ) => {
                let state = self.state.lock();
                let closed = self.tracker.lock().drop_closed(&state, data);
                drop(state);
                if let Some(path) = closed {
                    self.bus.publish(AgentBusEvent::DropClosed { path });
                }
            }
            _ => {}
        }
        Next::Continue
    }
}
