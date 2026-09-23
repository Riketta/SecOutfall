//! `event-reporter` — forwards pipeline events to the wire (verbosity-gated) and
//! translates derived bus events into wire events.
//!
//! Verbosity contract (legacy `elog_verbosity`): `None` silences source
//! telemetry; `Partial` is reserved for scope-relevant-only forwarding; `Full`
//! forwards everything. Derived lifecycle/drop events are always published —
//! they ARE the product.

use std::sync::{
    Arc,
    atomic::AtomicU64,
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
    config::EventVerbosity,
    events::EventType,
    nats::Envelope,
    payload::{
        DropClosedData,
        DropObservedData,
        Payload,
        ScopeDiedData,
    },
};
use tokio::{
    sync::broadcast,
    task::JoinHandle,
};
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
    ports::{
        broker::{
            BrokerPort,
            Channel,
        },
        clock::SystemClockPort,
    },
};

/// Reporter plugin.
pub struct EventReporterPlugin {
    state: SharedScopeState,
    broker: Arc<dyn BrokerPort>,
    clock: Arc<dyn SystemClockPort>,
    verbosity: EventVerbosity,
    bus: InMemoryEventBus<AgentBusEvent>,
    seq: Arc<AtomicU64>,
    consumer: Mutex<Option<JoinHandle<()>>>,
    cancel: CancellationToken,
}

impl EventReporterPlugin {
    /// Assemble the plugin.
    #[must_use]
    pub fn new(
        state: SharedScopeState,
        broker: Arc<dyn BrokerPort>,
        clock: Arc<dyn SystemClockPort>,
        verbosity: EventVerbosity,
        bus: InMemoryEventBus<AgentBusEvent>,
        seq: Arc<AtomicU64>,
    ) -> Self {
        Self {
            state,
            broker,
            clock,
            verbosity,
            bus,
            seq,
            consumer: Mutex::new(None),
            cancel: CancellationToken::new(),
        }
    }

    async fn publish(&self, envelope: Envelope<Payload>) {
        publish_envelope(&self.broker, envelope).await;
    }
}

/// Monotonic per-connection sequence number (Controller-side loss detection).
fn next_seq(seq: &AtomicU64) -> u64 {
    crate::plugins::wire::next_seq(seq)
}

/// (`study_id`, current session id) snapshot.
fn identity(state: &SharedScopeState) -> (uuid::Uuid, u32) {
    let guard = state.lock();
    let session_id = guard.current_session().map_or(0, |session| session.id);
    (guard.study_id, session_id)
}

async fn publish_envelope(broker: &Arc<dyn BrokerPort>, envelope: Envelope<Payload>) {
    if let Err(error) = broker.publish(Channel::Event, &envelope).await {
        tracing::error!(%error, event = %envelope.event_type, "event publish failed");
    }
}

/// Translate one derived bus event into its wire event (task-side entry).
async fn publish_bus_event(
    state: &SharedScopeState,
    broker: &Arc<dyn BrokerPort>,
    clock: &Arc<dyn SystemClockPort>,
    seq: &AtomicU64,
    event: AgentBusEvent,
) {
    let (study_id, session_id) = identity(state);
    let now = clock.now_ms();
    let envelope = match event {
        // `target.launched` is reported by the launcher itself (it owns the
        // pid/args/mechanism facts); score raises feed the finalizer.
        AgentBusEvent::TargetLaunched { .. }
        | AgentBusEvent::ExtendScopeExpectation { .. }
        | AgentBusEvent::SessionScoreRaised { .. }
        | AgentBusEvent::ProcessEnteredScope { .. }
        | AgentBusEvent::ProcessExitedScope { .. } => return,
        AgentBusEvent::DropObserved { path, pid } => crate::plugins::wire::envelope_raw(
            now,
            next_seq(seq),
            study_id,
            session_id,
            EventType::DropObserved,
            Payload::DropObserved(DropObservedData { path, pid }),
        ),
        AgentBusEvent::DropClosed { path } => crate::plugins::wire::envelope_raw(
            now,
            next_seq(seq),
            study_id,
            session_id,
            EventType::DropClosed,
            Payload::DropClosed(DropClosedData { path }),
        ),
        AgentBusEvent::ScopeDied => crate::plugins::wire::envelope_raw(
            now,
            next_seq(seq),
            study_id,
            session_id,
            EventType::ScopeDied,
            Payload::ScopeDied(ScopeDiedData {}),
        ),
        // Scope membership events are bus-internal (scoring/statistics fodder);
        // the raw process.started/stopped already hit the wire from `pre`.
    };
    publish_envelope(broker, envelope).await;
}

/// Single-owner bus consumer task (doctrine: no shared mutable state).
async fn consume_bus_events(
    mut receiver: broadcast::Receiver<AgentBusEvent>,
    cancel: CancellationToken,
    state: SharedScopeState,
    broker: Arc<dyn BrokerPort>,
    clock: Arc<dyn SystemClockPort>,
    seq: Arc<AtomicU64>,
) {
    loop {
        tokio::select! {
            // Biased: shutdown deterministically wins over pending events.
            biased;
            () = cancel.cancelled() => break,
            event = receiver.recv() => match event {
                Ok(bus_event) => {
                    publish_bus_event(&state, &broker, &clock, &seq, bus_event).await;
                }
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    // Overflow policy: count the loss, keep going (never OOM).
                    tracing::warn!(lost = count, "event-reporter bus lag");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }
}

#[async_trait]
impl PluginPort for EventReporterPlugin {
    fn name(&self) -> &'static str {
        "event-reporter"
    }

    async fn start(&self) -> Result<(), kernel::models::PluginError> {
        let receiver = self.bus.subscribe();
        let handle = tokio::spawn(consume_bus_events(
            receiver,
            self.cancel.clone(),
            Arc::clone(&self.state),
            Arc::clone(&self.broker),
            Arc::clone(&self.clock),
            Arc::clone(&self.seq),
        ));
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
impl MiddlewarePluginPort<SandboxEvent, AgentServices> for EventReporterPlugin {
    async fn pre(&self, event: &mut SandboxEvent, _services: &AgentServices) -> Next {
        if let SandboxEvent::Source(source) = event {
            if self.verbosity != EventVerbosity::Full {
                return Next::Continue;
            }
            let (study_id, session_id) = identity(&self.state);
            let envelope = crate::plugins::wire::envelope_from_source(
                self.clock.now_ms(),
                next_seq(&self.seq),
                study_id,
                session_id,
                source,
            );
            self.publish(envelope).await;
        }
        Next::Continue
    }
}
