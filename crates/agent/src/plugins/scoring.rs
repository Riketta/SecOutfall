//! `scoring` — derives the session score from derived bus events and reports
//! raises back onto the bus for the finalizer.
//!
//! Legacy parity: the session score is the **maximum** over signals, reported
//! once at finalize (`ScoringManager.MaxSessionScore`). Legacy fix: the
//! weights come from `[scoring]` config instead of being hardcoded and the
//! config ignored (bug #12).

use std::sync::{
    Arc,
    atomic::{
        AtomicU32,
        Ordering,
    },
};

use async_trait::async_trait;
use kernel::{
    app::plugin_ports::{
        event_bus_port::EventBusPort,
        plugin_port::PluginPort,
    },
    bus::InMemoryEventBus,
};
use parking_lot::Mutex;
use protocol::config::ScoringConfig;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{
    app::event::AgentBusEvent,
    domain::score::{
        ScoreSignal,
        ScoreWeights,
        score_signal,
    },
};

/// Scoring plugin (bus-only consumer and publisher).
pub struct ScoringPlugin {
    weights: ScoreWeights,
    bus: InMemoryEventBus<AgentBusEvent>,
    /// Session maximum so far.
    max_score: Arc<AtomicU32>,
    consumer: Mutex<Option<JoinHandle<()>>>,
    cancel: CancellationToken,
}

impl ScoringPlugin {
    /// Assemble the plugin over the configured weights.
    #[must_use]
    pub fn new(config: &ScoringConfig, bus: InMemoryEventBus<AgentBusEvent>) -> Self {
        Self {
            weights: ScoreWeights {
                cli_started: config.cli_started,
                drop_observed: config.drop_observed,
            },
            bus,
            max_score: Arc::new(AtomicU32::new(0)),
            consumer: Mutex::new(None),
            cancel: CancellationToken::new(),
        }
    }

    /// Session maximum score so far (diagnostics/tests).
    #[must_use]
    pub fn max_score(&self) -> u32 {
        self.max_score.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl PluginPort for ScoringPlugin {
    fn name(&self) -> &'static str {
        "scoring"
    }

    async fn start(&self) -> Result<(), kernel::models::PluginError> {
        let mut receiver = self.bus.subscribe();
        let cancel = self.cancel.clone();
        let bus = self.bus.clone();
        let weights = self.weights;
        let max_score = Arc::clone(&self.max_score);
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    event = receiver.recv() => match event {
                        Ok(bus_event) => {
                            let candidate = match bus_event {
                                AgentBusEvent::ProcessEnteredScope { name, .. } => {
                                    score_signal(&weights, &ScoreSignal::CliInterpreter(&name))
                                }
                                AgentBusEvent::DropObserved { .. } => {
                                    score_signal(&weights, &ScoreSignal::DropObserved)
                                }
                                _ => None,
                            };
                            if let Some(candidate) = candidate {
                                let previous = max_score.fetch_max(candidate, Ordering::SeqCst);
                                if candidate > previous {
                                    bus.publish(AgentBusEvent::SessionScoreRaised {
                                        score: candidate,
                                    });
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                            tracing::warn!(lost = count, "scoring bus lag");
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
