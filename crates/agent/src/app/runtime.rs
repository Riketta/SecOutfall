//! Shared session runtime for console and service hosts.
//!
//! Flow: `boot` → scheduler (deadline/keepalive) + optional ETW source →
//! forward stop-channel events into the pipeline → on `ServiceStop` (or a
//! finalized session) → `shutdown`. The hosts only differ in what feeds the
//! stop channel (Ctrl+C for console, SCM for service).

use std::sync::Arc;

use kernel::app::api_ports::EventInletPort;
use protocol::config::AgentConfig;
use tokio::sync::mpsc;

use crate::{
    adapters::scheduler::SchedulerAdapter,
    app::{
        builder::{
            AgentDeps,
            AgentKernel,
            assemble,
            load_scope_state,
        },
        event::SandboxEvent,
    },
    domain::scope::SharedScopeState,
    ports::{
        broker::BrokerPort,
        clock::SystemClockPort,
        event_source::EventSourcePort,
        process_launcher::ProcessLauncherPort,
        scope_repository::ScopeRepository,
        shell_association::ShellAssociationPort,
        uploader::FileUploadPort,
    },
};

/// Everything one agent boot needs.
pub struct SessionDeps {
    /// Parsed and validated configuration.
    pub config: Arc<AgentConfig>,
    /// Durable scope storage.
    pub scope_repo: Arc<dyn ScopeRepository>,
    /// Wire output (fake in dev, NATS in production).
    pub broker: Arc<dyn BrokerPort>,
    /// Time source.
    pub clock: Arc<dyn SystemClockPort>,
    /// Controller upload transport (drops, screenshots).
    pub uploader: Arc<dyn FileUploadPort>,
    /// Interactive-session launcher (mechanism per config).
    pub launcher: Arc<dyn ProcessLauncherPort>,
    /// Shell-association resolver for non-exe targets.
    pub shell: Arc<dyn ShellAssociationPort>,
}

/// A running session: the assembled kernel plus its driving handles.
pub struct RunningSession {
    kernel: Arc<AgentKernel>,
    state: SharedScopeState,
    scheduler: Arc<SchedulerAdapter>,
}

impl RunningSession {
    /// Boot the kernel, start the scheduler and return the session plus the
    /// stop-channel every host feeds (SCM events, Ctrl+C...).
    ///
    /// # Errors
    /// Kernel boot failures (a plugin lifecycle hook failed).
    pub async fn start(
        deps: SessionDeps,
    ) -> Result<(Self, mpsc::Sender<SandboxEvent>, mpsc::Receiver<SandboxEvent>), anyhow::Error>
    {
        let seq = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let state = load_scope_state(deps.scope_repo.as_ref()).await?;
        let bus = kernel::bus::InMemoryEventBus::new(4096);
        let kernel = Arc::new(assemble(AgentDeps {
            config: Arc::clone(&deps.config),
            scope_state: Arc::clone(&state),
            scope_repo: Arc::clone(&deps.scope_repo),
            broker: Arc::clone(&deps.broker),
            clock: Arc::clone(&deps.clock),
            uploader: Arc::clone(&deps.uploader),
            launcher: Arc::clone(&deps.launcher),
            shell: Arc::clone(&deps.shell),
            bus,
        }));
        kernel.boot().await?;

        let inlet: Arc<dyn EventInletPort<SandboxEvent>> = Arc::clone(&kernel) as _;
        let scheduler = SchedulerAdapter::new(
            Arc::clone(&state),
            Arc::clone(&deps.clock),
            Arc::clone(&deps.broker),
            Arc::clone(&seq),
        );
        let scheduler = Arc::new(scheduler);
        let scheduler_for_task = scheduler.clone();
        tokio::spawn(async move {
            let _ = scheduler_for_task.run(inlet).await;
        });

        let (stop_tx, stop_rx) = mpsc::channel::<SandboxEvent>(8);
        Ok((Self { kernel, state, scheduler }, stop_tx, stop_rx))
    }

    /// The pipeline inlet for additional driving adapters (ETW, probes...).
    #[must_use]
    pub fn inlet(&self) -> Arc<dyn EventInletPort<SandboxEvent>> {
        Arc::clone(&self.kernel) as Arc<dyn EventInletPort<SandboxEvent>>
    }

    /// The shared scope state (hosts observe finalization through it).
    #[must_use]
    pub fn scope_state(&self) -> &SharedScopeState {
        &self.state
    }

    /// Has the current session been finalized?
    #[must_use]
    pub fn is_finalized(&self) -> bool {
        self.state.lock().current_session().is_some_and(|session| session.ended_at_ms.is_some())
    }

    /// Run until the stop channel delivers `ServiceStop` or the session
    /// finalizes itself (deadline/autoshutdown), then shut the kernel down.
    ///
    /// # Errors
    /// Kernel shutdown failures.
    pub async fn run_until_stop(
        self,
        mut stop: mpsc::Receiver<SandboxEvent>,
    ) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                event = stop.recv() => match event {
                    Some(event) => {
                        let is_stop = matches!(event, SandboxEvent::ServiceStop);
                        self.kernel.accept(event).await;
                        if is_stop {
                            break;
                        }
                    }
                    None => break,
                },
                () = tokio::time::sleep(std::time::Duration::from_millis(250)) => {
                    // Deadline/autoshutdown finalizations happen inside the
                    // pipeline (scheduler inlet, bus consumers); the host just
                    // observes and exits afterwards.
                    if self.is_finalized() {
                        break;
                    }
                }
            }
        }
        self.scheduler.stop();
        self.kernel.shutdown().await;
        Ok(())
    }
}
