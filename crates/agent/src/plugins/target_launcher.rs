//! `target-launcher` — detonates the sample in the interactive session.
//!
//! Trigger: the marker process from config (`platform.non_s0_process`,
//! legacy `explorer`) starting under ETW is the interactive-session signal;
//! the first sighting launches the target — in session 0, or in every
//! session under `target.every_session`.
//!
//! The launch itself runs OFF the pipeline on a bounded job queue (a
//! `SchedTask` launch may legitimately take seconds; the serial pipeline
//! must keep draining ETW instead of stalling right at detonation). The
//! queue's overflow/shutdown policy counts abandoned jobs; a refused launch
//! job is logged as an error because a lost detonation voids the session.
//!
//! Non-executable targets resolve through [`ShellAssociationPort`] (registry
//! in production); the resolved interpreter's image name is published to the
//! bus so the `scope-tracker` expects **it** — a `.js` target never appears
//! as a process named `evil.js`, it appears as `wscript.exe`. The
//! expectation is published BEFORE the process is created, and the tracker
//! applies expectations synchronously on the pipeline path, so the
//! interpreter's first `process.started` always finds the expectation in
//! place (race-free by ordering).
//!
//! Legacy bugs fixed here: the association command was split on spaces
//! (crashing on single-token commands — bug #7); launch failures now log a
//! typed error instead of crashing.

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
    config::AgentConfig,
    events::EventType,
    payload::{
        Launcher,
        Payload,
        TargetLaunchedData,
    },
};

use crate::{
    app::{
        builder::AgentServices,
        event::{
            AgentBusEvent,
            SandboxEvent,
        },
        worker::JobQueue,
    },
    domain::{
        command_line::split_command_line,
        marker::is_marker_process,
        scope::SharedScopeState,
    },
    ports::{
        broker::{
            BrokerPort,
            Channel,
        },
        clock::SystemClockPort,
        process_launcher::{
            LaunchSpec,
            ProcessLauncherPort,
        },
        shell_association::ShellAssociationPort,
    },
};

/// Launch-queue capacity. One detonation per boot in practice; bounded per
/// doctrine (a full queue refuses + counts instead of buffering unbounded).
const LAUNCH_QUEUE_CAPACITY: usize = 8;

/// Constructor dependencies.
#[derive(Clone)]
pub struct TargetLauncherDeps {
    /// Shared scope state (study/session identity on the wire).
    pub state: SharedScopeState,
    /// Full agent config (target, platform).
    pub config: Arc<AgentConfig>,
    /// Interactive-session launcher (mechanism per `platform.launch_mechanism`).
    pub launcher: Arc<dyn ProcessLauncherPort>,
    /// Shell-association resolver for non-exe targets.
    pub shell: Arc<dyn ShellAssociationPort>,
    /// Wire output.
    pub broker: Arc<dyn BrokerPort>,
    /// Time source.
    pub clock: Arc<dyn SystemClockPort>,
    /// Shared per-boot wire sequence counter.
    pub seq: Arc<AtomicU64>,
    /// Derived-event bus.
    pub bus: InMemoryEventBus<AgentBusEvent>,
}

/// Target detonation plugin (pipeline middleware).
pub struct TargetLauncherPlugin {
    deps: TargetLauncherDeps,
    /// One launch attempt per boot (one session per boot).
    attempted: AtomicBool,
    /// Off-pipeline detonation queue (spawned in `start`, stopped in `stop`).
    queue: Mutex<Option<JobQueue<()>>>,
}

impl TargetLauncherPlugin {
    /// Assemble the plugin.
    #[must_use]
    pub fn new(deps: TargetLauncherDeps) -> Self {
        Self { deps, attempted: AtomicBool::new(false), queue: Mutex::new(None) }
    }

    /// Should this boot detonate the sample?
    fn should_launch(&self) -> bool {
        let session_count = self.deps.state.lock().sessions.len();
        session_count == 1 || self.deps.config.target.every_session
    }

    /// Resolve the launch spec: `.exe` targets launch directly; anything else
    /// goes through the shell-association resolver.
    async fn resolve_spec(deps: &TargetLauncherDeps) -> Result<LaunchSpec, String> {
        let target = &deps.config.target.path;
        let config_args = deps.config.target.args.clone();
        let is_exe = std::path::Path::new(target)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"));

        if is_exe {
            return Ok(LaunchSpec { path: target.clone(), args: config_args, working_dir: None });
        }

        let command = deps
            .shell
            .resolve_open_command(target)
            .await
            .map_err(|error| format!("association resolution failed: {error}"))?;
        let mut parts = split_command_line(&command);
        let Some(program) = parts.first().cloned() else {
            return Err(format!("association command for `{target}` resolved to nothing"));
        };
        let mut launch_args: Vec<String> = parts.drain(1..).collect();
        launch_args.extend(config_args);
        Ok(LaunchSpec { path: program, args: launch_args, working_dir: None })
    }

    /// The whole detonation flow (resolver → expectation → launcher → wire).
    /// Runs on the launch queue, off the pipeline.
    ///
    /// Ordering invariant: the resolved image's scope expectation is
    /// published BEFORE the process is created, and the scope tracker
    /// applies expectations synchronously on the pipeline path — so the
    /// interpreter's first `process.started` always finds the expectation in
    /// place.
    async fn launch_flow(deps: TargetLauncherDeps) {
        let spec = match Self::resolve_spec(&deps).await {
            Ok(spec) => spec,
            Err(detail) => {
                tracing::error!(target = %deps.config.target.path, "{detail}");
                return;
            }
        };

        // The interpreter/executable image joins the scope expectation
        // (bus-only plugin communication — never a direct call). Published
        // before CreateProcess; published even if the launch then fails, an
        // expectation for a name that never appears is inert. Textual split:
        // see `domain::image_name` — must not depend on the host OS.
        let image = crate::domain::image_name::image_name(&spec.path).to_owned();
        deps.bus.publish(AgentBusEvent::ExtendScopeExpectation { name: image });

        match deps.launcher.launch(&spec).await {
            Ok(outcome) => {
                tracing::info!(path = %spec.path, pid = ?outcome.pid, "target launched");

                let (study_id, session_id) = {
                    let state = deps.state.lock();
                    let session_id = state.current_session().map_or(0, |session| session.id);
                    (state.study_id, session_id)
                };
                let launcher = match deps.config.platform.launch_mechanism {
                    protocol::config::LaunchMechanism::Token => Launcher::Token,
                    protocol::config::LaunchMechanism::SchedTask => Launcher::SchedTask,
                };
                let envelope = crate::plugins::wire::envelope_raw(
                    deps.clock.now_ms(),
                    crate::plugins::wire::next_seq(&deps.seq),
                    study_id,
                    session_id,
                    EventType::TargetLaunched,
                    Payload::TargetLaunched(TargetLaunchedData {
                        pid: outcome.pid,
                        path: spec.path,
                        args: (!spec.args.is_empty()).then(|| spec.args.join(" ")),
                        launcher,
                    }),
                );
                if let Err(error) = deps.broker.publish(Channel::Event, &envelope).await {
                    tracing::error!(%error, "target.launched publish failed");
                }
            }
            Err(error) => {
                // Bug #7: a failed launch is a typed error, not a crash.
                tracing::error!(
                    target = %deps.config.target.path,
                    %error,
                    "target launch failed"
                );
            }
        }
    }
}

#[async_trait]
impl PluginPort for TargetLauncherPlugin {
    fn name(&self) -> &'static str {
        "target-launcher"
    }

    async fn start(&self) -> Result<(), kernel::models::PluginError> {
        let deps = self.deps.clone();
        let queue: JobQueue<()> = JobQueue::spawn(LAUNCH_QUEUE_CAPACITY, move |()| {
            let deps = deps.clone();
            async move { Self::launch_flow(deps).await }
        });
        *self.queue.lock() = Some(queue);
        Ok(())
    }

    async fn stop(&self) -> Result<(), kernel::models::PluginError> {
        // A detonation still queued at shutdown is abandoned (counted by the
        // queue) — the session is ending anyway. The take result is bound
        // first so the lock guard cannot cross the await.
        let queue = self.queue.lock().take();
        if let Some(queue) = queue {
            queue.stop().await;
        }
        Ok(())
    }
}

#[async_trait]
impl MiddlewarePluginPort<SandboxEvent, AgentServices> for TargetLauncherPlugin {
    async fn pre(&self, event: &mut SandboxEvent, _services: &AgentServices) -> Next {
        if let SandboxEvent::Source(crate::app::event::SourceEvent::ProcessStarted(data)) = event
            && is_marker_process(&self.deps.config.platform.non_s0_process, &data.name)
            && !self.attempted.swap(true, Ordering::SeqCst)
            && self.should_launch()
        {
            // Submit, never await: the pipeline must keep draining while
            // the launch (potentially a 15 s SchedTask budget) runs.
            let accepted =
                self.queue.lock().as_ref().is_some_and(|queue| queue.handle().submit(()));
            if !accepted {
                // A lost detonation voids the session; surface it loudly.
                tracing::error!(
                    target = %self.deps.config.target.path,
                    "launch queue refused the detonation job — the launch is lost"
                );
            }
        }
        Next::Continue
    }
}
