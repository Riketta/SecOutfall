//! `target-launcher` — detonates the sample in the interactive session.
//!
//! Trigger: the marker process from config (`platform.non_s0_process`,
//! legacy `explorer`) starting under ETW is the interactive-session signal;
//! the first sighting launches the target — in session 0, or in every
//! session under `target.every_session`.
//!
//! Non-executable targets resolve through [`ShellAssociationPort`] (registry
//! in production); the resolved interpreter's image name is published to the
//! bus so the `scope-tracker` expects **it** — a `.js` target never appears
//! as a process named `evil.js`, it appears as `wscript.exe`.
//!
//! Legacy bugs fixed here: the association command was split on spaces
//! (crashing on single-token commands — bug #7); launch failures now log a
//! typed error instead of crashing.

use std::{
    ffi::OsStr,
    sync::{
        Arc,
        atomic::{
            AtomicBool,
            AtomicU64,
            Ordering,
        },
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

/// Constructor dependencies.
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
}

impl TargetLauncherPlugin {
    /// Assemble the plugin.
    #[must_use]
    pub fn new(deps: TargetLauncherDeps) -> Self {
        Self { deps, attempted: AtomicBool::new(false) }
    }

    /// Should this boot detonate the sample?
    fn should_launch(&self) -> bool {
        let session_count = self.deps.state.lock().sessions.len();
        session_count == 1 || self.deps.config.target.every_session
    }

    /// Resolve the launch spec: `.exe` targets launch directly; anything else
    /// goes through the shell-association resolver.
    async fn resolve_spec(&self) -> Result<LaunchSpec, String> {
        let target = &self.deps.config.target.path;
        let config_args = self.deps.config.target.args.clone();
        let is_exe = std::path::Path::new(target)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"));

        if is_exe {
            return Ok(LaunchSpec { path: target.clone(), args: config_args, working_dir: None });
        }

        let command = self
            .deps
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

    /// The whole detonation flow (resolver → launcher → wire → bus).
    async fn launch_target(&self) {
        let spec = match self.resolve_spec().await {
            Ok(spec) => spec,
            Err(detail) => {
                tracing::error!(target = %self.deps.config.target.path, "{detail}");
                return;
            }
        };

        match self.deps.launcher.launch(&spec).await {
            Ok(outcome) => {
                tracing::info!(
                    path = %spec.path,
                    pid = ?outcome.pid,
                    "target launched"
                );
                // The interpreter/executable image joins the scope expectation
                // (bus-only plugin communication — never a direct call).
                let image = std::path::Path::new(&spec.path)
                    .file_name()
                    .and_then(OsStr::to_str)
                    .map_or_else(|| spec.path.clone(), ToString::to_string);
                self.deps.bus.publish(AgentBusEvent::ExtendScopeExpectation { name: image });

                let (study_id, session_id) = {
                    let state = self.deps.state.lock();
                    let session_id = state.current_session().map_or(0, |session| session.id);
                    (state.study_id, session_id)
                };
                let launcher = match self.deps.config.platform.launch_mechanism {
                    protocol::config::LaunchMechanism::Token => Launcher::Token,
                    protocol::config::LaunchMechanism::SchedTask => Launcher::SchedTask,
                };
                let envelope = crate::plugins::wire::envelope_raw(
                    self.deps.clock.now_ms(),
                    crate::plugins::wire::next_seq(&self.deps.seq),
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
                if let Err(error) = self.deps.broker.publish(Channel::Event, &envelope).await {
                    tracing::error!(%error, "target.launched publish failed");
                }
            }
            Err(error) => {
                // Bug #7: a failed launch is a typed error, not a crash.
                tracing::error!(
                    target = %self.deps.config.target.path,
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
}

#[async_trait]
impl MiddlewarePluginPort<SandboxEvent, AgentServices> for TargetLauncherPlugin {
    async fn pre(&self, event: &mut SandboxEvent, _services: &AgentServices) -> Next {
        if let SandboxEvent::Source(crate::app::event::SourceEvent::ProcessStarted(data)) = event {
            if is_marker_process(&self.deps.config.platform.non_s0_process, &data.name)
                && !self.attempted.swap(true, Ordering::SeqCst)
                && self.should_launch()
            {
                self.launch_target().await;
            }
        }
        Next::Continue
    }
}
