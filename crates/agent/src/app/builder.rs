//! Composition: assembles the agent kernel from config + injected adapters.
//!
//! The binary is a thin composition root; everything wireable is a parameter
//! here, so tests and the simulator inject fakes while the real bin injects
//! production adapters.

use std::sync::Arc;

use kernel::{
    app::{
        plugin_ports::{
            middleware_plugin_port::MiddlewarePluginPort,
            plugin_port::PluginPort,
        },
        services::kernel_service::KernelService,
    },
    bus::InMemoryEventBus,
};
use protocol::config::AgentConfig;

use crate::{
    app::event::{
        AgentBusEvent,
        SandboxEvent,
    },
    domain::{
        drop_filter::DropFilter,
        scope::SharedScopeState,
    },
    plugins::{
        drops_collector::{
            DropsCollectorDeps,
            DropsCollectorPlugin,
        },
        event_reporter::EventReporterPlugin,
        scope_tracker::ScopeTrackerPlugin,
        scoring::ScoringPlugin,
        screenshot_intake::{
            ScreenshotIntakeDeps,
            ScreenshotIntakePlugin,
        },
        session_manager::{
            SessionManagerDeps,
            SessionManagerPlugin,
        },
        statistics::{
            SessionStatistics,
            StatisticsPlugin,
        },
        target_launcher::{
            TargetLauncherDeps,
            TargetLauncherPlugin,
        },
        user_actor_supervisor::{
            UserActorSupervisorDeps,
            UserActorSupervisorPlugin,
        },
    },
    ports::{
        broker::BrokerPort,
        clock::{
            ClockShiftPort,
            SystemClockPort,
        },
        process_killer::ProcessKillerPort,
        process_launcher::ProcessLauncherPort,
        scope_repository::ScopeRepository,
        shell_association::ShellAssociationPort,
        uploader::FileUploadPort,
    },
};

/// Services bundle injected into every plugin hook.
pub struct AgentServices {
    /// Agent configuration.
    pub config: Arc<AgentConfig>,
    /// Durable scope storage.
    pub scope_repo: Arc<dyn ScopeRepository>,
    /// Wire output.
    pub broker: Arc<dyn BrokerPort>,
    /// Time source.
    pub clock: Arc<dyn SystemClockPort>,
    /// Shared per-boot wire sequence counter.
    pub seq: Arc<std::sync::atomic::AtomicU64>,
}

/// Fully assembled agent kernel type.
pub type AgentKernel =
    KernelService<SandboxEvent, AgentServices, InMemoryEventBus<AgentBusEvent>, AgentBusEvent>;

/// Everything the assembler needs; fakes for tests, reals for production.
pub struct AgentDeps {
    /// Parsed (and validated) configuration.
    pub config: Arc<AgentConfig>,
    /// Shared scope state — loaded from the repository before assembly.
    pub scope_state: SharedScopeState,
    /// Durable scope storage.
    pub scope_repo: Arc<dyn ScopeRepository>,
    /// Wire output.
    pub broker: Arc<dyn BrokerPort>,
    /// Time source.
    pub clock: Arc<dyn SystemClockPort>,
    /// Controller upload transport (drops, screenshots).
    pub uploader: Arc<dyn FileUploadPort>,
    /// Interactive-session launcher (mechanism per config).
    pub launcher: Arc<dyn ProcessLauncherPort>,
    /// Shell-association resolver for non-exe targets.
    pub shell: Arc<dyn ShellAssociationPort>,
    /// Finalize-time process cleanup.
    pub killer: Arc<dyn ProcessKillerPort>,
    /// Clock manipulation (fake timestamps, finalize offsets).
    pub shifter: Arc<dyn ClockShiftPort>,
    /// Shared session counters (ops/tests read them).
    pub statistics: Arc<SessionStatistics>,
    /// Per-boot user-actor nonce; shared with the IPC server adapter.
    pub user_actor_nonce: String,
    /// THE per-boot wire sequence counter — one per boot, shared by every
    /// publisher in the process (plugins, scheduler, IPC server). Gaps mean
    /// lost messages; duplicates mean publisher restarts. Never create a
    /// second counter for the same boot.
    pub seq: Arc<std::sync::atomic::AtomicU64>,
    /// Expected user-actor client pid gate (0 = unknown/ungated). The supervisor
    /// stores the pid it launched; the IPC server compares it against
    /// `GetNamedPipeClientProcessId` at `HELLO` (anti-impostor).
    pub user_actor_pid_gate: Arc<std::sync::atomic::AtomicU32>,
    /// Set to `true` only when a finalize has FULLY completed (persist and
    /// final publishes included) — hosts wait on this instead of
    /// `ended_at_ms`, which is stamped at the START of finalize.
    pub finalize_done: Arc<std::sync::atomic::AtomicBool>,
    /// Derived-event bus (also handed to tests/simulator for extra assertions).
    pub bus: InMemoryEventBus<AgentBusEvent>,
}

/// Load scope state from a repository, assigning a fresh study id on first boot
/// (nil id == "no study yet").
///
/// # Errors
/// Propagates repository load failures.
pub async fn load_scope_state(
    repo: &dyn ScopeRepository,
) -> Result<SharedScopeState, crate::ports::scope_repository::ScopeRepositoryError> {
    let mut state = repo.load().await?;
    if state.study_id.is_nil() {
        state.study_id = uuid::Uuid::new_v4();
    }
    Ok(Arc::new(parking_lot::Mutex::new(state)))
}

/// Target image name derived from the configured path (last path component).
#[must_use]
pub fn target_image_name(config: &AgentConfig) -> String {
    std::path::Path::new(&config.target.path).file_name().map_or_else(
        || config.target.path.to_lowercase(),
        |name| name.to_string_lossy().to_lowercase(),
    )
}

/// Assemble the kernel. Registration order matters: the session manager opens
/// the session in `init` before the tracker seeds it in `start`.
#[allow(clippy::too_many_lines)] // linear wiring, kept on purpose
#[must_use]
pub fn assemble(deps: AgentDeps) -> AgentKernel {
    let seq = Arc::clone(&deps.seq);
    let services = AgentServices {
        config: Arc::clone(&deps.config),
        scope_repo: Arc::clone(&deps.scope_repo),
        broker: Arc::clone(&deps.broker),
        clock: Arc::clone(&deps.clock),
        seq: Arc::clone(&seq),
    };

    let session_manager = Arc::new(SessionManagerPlugin::new(SessionManagerDeps {
        state: Arc::clone(&deps.scope_state),
        repo: Arc::clone(&deps.scope_repo),
        broker: Arc::clone(&deps.broker),
        clock: Arc::clone(&deps.clock),
        shifter: Arc::clone(&deps.shifter),
        killer: Arc::clone(&deps.killer),
        processes_to_terminate: Arc::new(deps.config.study.processes_to_terminate.clone()),
        uptimes: Arc::new(deps.config.study.uptimes.clone()),
        autoshutdown: deps.config.study.autoshutdown,
        time: deps.config.time,
        skip_time_manipulation: deps.config.debug.skip_time_manipulation,
        skip_reboot_and_shutdown: deps.config.debug.skip_reboot_and_shutdown,
        finalize_done: Arc::clone(&deps.finalize_done),
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        bus: deps.bus.clone(),
        seq: Arc::clone(&seq),
    }));

    let tracker = Arc::new(ScopeTrackerPlugin::new(
        Arc::clone(&deps.scope_state),
        target_image_name(&deps.config),
        deps.config.target.every_session,
        Arc::new(DropFilter::new(&deps.config.drops.extensions)),
        deps.bus.clone(),
        Arc::clone(&deps.clock),
    ));

    let reporter = Arc::new(EventReporterPlugin::new(
        Arc::clone(&deps.scope_state),
        Arc::clone(&deps.broker),
        Arc::clone(&deps.clock),
        deps.config.broker.verbosity,
        deps.bus.clone(),
        Arc::clone(&seq),
    ));

    let drops_collector = Arc::new(DropsCollectorPlugin::new(DropsCollectorDeps {
        state: Arc::clone(&deps.scope_state),
        config: Arc::new(deps.config.drops.clone()),
        uploader: Arc::clone(&deps.uploader),
        broker: Arc::clone(&deps.broker),
        clock: Arc::clone(&deps.clock),
        seq: Arc::clone(&seq),
        bus: deps.bus.clone(),
    }));

    let screenshot_intake = Arc::new(ScreenshotIntakePlugin::new(ScreenshotIntakeDeps {
        state: Arc::clone(&deps.scope_state),
        config: Arc::new(deps.config.screenshots.clone()),
        capture_enabled: deps.config.user_actor.screencapture,
        uploader: Arc::clone(&deps.uploader),
        broker: Arc::clone(&deps.broker),
        clock: Arc::clone(&deps.clock),
        seq: Arc::clone(&seq),
        bus: deps.bus.clone(),
    }));

    let target_launcher = Arc::new(TargetLauncherPlugin::new(TargetLauncherDeps {
        state: Arc::clone(&deps.scope_state),
        config: Arc::clone(&deps.config),
        launcher: Arc::clone(&deps.launcher),
        shell: Arc::clone(&deps.shell),
        broker: Arc::clone(&deps.broker),
        clock: Arc::clone(&deps.clock),
        seq: Arc::clone(&seq),
        bus: deps.bus.clone(),
    }));

    let scoring = Arc::new(ScoringPlugin::new(&deps.config.scoring, deps.bus.clone()));
    let statistics = Arc::new(StatisticsPlugin::new(
        Arc::clone(&deps.scope_state),
        deps.bus.clone(),
        Arc::clone(&deps.statistics),
    ));

    let supervisor = Arc::new(UserActorSupervisorPlugin::new(UserActorSupervisorDeps {
        config: Arc::clone(&deps.config),
        launcher: Arc::clone(&deps.launcher),
        nonce: deps.user_actor_nonce,
        pid_gate: Arc::clone(&deps.user_actor_pid_gate),
    }));

    let plugins: Vec<Arc<dyn PluginPort>> = vec![
        session_manager.clone(),
        tracker.clone(),
        reporter.clone(),
        drops_collector.clone(),
        screenshot_intake.clone(),
        target_launcher.clone(),
        supervisor.clone(),
        scoring.clone(),
        statistics.clone(),
    ];
    let middleware: Vec<Arc<dyn MiddlewarePluginPort<SandboxEvent, AgentServices>>> = vec![
        session_manager,
        tracker,
        reporter,
        screenshot_intake,
        target_launcher,
        supervisor,
        statistics,
    ];

    KernelService::new(plugins, middleware, deps.bus, services)
}
