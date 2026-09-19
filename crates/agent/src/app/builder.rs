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
        event_reporter::EventReporterPlugin,
        scope_tracker::ScopeTrackerPlugin,
        session_manager::{
            SessionManagerDeps,
            SessionManagerPlugin,
        },
    },
    ports::{
        broker::BrokerPort,
        clock::SystemClockPort,
        scope_repository::ScopeRepository,
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
#[must_use]
pub fn assemble(deps: AgentDeps) -> AgentKernel {
    let seq = Arc::new(std::sync::atomic::AtomicU64::new(0));
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
        uptimes: Arc::new(deps.config.study.uptimes.clone()),
        autoshutdown: deps.config.study.autoshutdown,
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

    let plugins: Vec<Arc<dyn PluginPort>> =
        vec![session_manager.clone(), tracker.clone(), reporter.clone()];
    let middleware: Vec<Arc<dyn MiddlewarePluginPort<SandboxEvent, AgentServices>>> =
        vec![session_manager, tracker, reporter];

    KernelService::new(plugins, middleware, deps.bus, services)
}
