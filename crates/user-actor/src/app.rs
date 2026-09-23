//! Composition: assembles the user-actor kernel from injected adapters.
//!
//! Mirrors the agent's `app::builder`: the binary is a thin composition root;
//! tests and dev harnesses inject fakes.

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

use crate::{
    domain::{
        ActorBusEvent,
        ActorEvent,
        ActorServices,
        SharedRuntime,
    },
    plugins::{
        activities::{
            ActivityEnv,
            ScriptedActivity,
            calc_script,
            explorer_script,
            notepad_script,
        },
        config_apply::ConfigApplyPlugin,
        focus_watch::FocusWatchPlugin,
        reactive::ReactivePlugin,
        scripted::{
            ScriptedRunnerDeps,
            ScriptedRunnerPlugin,
        },
    },
    ports::{
        AppLauncherPort,
        InputSynthesisPort,
        ScreenCapturePort,
        ScreenshotSinkPort,
    },
};

/// Fully assembled user-actor kernel type.
pub type ActorKernel =
    KernelService<ActorEvent, ActorServices, InMemoryEventBus<ActorBusEvent>, ActorBusEvent>;

/// Everything the assembler needs; fakes for tests, reals for production.
pub struct ActorDeps {
    /// Shared runtime state (filled by the config push).
    pub runtime: SharedRuntime,
    /// Derived-event bus (shared with the composition root for observers).
    pub bus: InMemoryEventBus<ActorBusEvent>,
    /// Desktop capture (JPEG out).
    pub capture: Arc<dyn ScreenCapturePort>,
    /// Screenshot transport to the agent.
    pub sink: Arc<dyn ScreenshotSinkPort>,
    /// Reactive input synthesis.
    pub input: Arc<dyn InputSynthesisPort>,
    /// Scripted-activity app launcher.
    pub launcher: Arc<dyn AppLauncherPort>,
}

/// Assemble the kernel. Registration order matters: the config must be
/// applied before the focus watcher consults it.
#[must_use]
pub fn assemble(deps: ActorDeps) -> ActorKernel {
    let services = ActorServices { runtime: Arc::clone(&deps.runtime) };

    let config_apply = Arc::new(ConfigApplyPlugin::new(deps.bus.clone()));
    let focus_watch = Arc::new(FocusWatchPlugin::new(deps.bus.clone(), deps.capture, deps.sink));
    let reactive =
        Arc::new(ReactivePlugin::new(deps.bus.clone(), deps.input.clone(), deps.runtime));

    // Scripted activities (notepad/calc/explorer), driven by the runner and
    // gated at runtime by the pushed `scripted` flag.
    let env = ActivityEnv { launcher: deps.launcher, input: deps.input };
    let activities: Vec<Arc<dyn crate::plugins::scripted::ActivityPort>> = vec![
        ScriptedActivity::new("notepad", notepad_script(), env.clone()),
        ScriptedActivity::new("calc", calc_script(), env.clone()),
        ScriptedActivity::new("explorer", explorer_script(), env),
    ];
    let scripted_runner = Arc::new(ScriptedRunnerPlugin::new(ScriptedRunnerDeps { activities }));

    let plugins: Vec<Arc<dyn PluginPort>> =
        vec![config_apply.clone(), focus_watch.clone(), reactive.clone(), scripted_runner.clone()];
    let middleware: Vec<Arc<dyn MiddlewarePluginPort<ActorEvent, ActorServices>>> =
        vec![config_apply, focus_watch, scripted_runner];

    KernelService::new(plugins, middleware, deps.bus, services)
}
