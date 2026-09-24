//! Scripted activities framework: legacy `IActivity` intent
//! (Start/Stop/Pause/Resume) over data-driven step scripts.
//!
//! Each activity is a component implementing [`ActivityPort`], owned by the
//! [`ScriptedRunnerPlugin`] (kernel plugins never call each other, so the
//! runner is their only driver). A script is a plain [`ActivityStep`] list —
//! pure data, executed through the driven ports (app launcher + input
//! synthesis), which makes every scenario testable without a desktop.
//!
//! Gating: the runner starts the activities only when the pushed config has
//! `scripted: true`; kernel shutdown stops everything.

use std::{
    sync::{
        Arc,
        atomic::{
            AtomicBool,
            Ordering,
        },
    },
    time::Duration,
};

use async_trait::async_trait;
use kernel::app::plugin_ports::{
    middleware_plugin_port::{
        MiddlewarePluginPort,
        Next,
    },
    plugin_port::PluginPort,
};
use tokio_util::sync::CancellationToken;

use crate::{
    domain::{
        ActorEvent,
        ActorServices,
    },
    ports::{
        AppLauncherPort,
        InputSynthesisPort,
    },
};

/// One executable step of an activity script. Pure data — adapters give it
/// life.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivityStep {
    /// Start an application with arguments (e.g. `notepad.exe`).
    Launch {
        /// Program name or path (OS search order applies).
        program: String,
        /// Command-line arguments.
        args: Vec<String>,
    },
    /// Pause before the next step (the human-ish beat).
    Wait {
        /// Milliseconds to wait.
        ms: u64,
    },
    /// Type Unicode text (line breaks become Enter presses).
    TypeText {
        /// The text to type.
        text: String,
    },
    /// Press a single key.
    Key {
        /// The key to press.
        key: crate::ports::Key,
    },
    /// Press a chord (e.g. `Win+E`, `Ctrl+L`): modifiers down first, the
    /// last key pressed and released, modifiers up in reverse.
    Hotkey {
        /// The chord keys, modifiers first, trigger last.
        keys: Vec<crate::ports::Key>,
    },
}

/// Shared control of one running activity.
#[derive(Debug, Default)]
pub struct ActivityControl {
    stop: CancellationToken,
    paused: AtomicBool,
    started: AtomicBool,
}

impl ActivityControl {
    /// Fresh control (not started, not paused, not stopped).
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Begin: one start per control lifetime (idempotent afterwards).
    pub fn begin(&self) -> bool {
        !self.started.swap(true, Ordering::SeqCst)
    }

    /// Request termination; the script loop exits before its next step.
    pub fn stop(&self) {
        self.stop.cancel();
    }

    /// Has termination been requested?
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stop.is_cancelled()
    }

    /// Suspend stepping (the loop parks until resumed or stopped).
    pub fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    /// Continue stepping.
    pub fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    /// Is the activity parked?
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    /// Park while paused; returns early on stop.
    async fn wait_while_paused(&self) {
        while !self.stop.is_cancelled() && self.paused.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// A scripted activity: named, controllable, and repeatable.
pub trait ActivityPort: Send + Sync + 'static {
    /// Activity name (logs and diagnostics).
    fn name(&self) -> &'static str;

    /// Begin running the script loop. Idempotent: at most one loop per
    /// activity instance.
    fn start(&self);

    /// Request termination; the loop exits before its next step.
    fn stop(&self);

    /// Suspend stepping.
    fn pause(&self);

    /// Continue stepping.
    fn resume(&self);
}

/// Execute `steps` in order, forever, with `iteration_delay` between
/// passes. Every step checks stop; pause parks between steps. A failed
/// launch aborts the pass (the typing steps assume their app is up) and the
/// loop retries after the delay — one missing binary never kills the actor.
pub async fn run_script(
    control: Arc<ActivityControl>,
    launcher: Arc<dyn AppLauncherPort>,
    input: Arc<dyn InputSynthesisPort>,
    steps: Vec<ActivityStep>,
    iteration_delay: Duration,
) {
    loop {
        if control.is_stopped() {
            return;
        }
        for step in &steps {
            control.wait_while_paused().await;
            if control.is_stopped() {
                return;
            }
            if !execute_step(launcher.as_ref(), input.as_ref(), step, &control).await {
                break; // pass aborted: retry after the iteration delay
            }
        }
        // Human-ish idle beat before the next pass; interruptible.
        tokio::select! {
            () = control.stop.cancelled() => return,
            () = tokio::time::sleep(iteration_delay) => {}
        }
    }
}

/// Execute one step; `false` = abort the current pass.
async fn execute_step(
    launcher: &dyn AppLauncherPort,
    input: &dyn InputSynthesisPort,
    step: &ActivityStep,
    control: &ActivityControl,
) -> bool {
    match step {
        ActivityStep::Launch { program, args } => match launcher.launch(program, args).await {
            Ok(pid) => {
                tracing::debug!(activity = "script", program, pid, "app launched");
                true
            }
            Err(error) => {
                tracing::warn!(program, %error, "activity launch failed; skipping the pass");
                false
            }
        },
        ActivityStep::Wait { ms } => {
            tokio::select! {
                () = control.stop.cancelled() => {}
                () = tokio::time::sleep(Duration::from_millis(*ms)) => {}
            }
            true
        }
        ActivityStep::TypeText { text } => {
            if let Err(error) = input.type_text(text).await {
                tracing::warn!(%error, "activity typing failed");
            }
            true
        }
        ActivityStep::Key { key } => {
            if let Err(error) = input.press_key(*key).await {
                tracing::warn!(%error, "activity key failed");
            }
            true
        }
        ActivityStep::Hotkey { keys } => {
            if let Err(error) = input.press_hotkey(keys).await {
                tracing::warn!(%error, "activity hotkey failed");
            }
            true
        }
    }
}

/// Constructor dependencies of the runner.
pub struct ScriptedRunnerDeps {
    /// Activities to drive (assembly-time injection — the runner is their
    /// only caller).
    pub activities: Vec<Arc<dyn ActivityPort>>,
}

/// Scripted-activities runner: a pipeline plugin that watches the config
/// push and starts/stops the registered activities.
pub struct ScriptedRunnerPlugin {
    activities: Vec<Arc<dyn ActivityPort>>,
    started: AtomicBool,
}

impl ScriptedRunnerPlugin {
    /// Assemble the plugin over its activities.
    #[must_use]
    pub fn new(deps: ScriptedRunnerDeps) -> Self {
        Self { activities: deps.activities, started: AtomicBool::new(false) }
    }

    /// Start every activity (once per boot).
    pub fn start_all(&self) {
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }
        for activity in &self.activities {
            activity.start();
            tracing::info!(activity = activity.name(), "scripted activity started");
        }
    }

    /// Stop every activity (kernel shutdown calls this via `PluginPort`).
    pub fn stop_all(&self) {
        for activity in &self.activities {
            activity.stop();
        }
    }
}

#[async_trait]
impl PluginPort for ScriptedRunnerPlugin {
    fn name(&self) -> &'static str {
        "scripted-runner"
    }

    async fn stop(&self) -> Result<(), kernel::models::PluginError> {
        self.stop_all();
        Ok(())
    }
}

#[async_trait]
impl MiddlewarePluginPort<ActorEvent, ActorServices> for ScriptedRunnerPlugin {
    async fn pre(&self, event: &mut ActorEvent, _services: &ActorServices) -> Next {
        if let ActorEvent::Welcome(welcome) = event
            && welcome.config.scripted
            && !self.started.load(Ordering::SeqCst)
        {
            tracing::info!("scripted activities enabled by config push");
            self.start_all();
        }
        Next::Continue
    }
}
