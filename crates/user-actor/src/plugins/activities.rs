//! The three scripted activities (legacy intent: `NotepadActivity`,
//! `CalcActivity`, `ExplorerActivity` — all unimplemented stubs in the
//! legacy source, so the scripts below are the first real implementation).
//!
//! Each activity is a step script executed by
//! [`run_script`](crate::plugins::scripted::run_script): launch the app,
//! wait for its window, then interact in a human-ish cadence, forever, until
//! stopped. Scripts favor layout-independent input: Unicode typing for
//! text, named virtual keys for chords and calculator tokens.

use std::{
    sync::Arc,
    time::Duration,
};

use crate::{
    plugins::scripted::{
        ActivityControl,
        ActivityPort,
        ActivityStep,
        run_script,
    },
    ports::driven::{
        AppLauncherPort,
        InputSynthesisPort,
        Key,
    },
};

/// Idle beat between script passes (interruptible; tests run on paused time).
const ITERATION_DELAY: Duration = Duration::from_secs(30);

/// Shared wiring every activity needs.
#[derive(Clone)]
pub struct ActivityEnv {
    /// App launcher (notepad/calc/explorer creation).
    pub launcher: Arc<dyn AppLauncherPort>,
    /// Input synthesis (typing, keys, chords).
    pub input: Arc<dyn InputSynthesisPort>,
}

/// A complete activity: script + control + env.
pub struct ScriptedActivity {
    name: &'static str,
    steps: Vec<ActivityStep>,
    env: ActivityEnv,
    control: Arc<ActivityControl>,
}

impl ScriptedActivity {
    /// Build one activity from its name and script.
    #[must_use]
    pub fn new(name: &'static str, steps: Vec<ActivityStep>, env: ActivityEnv) -> Arc<Self> {
        Arc::new(Self { name, steps, env, control: ActivityControl::new() })
    }
}

impl ActivityPort for ScriptedActivity {
    fn name(&self) -> &'static str {
        self.name
    }

    fn start(&self) {
        if !self.control.begin() {
            return;
        }
        let control = Arc::clone(&self.control);
        let launcher = Arc::clone(&self.env.launcher);
        let input = Arc::clone(&self.env.input);
        let steps = self.steps.clone();
        let delay = ITERATION_DELAY;
        tokio::spawn(async move {
            run_script(control, launcher, input, steps, delay).await;
        });
    }

    fn stop(&self) {
        self.control.stop();
    }

    fn pause(&self) {
        self.control.pause();
    }

    fn resume(&self) {
        self.control.resume();
    }
}

/// A short "user wrote something in notepad" scenario: open notepad, type a
/// note in a few lines, then start over (new run focuses the existing
/// window; typing continues there — plausible either way).
#[must_use]
pub fn notepad_script() -> Vec<ActivityStep> {
    vec![
        ActivityStep::Launch { program: "notepad.exe".to_owned(), args: vec![] },
        ActivityStep::Wait { ms: 1_500 },
        ActivityStep::TypeText {
            text: "Quarterly report draft\r\nThe numbers look reasonable this month.\r\n"
                .to_owned(),
        },
        ActivityStep::Wait { ms: 900 },
        ActivityStep::TypeText {
            text: "TODO: verify the export dialog remembers the last folder.\r\n".to_owned(),
        },
        ActivityStep::Wait { ms: 1_200 },
        ActivityStep::TypeText { text: "Done for now.\r\n".to_owned() },
        ActivityStep::Wait { ms: 2_000 },
    ]
}

/// Calculator arithmetic: open calc, run a few sums with a steady key
/// cadence, clear, repeat with variation.
#[must_use]
pub fn calc_script() -> Vec<ActivityStep> {
    use ActivityStep::{
        Key as StepKey,
        Launch,
        Wait,
    };
    vec![
        Launch { program: "calc.exe".to_owned(), args: vec![] },
        Wait { ms: 2_500 },
        StepKey { key: Key::Digit(1) },
        StepKey { key: Key::Digit(2) },
        StepKey { key: Key::Add },
        StepKey { key: Key::Digit(3) },
        StepKey { key: Key::Digit(0) },
        StepKey { key: Key::Enter },
        Wait { ms: 800 },
        StepKey { key: Key::Multiply },
        StepKey { key: Key::Digit(2) },
        StepKey { key: Key::Enter },
        Wait { ms: 800 },
        StepKey { key: Key::Escape },
        Wait { ms: 600 },
        StepKey { key: Key::Digit(9) },
        StepKey { key: Key::Divide },
        StepKey { key: Key::Digit(3) },
        StepKey { key: Key::Enter },
        Wait { ms: 1_500 },
    ]
}

/// Explorer navigation: open a window, jump to the address bar, visit a
/// couple of directories.
#[must_use]
pub fn explorer_script() -> Vec<ActivityStep> {
    vec![
        ActivityStep::Hotkey { keys: vec![Key::Win, Key::Letter('E')] },
        ActivityStep::Wait { ms: 2_000 },
        ActivityStep::Hotkey { keys: vec![Key::Ctrl, Key::Letter('L')] },
        ActivityStep::Wait { ms: 300 },
        ActivityStep::TypeText { text: "C:\\Users\\Public\\Documents".to_owned() },
        ActivityStep::Key { key: Key::Enter },
        ActivityStep::Wait { ms: 1_500 },
        ActivityStep::Hotkey { keys: vec![Key::Ctrl, Key::Letter('L')] },
        ActivityStep::Wait { ms: 300 },
        ActivityStep::TypeText { text: "C:\\Windows\\Temp".to_owned() },
        ActivityStep::Key { key: Key::Enter },
        ActivityStep::Wait { ms: 1_500 },
        ActivityStep::Hotkey { keys: vec![Key::Alt, Key::Tab] },
    ]
}
