//! Fake input synthesis: records synthesized actions instead of touching the
//! desktop. Tests and dev builds.

use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::ports::{
    InputError,
    InputSynthesisPort,
    Key,
};

/// One synthesized action, recorded verbatim for assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedInput {
    /// Enter held for this many milliseconds.
    EnterHold(u64),
    /// Text typed verbatim (line breaks as `\n`).
    Text(String),
    /// Single key press.
    KeyPress(Key),
    /// Chord (keys in the order given).
    Hotkey(Vec<Key>),
}

/// Always-succeeding fake recording actions.
#[derive(Debug)]
pub struct FakeInput {
    actions: Mutex<Vec<RecordedInput>>,
    /// A waiter used by tests to await the Nth action deterministically.
    waiter: tokio::sync::watch::Sender<usize>,
}

impl Default for FakeInput {
    fn default() -> Self {
        let (waiter, _) = tokio::sync::watch::channel(0);
        Self { actions: Mutex::new(Vec::new()), waiter }
    }
}

impl FakeInput {
    /// Fresh fake.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Recorded actions in synthesis order.
    #[must_use]
    pub fn actions(&self) -> Vec<RecordedInput> {
        self.actions.lock().clone()
    }

    /// Recorded Enter hold durations in milliseconds (legacy assertions).
    #[must_use]
    pub fn holds(&self) -> Vec<u64> {
        self.actions
            .lock()
            .iter()
            .filter_map(|action| match action {
                RecordedInput::EnterHold(hold) => Some(*hold),
                _ => None,
            })
            .collect()
    }

    /// A receiver for the action count (tests await thresholds on it).
    #[must_use]
    pub fn count_rx(&self) -> tokio::sync::watch::Receiver<usize> {
        self.waiter.subscribe()
    }
}

#[async_trait]
impl InputSynthesisPort for FakeInput {
    async fn press_enter(&self, hold: Duration) -> Result<(), InputError> {
        let hold = u64::try_from(hold.as_millis()).unwrap_or(u64::MAX);
        self.actions.lock().push(RecordedInput::EnterHold(hold));
        self.waiter.send_replace(self.actions.lock().len());
        Ok(())
    }

    async fn type_text(&self, text: &str) -> Result<(), InputError> {
        self.actions.lock().push(RecordedInput::Text(text.to_owned()));
        self.waiter.send_replace(self.actions.lock().len());
        Ok(())
    }

    async fn press_key(&self, key: Key) -> Result<(), InputError> {
        self.actions.lock().push(RecordedInput::KeyPress(key));
        self.waiter.send_replace(self.actions.lock().len());
        Ok(())
    }

    async fn press_hotkey(&self, keys: &[Key]) -> Result<(), InputError> {
        self.actions.lock().push(RecordedInput::Hotkey(keys.to_vec()));
        self.waiter.send_replace(self.actions.lock().len());
        Ok(())
    }
}

/// Placeholder for binaries built without the `input` feature: every press
/// fails with a clear error.
#[derive(Debug, Default)]
pub struct UnavailableInput;

#[async_trait]
impl InputSynthesisPort for UnavailableInput {
    async fn press_enter(&self, _hold: Duration) -> Result<(), InputError> {
        Err(InputError::Failed("built without the input feature".to_owned()))
    }

    async fn type_text(&self, _text: &str) -> Result<(), InputError> {
        Err(InputError::Failed("built without the input feature".to_owned()))
    }

    async fn press_key(&self, _key: Key) -> Result<(), InputError> {
        Err(InputError::Failed("built without the input feature".to_owned()))
    }

    async fn press_hotkey(&self, _keys: &[Key]) -> Result<(), InputError> {
        Err(InputError::Failed("built without the input feature".to_owned()))
    }
}
