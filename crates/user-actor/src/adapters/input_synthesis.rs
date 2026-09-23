//! `SendInput`-based input synthesis — the only supported mechanism
//! (`SendMessage`/`mouse_event` are deprecated). Text goes through
//! `KEYEVENTF_UNICODE` (layout-independent); chords press modifiers first
//! and release them in reverse.

use std::time::Duration;

use async_trait::async_trait;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT,
    INPUT_KEYBOARD,
    KEYBD_EVENT_FLAGS,
    KEYBDINPUT,
    KEYEVENTF_KEYUP,
    KEYEVENTF_UNICODE,
    SendInput,
    VIRTUAL_KEY,
    VK_RETURN,
};

use crate::ports::{
    InputError,
    InputSynthesisPort,
    Key,
};

/// Delay between typed characters (human-ish pacing, small enough to keep
/// scripts snappy).
const TYPE_CHAR_DELAY: Duration = Duration::from_millis(15);

/// `SendInput` adapter.
#[derive(Debug, Default)]
pub struct SendInputSynthesizer {
    /// Sequences submitted, for tests/diagnostics.
    pub submitted: std::sync::atomic::AtomicU32,
}

impl SendInputSynthesizer {
    /// Singleton.
    #[must_use]
    pub const fn new() -> Self {
        Self { submitted: std::sync::atomic::AtomicU32::new(0) }
    }

    fn count(&self) {
        self.submitted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// One keyboard event (down or up).
fn key_event(vk: Option<VIRTUAL_KEY>, ch: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: windows::Win32::UI::Input::KeyboardAndMouse::INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk.unwrap_or(VIRTUAL_KEY(0)),
                wScan: ch,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

/// Submit a batch of events; errors unless every event was accepted.
fn send_all(inputs: &[INPUT]) -> Result<(), InputError> {
    let input_size = i32::try_from(std::mem::size_of::<INPUT>())
        .map_err(|error| InputError::Failed(error.to_string()))?;
    // SAFETY: `inputs` is a valid INPUT array and `input_size` its element
    // size, per the SendInput contract.
    let sent = unsafe { SendInput(inputs, input_size) };
    let expected = u32::try_from(inputs.len()).unwrap_or(u32::MAX);
    if sent != expected {
        return Err(InputError::Failed(format!("SendInput sent {sent} of {expected}")));
    }
    Ok(())
}

#[async_trait]
impl InputSynthesisPort for SendInputSynthesizer {
    async fn press_enter(&self, hold: Duration) -> Result<(), InputError> {
        self.count();
        tokio::task::spawn_blocking(move || press_enter_blocking(hold))
            .await
            .map_err(|error| InputError::Join(error.to_string()))?
    }

    async fn type_text(&self, text: &str) -> Result<(), InputError> {
        self.count();
        let text = text.to_owned();
        tokio::task::spawn_blocking(move || type_text_blocking(&text))
            .await
            .map_err(|error| InputError::Join(error.to_string()))?
    }

    async fn press_key(&self, key: Key) -> Result<(), InputError> {
        self.count();
        tokio::task::spawn_blocking(move || press_key_blocking(key))
            .await
            .map_err(|error| InputError::Join(error.to_string()))?
    }

    async fn press_hotkey(&self, keys: &[Key]) -> Result<(), InputError> {
        self.count();
        let keys = keys.to_vec();
        tokio::task::spawn_blocking(move || press_hotkey_blocking(&keys))
            .await
            .map_err(|error| InputError::Join(error.to_string()))?
    }
}

/// Blocking down → hold → up sequence for Enter.
fn press_enter_blocking(hold: Duration) -> Result<(), InputError> {
    let down = key_event(Some(VK_RETURN), 0, KEYBD_EVENT_FLAGS(0));
    let up = key_event(Some(VK_RETURN), 0, KEYEVENTF_KEYUP);
    send_all(std::slice::from_ref(&down))?;
    std::thread::sleep(hold);
    send_all(std::slice::from_ref(&up))
}

/// Blocking Unicode typing; `\r\n` collapses to one Enter, control
/// characters are skipped, everything else goes through
/// `KEYEVENTF_UNICODE` (surrogate pairs emit both UTF-16 units).
fn type_text_blocking(text: &str) -> Result<(), InputError> {
    for ch in text.chars() {
        match ch {
            '\r' => continue,
            '\n' => press_key_blocking(Key::Enter)?,
            c if u32::from(c) < 0x20 || c == '\u{7F}' => continue,
            c => {
                let mut units = [0_u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    type_unit(*unit)?;
                }
            }
        }
        std::thread::sleep(TYPE_CHAR_DELAY);
    }
    Ok(())
}

/// Emit one UTF-16 unit via `KEYEVENTF_UNICODE`.
fn type_unit(unit: u16) -> Result<(), InputError> {
    let down = key_event(None, unit, KEYEVENTF_UNICODE);
    let up = key_event(None, unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP);
    send_all(std::slice::from_ref(&down))?;
    send_all(std::slice::from_ref(&up))
}

/// Blocking single key press.
fn press_key_blocking(key: Key) -> Result<(), InputError> {
    let vk = VIRTUAL_KEY(key.virtual_key());
    let down = key_event(Some(vk), 0, KEYBD_EVENT_FLAGS(0));
    let up = key_event(Some(vk), 0, KEYEVENTF_KEYUP);
    send_all(std::slice::from_ref(&down))?;
    send_all(std::slice::from_ref(&up))
}

/// Blocking chord: modifiers down in order, last key down+up, modifiers up
/// in reverse.
fn press_hotkey_blocking(keys: &[Key]) -> Result<(), InputError> {
    let Some((last, modifiers)) = keys.split_last() else {
        return Ok(()); // empty chord: nothing to do
    };
    let mut down_events = Vec::with_capacity(keys.len());
    for key in modifiers {
        down_events.push(key_event(Some(VIRTUAL_KEY(key.virtual_key())), 0, KEYBD_EVENT_FLAGS(0)));
    }
    down_events.push(key_event(Some(VIRTUAL_KEY(last.virtual_key())), 0, KEYBD_EVENT_FLAGS(0)));
    send_all(&down_events)?;

    let mut up_events = Vec::with_capacity(keys.len());
    up_events.push(key_event(Some(VIRTUAL_KEY(last.virtual_key())), 0, KEYEVENTF_KEYUP));
    for key in modifiers.iter().rev() {
        up_events.push(key_event(Some(VIRTUAL_KEY(key.virtual_key())), 0, KEYEVENTF_KEYUP));
    }
    send_all(&up_events)
}
