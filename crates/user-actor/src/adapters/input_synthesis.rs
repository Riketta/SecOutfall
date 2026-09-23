//! `SendInput`-based input synthesis — the only supported mechanism
//! (`SendMessage`/`mouse_event` are deprecated). Enter is pressed and held
//! for the configured duration (legacy cadence: 300 ms).

use std::time::Duration;

use async_trait::async_trait;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT,
    INPUT_KEYBOARD,
    KEYBDINPUT,
    KEYEVENTF_KEYUP,
    SendInput,
    VK_RETURN,
};

use crate::ports::{
    InputError,
    InputSynthesisPort,
};

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
}

fn key_input(flags: windows::Win32::UI::Input::KeyboardAndMouse::KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: windows::Win32::UI::Input::KeyboardAndMouse::INPUT_0 {
            ki: KEYBDINPUT { wVk: VK_RETURN, wScan: 0, dwFlags: flags, time: 0, dwExtraInfo: 0 },
        },
    }
}

#[async_trait]
impl InputSynthesisPort for SendInputSynthesizer {
    async fn press_enter(&self, hold: Duration) -> Result<(), InputError> {
        self.submitted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        tokio::task::spawn_blocking(move || press_enter_blocking(hold))
            .await
            .map_err(|error| InputError::Join(error.to_string()))?
    }
}

/// Blocking down → hold → up sequence.
fn press_enter_blocking(hold: Duration) -> Result<(), InputError> {
    let down = key_input(windows::Win32::UI::Input::KeyboardAndMouse::KEYBD_EVENT_FLAGS(0));
    let up = key_input(KEYEVENTF_KEYUP);
    let input_size = i32::try_from(std::mem::size_of::<INPUT>())
        .map_err(|error| InputError::Failed(error.to_string()))?;

    // SAFETY: a one-element INPUT array with the matching size.
    let sent = unsafe { SendInput(std::slice::from_ref(&down), input_size) };
    if sent != 1 {
        return Err(InputError::Failed(format!("SendInput down sent {sent} of 1")));
    }

    std::thread::sleep(hold);

    // SAFETY: as above.
    let sent = unsafe { SendInput(std::slice::from_ref(&up), input_size) };
    if sent != 1 {
        return Err(InputError::Failed(format!("SendInput up sent {sent} of 1")));
    }
    Ok(())
}
