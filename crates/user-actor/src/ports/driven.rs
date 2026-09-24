//! User-actor driven ports beyond the kernel's. Driving sources (focus, IPC)
//! call the kernel inlet directly — they are adapters, not ports here.

use async_trait::async_trait;

/// Driven port: capture the desktop to a JPEG-encoded image.
///
/// Implementations must be DPI-aware and cover the whole virtual screen (all
/// monitors).
#[async_trait]
pub trait ScreenCapturePort: Send + Sync + 'static {
    /// Capture now; returns raw JPEG bytes.
    ///
    /// # Errors
    /// [`CaptureError`] describing the failure stage (desktop gone, GDI
    /// failure, encode failure).
    async fn capture(&self) -> Result<Vec<u8>, CaptureError>;
}

/// Capture failures.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// No interactive desktop to capture (session shutting down).
    #[error("desktop unavailable")]
    Unavailable,
    /// Win32 GDI call failed.
    #[error("gdi failure: {0}")]
    Gdi(String),
    /// JPEG encoding failed.
    #[error("jpeg encode failed: {0}")]
    Encode(String),
    /// The blocking task could not be joined (runtime shutting down).
    #[error("capture task join failed: {0}")]
    Join(String),
}

/// Driven port: hand one finished screenshot to the agent (IPC v1).
///
/// The sequence number is the per-session capture counter — assigned by the
/// caller, echoed by the agent in `screenshot.received`.
#[async_trait]
pub trait ScreenshotSinkPort: Send + Sync + 'static {
    /// Send one screenshot frame.
    ///
    /// # Errors
    /// [`ScreenshotSinkError::Closed`] while the pipe is down (the caller may
    /// retry later frames; the failed one is dropped).
    async fn send(&self, seq: u32, jpeg: Vec<u8>) -> Result<(), ScreenshotSinkError>;
}

/// Sink failures.
#[derive(Debug, thiserror::Error)]
pub enum ScreenshotSinkError {
    /// The transport is not connected; the frame is lost.
    #[error("screenshot sink closed")]
    Closed,
    /// The bounded queue is saturated; the frame is dropped (overflow
    /// policy: coalesce + loss counter — the sink never blocks its caller).
    #[error("screenshot queue saturated; frame dropped")]
    Full,
    /// The frame would exceed the wire cap (`MAX_PAYLOAD_LEN`); sending it
    /// would poison the connection (the peer must reject it and disconnect).
    #[error("screenshot exceeds the IPC frame cap")]
    Oversize,
}

/// A virtual key named for script use; mapped to Win32 VK codes by adapters.
/// `Raw` is the escape hatch for anything the scripts don't name yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// Left Windows key (scripted `Win+E` and friends).
    Win,
    /// Ctrl modifier.
    Ctrl,
    /// Shift modifier.
    Shift,
    /// Alt modifier.
    Alt,
    /// Escape.
    Escape,
    /// Tab.
    Tab,
    /// Enter / Return.
    Enter,
    /// Backspace.
    Backspace,
    /// Space.
    Space,
    /// Top-row digit `0`–`9` (`Key::Digit(0)` … `Key::Digit(9)`).
    Digit(u8),
    /// Letter `A`–`Z` (VK code, layout-independent for modifiers chords).
    Letter(char),
    /// Numpad `+`.
    Add,
    /// Numpad `-`.
    Subtract,
    /// Numpad `*`.
    Multiply,
    /// Numpad `/`.
    Divide,
    /// Numpad `.`.
    Decimal,
    /// Raw virtual-key code (escape hatch; scripts should prefer named keys).
    Raw(u16),
}

impl Key {
    /// The Win32 virtual-key code.
    #[must_use]
    pub fn virtual_key(self) -> u16 {
        match self {
            Self::Win => 0x5B,                                          // VK_LWIN
            Self::Ctrl => 0x11,                                         // VK_CONTROL
            Self::Shift => 0x10,                                        // VK_SHIFT
            Self::Alt => 0x12,                                          // VK_MENU
            Self::Escape => 0x1B,                                       // VK_ESCAPE
            Self::Tab => 0x09,                                          // VK_TAB
            Self::Enter => 0x0D,                                        // VK_RETURN
            Self::Backspace => 0x08,                                    // VK_BACK
            Self::Space => 0x20,                                        // VK_SPACE
            Self::Digit(d) => 0x30 + u16::from(d.min(9)),               // VK 0x30..0x39 = '0'..'9'
            Self::Letter(c) => u16::from(c.to_ascii_uppercase() as u8), // VK = ASCII for A..Z
            Self::Add => 0x6B,                                          // VK_ADD
            Self::Subtract => 0x6D,                                     // VK_SUBTRACT
            Self::Multiply => 0x6A,                                     // VK_MULTIPLY
            Self::Divide => 0x6F,                                       // VK_DIVIDE
            Self::Decimal => 0x6E,                                      // VK_DECIMAL
            Self::Raw(vk) => vk,
        }
    }
}

/// Driven port: synthesize user input on the interactive desktop
/// (`SendInput` only — `SendMessage`/`mouse_event` are deprecated).
#[async_trait]
pub trait InputSynthesisPort: Send + Sync + 'static {
    /// Press and release Enter, holding the key down for `hold`.
    ///
    /// # Errors
    /// [`InputError`] when the OS refuses the synthesis.
    async fn press_enter(&self, hold: std::time::Duration) -> Result<(), InputError>;

    /// Type Unicode text (`KEYEVENTF_UNICODE`, layout-independent). Line
    /// breaks become Enter presses.
    ///
    /// # Errors
    /// [`InputError`] when the OS refuses the synthesis.
    async fn type_text(&self, text: &str) -> Result<(), InputError>;

    /// Press and release one key.
    ///
    /// # Errors
    /// [`InputError`] when the OS refuses the synthesis.
    async fn press_key(&self, key: Key) -> Result<(), InputError>;

    /// Press a chord: modifiers down first (in order), the last key pressed
    /// and released, modifiers up in reverse.
    ///
    /// # Errors
    /// [`InputError`] when the OS refuses the synthesis.
    async fn press_hotkey(&self, keys: &[Key]) -> Result<(), InputError>;
}

/// Input synthesis failures.
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    /// Win32 `SendInput` failed (ubits/desktop gone).
    #[error("send_input failed: {0}")]
    Failed(String),
    /// The blocking task could not be joined.
    #[error("input task join failed: {0}")]
    Join(String),
}

/// Driven port: start an application in the interactive session. The user
/// actor already runs as the interactive user, so a plain process creation
/// is enough (the agent's token-based launcher is session-0 side only).
#[async_trait]
pub trait AppLauncherPort: Send + Sync + 'static {
    /// Launch `program` with `args`; returns the spawned pid.
    ///
    /// # Errors
    /// [`AppLaunchError`] when creation fails.
    async fn launch(&self, program: &str, args: &[String]) -> Result<u32, AppLaunchError>;
}

/// App launch failures.
#[derive(Debug, thiserror::Error)]
pub enum AppLaunchError {
    /// Process creation failed (binary missing, desktop gone).
    #[error("process creation failed: {0}")]
    Create(String),
    /// The blocking task could not be joined.
    #[error("launch task join failed: {0}")]
    Join(String),
}
