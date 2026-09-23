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
