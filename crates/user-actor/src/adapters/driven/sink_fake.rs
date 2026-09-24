//! Fake screenshot sink: records frames in memory. Tests and dev builds.

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::ports::driven::{
    ScreenshotSinkError,
    ScreenshotSinkPort,
};

/// One recorded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedFrame {
    /// Sequence number the caller assigned.
    pub seq: u32,
    /// JPEG bytes.
    pub jpeg: Vec<u8>,
}

/// Fake sink keeping every frame; optionally failing.
#[derive(Debug, Default)]
pub struct FakeSink {
    frames: Mutex<Vec<RecordedFrame>>,
    /// When true, every send fails (pipe-down simulation).
    pub fail_sends: std::sync::atomic::AtomicBool,
}

impl FakeSink {
    /// Singleton (succeeding sends).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            frames: Mutex::new(Vec::new()),
            fail_sends: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Recorded frames in send order.
    #[must_use]
    pub fn frames(&self) -> Vec<RecordedFrame> {
        self.frames.lock().clone()
    }
}

#[async_trait]
impl ScreenshotSinkPort for FakeSink {
    async fn send(&self, seq: u32, jpeg: Vec<u8>) -> Result<(), ScreenshotSinkError> {
        if self.fail_sends.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ScreenshotSinkError::Closed);
        }
        self.frames.lock().push(RecordedFrame { seq, jpeg });
        Ok(())
    }
}

/// Placeholder for binaries built without the `ipc` feature: every frame is
/// dropped with a clear error.
#[derive(Debug, Default)]
pub struct UnavailableSink;

#[async_trait]
impl ScreenshotSinkPort for UnavailableSink {
    async fn send(&self, _seq: u32, _jpeg: Vec<u8>) -> Result<(), ScreenshotSinkError> {
        Err(ScreenshotSinkError::Closed)
    }
}
