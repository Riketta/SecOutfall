//! Fake capture: returns a canned JPEG-shaped buffer. Tests and dev builds.

use async_trait::async_trait;

use crate::ports::{
    CaptureError,
    ScreenCapturePort,
};

/// A minimal but structurally valid JPEG header (SOI + APP0 JFIF) followed by
/// a recognizable filler — enough for tests to assert framing without a real
/// encoder.
#[must_use]
pub fn canned_jpeg() -> Vec<u8> {
    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00];
    jpeg.extend(std::iter::repeat_n(0xAB, 32));
    jpeg
}

/// Always-succeeding fake capture.
#[derive(Debug, Default)]
pub struct FakeCapture {
    /// Capture invocations, for assertions.
    pub calls: std::sync::atomic::AtomicU32,
}

impl FakeCapture {
    /// Singleton.
    #[must_use]
    pub const fn new() -> Self {
        Self { calls: std::sync::atomic::AtomicU32::new(0) }
    }
}

#[async_trait]
impl ScreenCapturePort for FakeCapture {
    async fn capture(&self) -> Result<Vec<u8>, CaptureError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(canned_jpeg())
    }
}

/// Failing fake (quota/backoff paths).
#[derive(Debug, Default)]
pub struct FailingCapture {
    /// Capture invocations, for assertions.
    pub calls: std::sync::atomic::AtomicU32,
}

#[async_trait]
impl ScreenCapturePort for FailingCapture {
    async fn capture(&self) -> Result<Vec<u8>, CaptureError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(CaptureError::Unavailable)
    }
}

/// Placeholder for binaries built without the `capture` feature: every call
/// fails with a clear error instead of silently producing nothing.
#[derive(Debug, Default)]
pub struct UnavailableCapture;

#[async_trait]
impl ScreenCapturePort for UnavailableCapture {
    async fn capture(&self) -> Result<Vec<u8>, CaptureError> {
        Err(CaptureError::Gdi("built without the capture feature".to_owned()))
    }
}
