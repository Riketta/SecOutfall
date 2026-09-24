//! `ScreenCapturePort` family: the GDI capture and the unavailable fake.

pub mod fake;

#[cfg(feature = "capture")]
pub mod screen;
