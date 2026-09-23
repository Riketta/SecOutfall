//! Infrastructure adapters. Feature-gated Windows adapters (IPC client, focus
//! sources, GDI capture, input synthesis) live beside the always-compiled
//! fakes used by tests and fallback composition.

pub mod capture_fake;
pub mod input_fake;
pub mod sink_fake;

#[cfg(feature = "focus-poll")]
pub mod focus_poll;
#[cfg(any(feature = "focus-poll", feature = "focus-winevents"))]
pub mod focus_shared;
#[cfg(feature = "focus-winevents")]
pub mod focus_winevents;
#[cfg(feature = "input")]
pub mod input_synthesis;
#[cfg(feature = "ipc")]
pub mod ipc_client;
#[cfg(feature = "capture")]
pub mod screen_capture;
