//! Driving adapters: sources that call INTO the hexagon via the kernel's
//! `EventInletPort`.

#[cfg(feature = "focus-poll")]
pub mod focus_poll;
#[cfg(any(feature = "focus-poll", feature = "focus-winevents"))]
pub mod focus_shared;
#[cfg(feature = "focus-winevents")]
pub mod focus_winevents;
#[cfg(feature = "ipc")]
pub mod ipc_client;
