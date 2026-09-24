//! Driving adapters: event sources and lifecycle drivers that call INTO the
//! hexagon via the kernel's `EventInletPort`.

/// Pure ETW → taxonomy mapping; platform-independent and always tested.
pub mod etw_mapping;
pub mod event_source_fake;
pub mod scheduler;

#[cfg(all(windows, feature = "etw"))]
pub mod etw_adapter;
#[cfg(all(windows, feature = "ipc"))]
pub mod ipc_server;
#[cfg(all(windows, feature = "service"))]
pub mod service_control;
