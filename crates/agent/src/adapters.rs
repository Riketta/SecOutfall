//! Infrastructure adapters: real ones ship in phases 4–6, fakes power tests and
//! the simulation harness.

pub mod broker_fake;
pub mod clock_fake;
pub mod clock_system;
pub mod event_source_fake;
pub mod launcher_fake;
pub mod scheduler;
pub mod scope_store_json;
pub mod scope_store_memory;

#[cfg(all(windows, feature = "etw"))]
pub mod etw_adapter;
#[cfg(feature = "launcher")]
pub mod launcher_token;
#[cfg(all(windows, feature = "service"))]
pub mod service_control;

/// Pure ETW → taxonomy mapping; platform-independent and always tested.
pub mod etw_mapping;
