//! Infrastructure adapters: real ones ship in phases 4–6, fakes power tests and
//! the simulation harness.

pub mod broker_console;
pub mod broker_fake;
pub mod broker_jsonl;
pub mod broker_nats;
pub mod broker_tee;
pub mod clock_fake;
pub mod clock_shift;
pub mod clock_system;
pub mod config_toml;
pub mod event_source_fake;
pub mod http_upload;
pub mod launcher_fake;
pub mod launcher_unavailable;
pub mod process_killer_fake;
pub mod scheduler;
pub mod scope_store_json;
pub mod scope_store_local;
pub mod scope_store_memory;
pub mod shell_association_fake;
pub mod upload_fake;

#[cfg(all(windows, feature = "etw"))]
pub mod etw_adapter;
#[cfg(all(windows, feature = "ipc"))]
pub mod ipc_server;
#[cfg(all(windows, feature = "schedtask"))]
pub mod launcher_schedtask;
#[cfg(feature = "launcher")]
pub mod launcher_token;
#[cfg(all(windows, feature = "killer"))]
pub mod process_killer_windows;
#[cfg(all(windows, feature = "service"))]
pub mod service_control;
#[cfg(all(windows, feature = "associations"))]
pub mod shell_association_registry;

/// Pure ETW → taxonomy mapping; platform-independent and always tested.
pub mod etw_mapping;
