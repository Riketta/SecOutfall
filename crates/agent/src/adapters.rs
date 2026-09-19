//! Infrastructure adapters: real ones ship in phases 4–6, fakes power tests and
//! the simulation harness.

pub mod broker_fake;
pub mod clock_fake;
pub mod clock_system;
pub mod event_source_fake;
pub mod scope_store_json;
pub mod scope_store_memory;
