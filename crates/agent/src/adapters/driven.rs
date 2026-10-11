//! Driven adapters: implement the hexagon's outbound ports, one family per
//! port. Fakes live beside their production twins inside each family.

pub mod broker;
pub mod clock;
pub mod config_toml;
#[cfg(all(windows, feature = "driver"))]
pub mod driver_control_device;
pub mod driver_control_fake;
// Pre-tracing service failure reporting (Event Log + fallback file).
#[cfg(all(windows, feature = "service"))]
pub mod event_log;
pub mod killer;
pub mod launcher;
// Needs the optional `windows` dep: compiled whenever any windows-using
// feature is on (its consumers are all feature-gated the same way).
#[cfg(all(
    windows,
    any(
        feature = "time_shift",
        feature = "launcher",
        feature = "schedtask",
        feature = "ipc",
        feature = "killer"
    )
))]
pub mod privileges;
pub mod scope_store;
pub mod sensor_store;
pub mod shell_association;
pub mod upload;
