//! `ProcessLauncherPort` family: two swappable launchers (token-based and
//! schtasks-based — config selects), the unavailable stub for builds without
//! the feature, and the fake.

pub mod fake;
pub mod unavailable;

#[cfg(all(windows, feature = "schedtask"))]
pub mod schedtask;
#[cfg(feature = "launcher")]
pub mod token;
