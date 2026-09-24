//! `ProcessKillerPort` family: the real killer and the recording fake.

pub mod fake;

#[cfg(all(windows, feature = "killer"))]
pub mod windows;
