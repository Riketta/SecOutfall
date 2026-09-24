//! `ShellAssociationPort` family: the registry lookup and the unavailable
//! fake/fallback.

pub mod fake;

#[cfg(all(windows, feature = "associations"))]
pub mod registry;
