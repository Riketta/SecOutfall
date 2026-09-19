//! `SecOutfall` user-actor hexagon — the interactive-session component (rewrite of
//! legacy `ExternalModuleUA`).
//!
//! The user actor both observes the desktop (focus tracking, screenshots) and
//! acts in it (reactive + scripted input). Layout mirrors the agent: [`domain`],
//! [`ports`], [`adapters`], [`plugins`]. The binary target is a thin composition
//! root only; all config arrives via IPC push.

/// Crate name as launched on disk (the bin target name).
pub const NAME: &str = "secoutfall-user-actor";

pub mod adapters;
pub mod domain;
pub mod plugins;
pub mod ports;
