//! `SecOutfall` user-actor hexagon — the interactive-session component (rewrite of
//! legacy `ExternalModuleUA`).
//!
//! The user actor both observes the desktop (focus tracking, screenshots) and
//! acts in it (reactive + scripted input). Layout mirrors the agent: [`app`],
//! [`domain`], [`ports`], [`adapters`], [`plugins`]. The binary target is a thin
//! composition root only; all config arrives via IPC push.

/// Crate name as launched on disk (the bin target name).
pub const NAME: &str = "secoutfall-user-actor";

/// Fixed IPC v1 pipe name (must match the agent's server adapter).
pub const PIPE_NAME: &str = "\\\\.\\pipe\\secoutfall\\user-actor-v1";

pub mod adapters;
pub mod app;
pub mod domain;
pub mod plugins;
pub mod ports;
