//! `SecOutfall` agent hexagon — the session-0 service (rewrite of legacy
//! `SecOutfallB`).
//!
//! Layout: [`app`] (inbound taxonomy + composition), [`domain`] (study/session/
//! scope/drop aggregates), [`ports`] (agent port contracts), [`adapters`]
//! (real + fake adapters), [`plugins`] (hexagon plugins). The binary target is a
//! thin composition root only.

/// Crate name as launched on disk (the bin target name).
pub const NAME: &str = "secoutfall-agent";

pub mod adapters;
pub mod app;
pub mod domain;
pub mod plugins;
pub mod ports;
