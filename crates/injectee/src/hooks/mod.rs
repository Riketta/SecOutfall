//! Example hooks built on the [`crate::hooking`] framework.
//!
//! Each module defines a single hook with the [`hook`](crate::hooking::hook)
//! macro and serves as a template for new hooks.

mod ntdelayexecution;
mod sleep;

/// Installs every example hook, collecting all failures before reporting.
pub(crate) fn install_all() -> anyhow::Result<()> {
    crate::hooking::install_all(&[ntdelayexecution::install, sleep::install])
}
