//! Sensor hooks (v1 set): observe-only detours that report the host
//! process's API activity into the sensor ring. No behavior changes, no
//! allocation, no panics — the emit path is bounded and lock-free.

mod ntcreatefile;
mod ntcreatethreadex;
mod ntdelayexecution;
mod ntwritefile;

/// Installs every sensor hook, collecting all failures before reporting.
pub(crate) fn install_all() -> anyhow::Result<()> {
    crate::hooking::install_all(&[
        ntcreatefile::install,
        ntwritefile::install,
        ntcreatethreadex::install,
        ntdelayexecution::install,
    ])
}
