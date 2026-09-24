//! Toolhelp-snapshot process killer (Windows only, feature `killer`).
//!
//! Sweeps every process on the machine, terminates the ones whose image name
//! matches the configured cleanup list (case-insensitive, `.exe`-tolerant),
//! and never terminates the agent itself.

use std::collections::BTreeSet;

use async_trait::async_trait;
use windows::Win32::{
    Foundation::{
        CloseHandle,
        HANDLE,
    },
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot,
            PROCESSENTRY32W,
            Process32FirstW,
            Process32NextW,
            TH32CS_SNAPPROCESS,
        },
        Threading::{
            GetCurrentProcessId,
            OpenProcess,
            PROCESS_TERMINATE,
            TerminateProcess,
        },
    },
};

use crate::ports::driven::process_killer::{
    KillOutcome,
    ProcessKillerPort,
};

/// Toolhelp killer.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsProcessKiller;

impl WindowsProcessKiller {
    /// Assemble the adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

fn normalize(image: &str) -> String {
    image.strip_suffix(".exe").unwrap_or(image).to_lowercase()
}

/// All running pids + image names, one snapshot.
fn snapshot_processes() -> anyhow::Result<Vec<(u32, String)>> {
    // SAFETY: `PROCESSENTRY32W` is zero-initialized and `dwSize` set per the
    // contract before the first `Process32FirstW` call; the snapshot handle
    // is closed by the caller.
    unsafe {
        let handle: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        let mut processes = Vec::new();
        let mut entry = PROCESSENTRY32W {
            dwSize: u32::try_from(std::mem::size_of::<PROCESSENTRY32W>())?,
            ..Default::default()
        };
        if Process32FirstW(handle, &raw mut entry).is_ok() {
            loop {
                let image =
                    String::from_utf16_lossy(&entry.szExeFile).trim_end_matches('\0').to_owned();
                processes.push((entry.th32ProcessID, image));
                if Process32NextW(handle, &raw mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(handle);
        Ok(processes)
    }
}

fn sweep(names: &[String]) -> anyhow::Result<KillOutcome> {
    let wanted: BTreeSet<String> = names.iter().map(|name| normalize(name)).collect();
    // SAFETY: GetCurrentProcessId is always safe to call.
    let own_pid = unsafe { GetCurrentProcessId() };
    let mut outcome = KillOutcome::default();

    for (pid, image) in snapshot_processes()? {
        if pid == own_pid || !wanted.contains(&normalize(&image)) {
            continue;
        }
        // SAFETY: pid comes fresh from the snapshot; the handle is closed on
        // every path below.
        unsafe {
            match OpenProcess(PROCESS_TERMINATE, false, pid) {
                Ok(handle) => {
                    if TerminateProcess(handle, 1).is_ok() {
                        outcome.killed += 1;
                    } else {
                        outcome.failed += 1;
                    }
                    let _ = CloseHandle(handle);
                }
                Err(_) => {
                    outcome.failed += 1;
                }
            }
        }
    }
    Ok(outcome)
}

#[async_trait]
impl ProcessKillerPort for WindowsProcessKiller {
    async fn kill_by_image_names(&self, image_names: &[String]) -> anyhow::Result<KillOutcome> {
        // The snapshot walk is blocking and cheap; keep it off the executor.
        let names = image_names.to_vec();
        tokio::task::spawn_blocking(move || sweep(&names)).await?
    }
}
