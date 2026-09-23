//! `CreateProcessW` app launcher — the user actor already runs as the
//! interactive user, so a plain creation reaches the visible desktop.
//! Blocking FFI runs in `spawn_blocking`; the port stays async.

use std::os::windows::ffi::OsStrExt;

use async_trait::async_trait;

use crate::ports::{
    AppLaunchError,
    AppLauncherPort,
};

/// Native app launcher.
#[derive(Debug, Default)]
pub struct NativeAppLauncher;

impl NativeAppLauncher {
    /// Singleton adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

fn wide_null(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// Blocking creation; the command line is `"prog" arg1 arg2` (mutable buffer
/// per the `CreateProcessW` contract), `lpApplicationName` left null so the
/// OS applies its standard search order (`System32`, `PATH`...) — scripts
/// name plain `notepad.exe`-style programs.
fn launch_blocking(program: &str, args: &[String]) -> Result<u32, AppLaunchError> {
    use windows::{
        Win32::System::Threading::{
            CREATE_UNICODE_ENVIRONMENT,
            CreateProcessW,
            PROCESS_INFORMATION,
            STARTUPINFOW,
        },
        core::PWSTR,
    };

    let mut command_line = wide_null(&quote(program));
    for arg in args {
        command_line.extend(wide_null(&quote(arg)));
    }
    command_line.push(0);

    let si = STARTUPINFOW {
        cb: u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap_or(0),
        ..STARTUPINFOW::default()
    };
    let mut pi = PROCESS_INFORMATION::default();

    // SAFETY: the command line is a NUL-terminated mutable buffer valid for
    // the call; handles and structs are initialized per the API contract.
    let created = unsafe {
        CreateProcessW(
            None,
            PWSTR(command_line.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_UNICODE_ENVIRONMENT,
            None,
            None,
            std::ptr::from_ref(&si),
            std::ptr::from_mut(&mut pi),
        )
    };
    let pid = pi.dwProcessId;
    // SAFETY: each handle is valid (returned by the call above) and closed
    // exactly once; closing them does not terminate the spawned process.
    unsafe {
        if !pi.hThread.is_invalid() {
            let _ = windows::Win32::Foundation::CloseHandle(pi.hThread);
        }
        if !pi.hProcess.is_invalid() {
            let _ = windows::Win32::Foundation::CloseHandle(pi.hProcess);
        }
    }
    created.map_err(|error| AppLaunchError::Create(error.to_string()))?;
    Ok(pid)
}

/// Windows command-line quoting: wrap when the argument contains whitespace
/// or a quote; inner quotes are backslash-escaped.
fn quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|ch| ch.is_whitespace() || ch == '"') {
        return arg.to_owned();
    }
    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('"');
    for ch in arg.chars() {
        if ch == '"' {
            quoted.push('\\');
        }
        quoted.push(ch);
    }
    quoted.push('"');
    quoted
}

#[async_trait]
impl AppLauncherPort for NativeAppLauncher {
    async fn launch(&self, program: &str, args: &[String]) -> Result<u32, AppLaunchError> {
        let program = program.to_owned();
        let args = args.to_vec();
        tokio::task::spawn_blocking(move || launch_blocking(&program, &args))
            .await
            .map_err(|error| AppLaunchError::Join(error.to_string()))?
    }
}
