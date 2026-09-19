//! `TokenProcessLauncher` — native interactive-session launch (spike).
//!
//! Replaces the legacy scheduled-task trick with the straightforward path the
//! legacy code already contained as dead code: take the active console session
//! id, grab the session user's token (`WTSQueryUserToken`, requires
//! `SE_TCB_NAME` — we run as SYSTEM inside the VM), duplicate it into a primary
//! token and `CreateProcessAsUserW` on the interactive desktop.
//!
//! Blocking FFI runs in `spawn_blocking`; the port stays async.

use std::os::windows::ffi::OsStrExt;

use async_trait::async_trait;

use crate::ports::process_launcher::{
    LaunchError,
    LaunchOutcome,
    LaunchSpec,
    ProcessLauncherPort,
};

/// Native token-based launcher.
#[derive(Debug, Default)]
pub struct TokenProcessLauncher;

impl TokenProcessLauncher {
    /// Singleton adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

fn wide_null(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// Blocking implementation; errors already mapped to [`LaunchError`].
#[allow(clippy::too_many_lines)] // one FFI sequence, kept linear on purpose
fn launch_blocking(spec: &LaunchSpec) -> Result<LaunchOutcome, LaunchError> {
    use windows::{
        Win32::{
            Foundation::{
                CloseHandle,
                ERROR_ACCESS_DENIED,
                HANDLE,
            },
            Security::{
                DuplicateTokenEx,
                SecurityIdentification,
                TOKEN_ADJUST_DEFAULT,
                TOKEN_ADJUST_SESSIONID,
                TOKEN_ASSIGN_PRIMARY,
                TOKEN_DUPLICATE,
                TOKEN_QUERY,
                TokenPrimary,
            },
            System::{
                RemoteDesktop::{
                    WTSGetActiveConsoleSessionId,
                    WTSQueryUserToken,
                },
                Threading::{
                    CREATE_UNICODE_ENVIRONMENT,
                    CreateProcessAsUserW,
                    PROCESS_INFORMATION,
                    STARTUPINFOW,
                },
            },
        },
        core::{
            PCWSTR,
            PWSTR,
        },
    };

    // SAFETY: no preconditions — returns the current console session id.
    let session_id = unsafe { WTSGetActiveConsoleSessionId() };
    let mut token = HANDLE::default();
    // SAFETY: `token` is a valid, initialized output handle; `session_id` is
    // an arbitrary session id, which the API accepts from privileged callers.
    unsafe { WTSQueryUserToken(session_id, std::ptr::from_mut(&mut token)) }.map_err(|error| {
        if error.code() == ERROR_ACCESS_DENIED.to_hresult() {
            LaunchError::NoInteractiveSession
        } else {
            LaunchError::Token(error.to_string())
        }
    })?;

    let desired: windows::Win32::Security::TOKEN_ACCESS_MASK = TOKEN_ASSIGN_PRIMARY
        | TOKEN_DUPLICATE
        | TOKEN_QUERY
        | TOKEN_ADJUST_DEFAULT
        | TOKEN_ADJUST_SESSIONID;
    let mut primary = HANDLE::default();
    // SAFETY: `token` is a valid open token handle; out-param `primary` is
    // initialized by the call.
    let duplicated = unsafe {
        DuplicateTokenEx(
            token,
            desired,
            None,
            SecurityIdentification,
            TokenPrimary,
            std::ptr::from_mut(&mut primary),
        )
    };
    // SAFETY: `token` is owned and closed exactly once here.
    let _ = unsafe { CloseHandle(token) };
    duplicated.map_err(|error| LaunchError::Token(error.to_string()))?;

    // Mutable command line: "path\0arg1\0arg2\0\0" (CreateProcessAsUserW contract).
    let mut cmdline: Vec<u16> = wide_null(&spec.path);
    for arg in &spec.args {
        cmdline.extend(wide_null(arg));
    }
    cmdline.push(0);

    let si = STARTUPINFOW {
        cb: u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap_or(0),
        lpDesktop: PWSTR(windows::core::w!("winsta0\\default").as_ptr().cast_mut()),
        ..STARTUPINFOW::default()
    };
    let mut pi = PROCESS_INFORMATION::default();

    let application = wide_null(&spec.path);
    let working_dir: Vec<u16> =
        spec.working_dir.as_ref().map(|dir| wide_null(dir)).unwrap_or_default();
    let working_dir_ptr =
        if working_dir.is_empty() { PWSTR::null() } else { PWSTR(working_dir.as_ptr().cast_mut()) };

    // SAFETY: all string buffers are NUL-terminated for the call's lifetime;
    // handles and structs are initialized per the API contract.
    let created = unsafe {
        CreateProcessAsUserW(
            primary,
            PCWSTR(application.as_ptr()),
            PWSTR(cmdline.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_UNICODE_ENVIRONMENT,
            None,
            working_dir_ptr,
            std::ptr::from_ref(&si),
            std::ptr::from_mut(&mut pi),
        )
    };
    let pid = pi.dwProcessId;
    // SAFETY: each handle is valid (returned by the call above) and closed
    // exactly once; closing them does not terminate the spawned process.
    unsafe {
        let _ = CloseHandle(primary);
        if !pi.hThread.is_invalid() {
            let _ = CloseHandle(pi.hThread);
        }
        if !pi.hProcess.is_invalid() {
            let _ = CloseHandle(pi.hProcess);
        }
    }
    created.map_err(|error| LaunchError::Spawn(error.to_string()))?;
    Ok(LaunchOutcome { pid: Some(pid) })
}

#[async_trait]
impl ProcessLauncherPort for TokenProcessLauncher {
    async fn launch(&self, spec: &LaunchSpec) -> Result<LaunchOutcome, LaunchError> {
        let spec = spec.clone();
        tokio::task::spawn_blocking(move || launch_blocking(&spec))
            .await
            .map_err(|error| LaunchError::Spawn(error.to_string()))?
    }
}
