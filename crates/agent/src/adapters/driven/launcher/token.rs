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

use crate::ports::driven::process_launcher::{
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

/// Quote one argv element with the MSVCRT rules the child's command-line
/// parser applies: backslash runs before a quote double up, a trailing
/// backslash run before the closing quote doubles. Values without specials
/// pass through unquoted. (Same rules as the user-actor's app launcher and
/// the schedtask action line — keep the three in sync.)
fn quote(arg: &str) -> String {
    let needs_quotes =
        arg.is_empty() || arg.chars().any(|ch| matches!(ch, ' ' | '\t' | '\n' | '"'));
    if !needs_quotes {
        return arg.to_owned();
    }
    let mut quoted = String::with_capacity(arg.len() + 3);
    quoted.push('"');
    let mut backslashes = 0_usize;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            other => {
                quoted.extend(std::iter::repeat_n('\\', backslashes));
                backslashes = 0;
                quoted.push(other);
            }
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
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
    // SeTcbPrivilege gates WTSQueryUserToken; LocalSystem holds it
    // present-but-disabled — enable it or the query always fails.
    if !crate::adapters::driven::privileges::enable("SeTcbPrivilege") {
        tracing::warn!("SeTcbPrivilege could not be enabled; WTSQueryUserToken will likely fail");
    }
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

    // CreateProcessAsUserW needs both assignment privileges enabled on the
    // caller's token; LocalSystem holds them present-but-disabled.
    let assign = crate::adapters::driven::privileges::enable("SeAssignPrimaryTokenPrivilege");
    let quota = crate::adapters::driven::privileges::enable("SeIncreaseQuotaPrivilege");
    if !assign || !quota {
        tracing::warn!(
            assign,
            quota,
            "primary-token privileges could not be enabled; CreateProcessAsUserW will likely fail"
        );
    }

    // The command line is ONE space-joined, NUL-terminated string — the
    // child's parser reads `lpCommandLine` up to the first NUL, so every
    // element must be present there. (The historical NUL-joined buffer — the
    // environment-block format — silently dropped every argument after the
    // program.) `lpApplicationName` is set, so the program itself is exact;
    // the first command-line element is its quoting for the child's argv[0].
    let mut cmdline_text = quote(&spec.path);
    for arg in &spec.args {
        cmdline_text.push(' ');
        cmdline_text.push_str(&quote(arg));
    }
    let mut cmdline = wide_null(&cmdline_text);
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::quote;

    /// Test-only MSVCRT argv splitter — the inverse of [`quote`], i.e. what
    /// the launched child's parser sees (same helper as the app launcher's
    /// round-trip test).
    fn split(line: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut backslashes = 0_usize;
        let mut started = false;
        for ch in line.chars() {
            match ch {
                '\\' => backslashes += 1,
                '"' => {
                    current.extend(std::iter::repeat_n('\\', backslashes / 2));
                    if backslashes % 2 == 1 {
                        current.push('"');
                    } else {
                        in_quotes = !in_quotes;
                    }
                    backslashes = 0;
                    started = true;
                }
                ' ' | '\t' if !in_quotes => {
                    current.extend(std::iter::repeat_n('\\', backslashes));
                    backslashes = 0;
                    if started || !current.is_empty() {
                        out.push(std::mem::take(&mut current));
                    }
                    started = false;
                }
                other => {
                    current.extend(std::iter::repeat_n('\\', backslashes));
                    backslashes = 0;
                    current.push(other);
                    started = true;
                }
            }
        }
        current.extend(std::iter::repeat_n('\\', backslashes));
        if started || !current.is_empty() {
            out.push(current);
        }
        out
    }

    /// Build the command line exactly like `launch_blocking` does.
    fn build_line(path: &str, args: &[String]) -> String {
        let mut line = quote(path);
        for arg in args {
            line.push(' ');
            line.push_str(&quote(arg));
        }
        line
    }

    #[test]
    fn command_line_round_trips_through_child_parser_rules() {
        // The built command line must split back into exactly the elements
        // meant: the historical NUL-joined buffer dropped every argument after
        // the program (CreateProcessAsUserW reads up to the first NUL), which
        // voided non-exe targets and starved the user actor of its nonce.
        let cases: Vec<(String, Vec<String>)> = vec![
            ("C:\\Tools\\secoutfall-user-actor.exe".to_owned(), vec![]),
            (
                // The user-actor launch: nonce args must survive.
                "C:\\Tools\\secoutfall-user-actor.exe".to_owned(),
                vec!["--nonce".to_owned(), "0123abcd".to_owned()],
            ),
            (
                // The shell-association shape: interpreter + document + flag.
                "C:\\Windows\\System32\\wscript.exe".to_owned(),
                vec!["C:\\Users\\v\\sample.js".to_owned(), "-q".to_owned()],
            ),
            (
                "C:\\Program Files\\App\\run as.exe".to_owned(),
                vec![
                    "--flag".to_owned(),
                    "v 1".to_owned(),
                    "a\"b".to_owned(),
                    "C:\\dir\\".to_owned(),
                ],
            ),
            ("notepad.exe".to_owned(), vec![]),
        ];
        for (program, args) in cases {
            let line = build_line(&program, &args);
            assert!(!line.contains('\0'), "embedded NUL would truncate: {line}");
            let mut expected = vec![program];
            expected.extend(args);
            assert_eq!(split(&line), expected, "line: {line}");
        }
    }
}
