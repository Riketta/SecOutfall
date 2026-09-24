//! `CreateProcessW` app launcher — the user actor already runs as the
//! interactive user, so a plain creation reaches the visible desktop.
//! Blocking FFI runs in `spawn_blocking`; the port stays async.

use std::os::windows::ffi::OsStrExt;

use async_trait::async_trait;

use crate::ports::driven::{
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

/// Quote one argv element with the MSVCRT rules `CreateProcessW`'s child
/// parser applies: backslash runs before a quote double up, a trailing
/// backslash run before the closing quote doubles. Values without specials
/// pass through unquoted.
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

/// Blocking creation; the command line is `"prog" arg1 arg2` — ONE
/// space-joined, NUL-terminated string (`CreateProcessW` reads `lpCommandLine`
/// up to the first NUL, so every element must be present there), mutable
/// buffer per the API contract. `lpApplicationName` left null so the OS
/// applies its standard search order (`System32`, `PATH`...) — scripts name
/// plain `notepad.exe`-style programs.
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

    let mut command_line = quote(program);
    for arg in args {
        command_line.push(' ');
        command_line.push_str(&quote(arg));
    }
    let mut command_line = wide_null(&command_line);
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn quoting_follows_msvcrt_rules() {
        // No specials — unquoted.
        assert_eq!(quote("notepad.exe"), "notepad.exe");
        assert_eq!(quote("C:\\Windows\\System32\\calc.exe"), "C:\\Windows\\System32\\calc.exe");
        // Emptiness and whitespace quote.
        assert_eq!(quote(""), "\"\"");
        assert_eq!(quote("a b"), "\"a b\"");
        // Embedded quotes escape; backslash runs before them double.
        assert_eq!(quote("a\"b"), "\"a\\\"b\"");
        // A trailing backslash run inside quotes doubles.
        assert_eq!(quote("a b\\"), "\"a b\\\\\"");
    }

    /// Test-only MSVCRT argv splitter — the inverse of [`quote`], i.e. what
    /// the launched child's parser sees.
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

    #[test]
    fn command_line_round_trips_through_child_parser_rules() {
        // The built command line must split back into exactly the elements
        // meant: the historical NUL-joined buffer dropped every argument
        // after the program (CreateProcessW reads up to the first NUL).
        let cases: Vec<(String, Vec<String>)> = vec![
            ("notepad.exe".to_owned(), vec![]),
            (
                "C:\\Program Files\\App\\run as.exe".to_owned(),
                vec!["--flag".to_owned(), "v 1".to_owned(), "a\"b".to_owned()],
            ),
            ("cmd.exe".to_owned(), vec!["/c".to_owned(), "C:\\dir\\".to_owned()]),
        ];
        for (program, args) in cases {
            let mut line = quote(&program);
            for arg in &args {
                line.push(' ');
                line.push_str(&quote(arg));
            }
            let mut expected = vec![program];
            expected.extend(args);
            assert_eq!(split(&line), expected, "line: {line}");
        }
    }
}
