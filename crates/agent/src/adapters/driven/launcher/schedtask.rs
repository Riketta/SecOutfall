//! `SchedTaskLauncher` — the legacy scheduled-task launch path (the reason
//! `LaunchMechanism::SchedTask` exists).
//!
//! Flow per launch (legacy `ProcessLauncher.StartProcessAsSchedulerTask`):
//! create an `ONEVENT` scheduled task firing on Application-log `EventID 777`,
//! running the configured run-as helper (`platform.runas_utility_path`) in
//! the console user's security context at run level HIGHEST, then `/Run` it
//! and `/Delete` it — the helper is what detonates the target from there.
//!
//! Improvements over the legacy flow, kept deliberate:
//! - the console user comes from WTS (`WTSQuerySessionInformationW`), not
//!   WMI owner parsing — the "NO OWNER" crash class (bug #7) cannot recur;
//! - the task action line quotes every element by the MSVCRT rules the
//!   `CreateProcess` parser applies when the task fires — legacy interpolated
//!   raw strings and skipped escaping entirely (its own TODO);
//! - NO manual `/TR` escaping on top: the legacy `\` → `\\` doubling was a
//!   workaround for `UseShellExecute` raw concatenation, and would corrupt
//!   paths under our spawn — [`std::process::Command`] argv-quotes each
//!   element itself and `schtasks` parses standard argv, so the action line
//!   round-trips byte-exact;
//! - each invocation has the legacy 15 s budget, but as a real timeout; exit
//!   codes and stderr surface as typed [`LaunchError`]s instead of log lines;
//! - the task definition is deleted even when `/Run` fails — a stale task
//!   must not fire on the next `EventID 777` the VM happens to see.
//!
//! The run-as helper itself is an external binary by contract; this adapter
//! only orchestrates the task engine around it.
//!
//! Not unit-testable end-to-end (needs a real interactive session + the
//! helper); the command-line construction is pure and covered below. The
//! FFI/`schtasks` paths are VM-soak material.

use std::time::Duration;

use async_trait::async_trait;

use crate::ports::driven::process_launcher::{
    LaunchError,
    LaunchOutcome,
    LaunchSpec,
    ProcessLauncherPort,
};

/// Scheduled-task name; `/F` overwrites any stale definition from a prior
/// crash, and `/Delete` removes it after the run.
const TASK_NAME: &str = "SecOutfallLaunch";
/// Per-schtasks-invocation budget (legacy parity).
const SCHTASKS_BUDGET: Duration = Duration::from_secs(15);
/// The trigger: Application log, `EventID 777`.
const EVENT_FILTER: &str = "*[System/EventID=777]";

/// Scheduled-task launcher over the run-as helper.
#[derive(Debug, Clone)]
pub struct SchedTaskLauncher {
    /// Run-as helper path, as configured (`platform.runas_utility_path`).
    helper_path: String,
}

impl SchedTaskLauncher {
    /// Assemble the adapter around the configured helper.
    #[must_use]
    pub fn new(helper_path: impl Into<String>) -> Self {
        Self { helper_path: helper_path.into() }
    }
}

/// Quote one argv element with the standard Windows command-line rules
/// (backslash runs before quotes double up; a trailing backslash run before
/// the closing quote doubles — `C:\dir\` must survive as `C:\dir\`).
/// Values without specials pass through unquoted, like the MSVCRT parser
/// expects.
fn quote_argument(value: &str) -> String {
    let needs_quotes =
        value.is_empty() || value.chars().any(|c| matches!(c, ' ' | '\t' | '\n' | '\u{0B}' | '"'));
    if !needs_quotes {
        return value.to_owned();
    }
    let mut quoted = String::with_capacity(value.len() + 3);
    quoted.push('"');
    let mut backslashes = 0_usize;
    for ch in value.chars() {
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

/// The task action command line: `<helper> --path <target> -- <args...>`
/// (the helper's CLI contract, legacy `RunAsSystem`). This exact string is
/// stored as the task action and parsed by `CreateProcess` when it fires.
fn action_command_line(helper: &str, spec: &LaunchSpec) -> String {
    let mut line = quote_argument(helper);
    line.push_str(" --path ");
    line.push_str(&quote_argument(&spec.path));
    line.push_str(" --");
    for arg in &spec.args {
        line.push(' ');
        line.push_str(&quote_argument(arg));
    }
    line
}

/// One `schtasks` invocation with the legacy budget; exit codes and a
/// truncated stderr surface in the error.
async fn run_schtasks(arguments: &[&str]) -> Result<(), LaunchError> {
    let stage = arguments.first().copied().unwrap_or("?");
    let output = tokio::time::timeout(SCHTASKS_BUDGET, async {
        tokio::process::Command::new("schtasks")
            .args(arguments)
            .stdin(std::process::Stdio::null())
            .output()
            .await
    })
    .await
    .map_err(|_| LaunchError::Spawn(format!("schtasks {stage} timed out after 15 s")))?
    .map_err(|error| LaunchError::Spawn(format!("schtasks {stage} spawn failed: {error}")))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).chars().take(300).collect::<String>();
    Err(LaunchError::Spawn(format!("schtasks {stage} failed ({}): {stderr}", output.status)))
}

/// Console-session user as `DOMAIN\user` (bare user when no domain) — the
/// `/RU` value. `None` = no interactive session to launch into.
fn console_session_user() -> Option<String> {
    use windows::Win32::System::RemoteDesktop::{
        WTSDomainName,
        WTSGetActiveConsoleSessionId,
        WTSUserName,
    };

    // SAFETY: no preconditions — returns the current console session id.
    let session_id = unsafe { WTSGetActiveConsoleSessionId() };
    let user = query_wts_string(session_id, WTSUserName)?;
    if user.is_empty() {
        return None;
    }
    let domain = query_wts_string(session_id, WTSDomainName).unwrap_or_default();
    if domain.is_empty() { Some(user) } else { Some(format!("{domain}\\{user}")) }
}

/// Read one WTS string property; `None` when the query fails (e.g. no such
/// session). The returned buffer is freed exactly once.
fn query_wts_string(
    session_id: u32,
    class: windows::Win32::System::RemoteDesktop::WTS_INFO_CLASS,
) -> Option<String> {
    use windows::{
        Win32::System::RemoteDesktop::{
            WTSFreeMemory,
            WTSQuerySessionInformationW,
        },
        core::PWSTR,
    };

    let mut buffer = PWSTR::null();
    let mut bytes = 0_u32;
    // SAFETY: `buffer`/`bytes` are initialized out-params; the API allocates
    // the buffer, which is freed below on success.
    unsafe {
        WTSQuerySessionInformationW(
            windows::Win32::System::RemoteDesktop::WTS_CURRENT_SERVER_HANDLE,
            session_id,
            class,
            std::ptr::from_mut(&mut buffer),
            std::ptr::from_mut(&mut bytes),
        )
        .ok()?;
    }
    // SAFETY: on success the buffer is a NUL-terminated wide string.
    let value = unsafe { buffer.to_string() }.unwrap_or_default();
    // SAFETY: allocated by WTSQuerySessionInformationW; freed exactly once.
    unsafe { WTSFreeMemory(buffer.as_ptr().cast()) };
    Some(value)
}

#[async_trait]
impl ProcessLauncherPort for SchedTaskLauncher {
    async fn launch(&self, spec: &LaunchSpec) -> Result<LaunchOutcome, LaunchError> {
        let Some(user) = console_session_user() else {
            return Err(LaunchError::NoInteractiveSession);
        };
        let action = action_command_line(&self.helper_path, spec);

        run_schtasks(&[
            "/Create",
            "/SC",
            "ONEVENT",
            "/EC",
            "Application",
            "/MO",
            EVENT_FILTER,
            "/RU",
            user.as_str(),
            "/RL",
            "HIGHEST",
            "/TN",
            TASK_NAME,
            "/TR",
            action.as_str(),
            "/F",
        ])
        .await?;

        let run = run_schtasks(&["/Run", "/I", "/TN", TASK_NAME]).await;
        // Cleanup regardless of the run outcome; a leftover definition would
        // fire on the next Application-log EventID 777. A failed delete never
        // masks the launch result.
        if let Err(error) = run_schtasks(&["/Delete", "/TN", TASK_NAME, "/F"]).await {
            tracing::warn!(%error, "schtasks delete failed; task definition left behind");
        }
        run?;

        // The task engine reports no pid through this mechanism.
        Ok(LaunchOutcome { pid: None })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn spec(path: &str, args: &[&str]) -> LaunchSpec {
        LaunchSpec {
            path: path.to_owned(),
            args: args.iter().map(ToString::to_string).collect(),
            working_dir: None,
        }
    }

    #[test]
    fn quoting_follows_windows_rules() {
        // No specials — passed through unquoted, like the MSVCRT parser
        // expects; trailing backslashes are only special inside quotes.
        assert_eq!(quote_argument("plain.exe"), "plain.exe");
        assert_eq!(quote_argument("C:\\dir\\file.exe"), "C:\\dir\\file.exe");
        assert_eq!(quote_argument("C:\\dir\\"), "C:\\dir\\");
        // Quoting kicks in for emptiness, whitespace, and quotes.
        assert_eq!(quote_argument(""), "\"\"");
        assert_eq!(quote_argument("with space"), "\"with space\"");
        // Embedded quotes are escaped; backslash runs before them double.
        assert_eq!(quote_argument("a\"b"), "\"a\\\"b\"");
        // Quoted value with a trailing backslash: the run doubles.
        assert_eq!(quote_argument("a b\\"), "\"a b\\\\\"");
    }

    #[test]
    fn action_line_wraps_the_helper_contract() {
        let line = action_command_line(
            "C:\\Tools\\runas.exe",
            &spec("C:\\Targets\\evil.exe", &["-k", "v 1"]),
        );
        assert_eq!(line, "C:\\Tools\\runas.exe --path C:\\Targets\\evil.exe -- -k \"v 1\"");
    }

    /// Test-only MSVCRT argv splitter — the inverse of the quoting rules,
    /// i.e. exactly what `CreateProcess` does to the stored task action when
    /// it fires.
    fn split_command_line(line: &str) -> Vec<String> {
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
                        current.push('"'); // escaped quote, quoting continues
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
    fn hostile_action_lines_round_trip_through_createprocess_rules() {
        // A malware-chosen target path and args — spaces, quotes, backslash
        // runs, trailing backslashes. The stored action line must split back
        // into exactly the elements we meant: the helper gets what we meant
        // to give it, nothing more, nothing less.
        let cases: Vec<(String, LaunchSpec)> = vec![
            (
                "C:\\Tools\\run as.exe".to_owned(),
                spec("C:\\wei rd\\ta\"rget.exe", &["--flag\\path"]),
            ),
            ("helper.exe".to_owned(), spec("C:\\evil\\", &["-x", "", "a\"b", "\\\\server\\share"])),
            ("h.exe".to_owned(), spec("t.exe", &["\"quoted\"", "\\", "\\\\"])),
        ];
        for (helper, spec) in cases {
            let action = action_command_line(&helper, &spec);
            let mut expected = vec![helper, "--path".to_owned(), spec.path, "--".to_owned()];
            expected.extend(spec.args.iter().cloned());
            assert_eq!(split_command_line(&action), expected, "action: {action}");
        }
    }
}
