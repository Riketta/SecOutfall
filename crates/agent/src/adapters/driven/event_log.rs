//! Pre-tracing failure reporting for the service: the Windows Event Log
//! first (it survives a broken config and a missing console), then an
//! append-only fallback file under the default log directory. Both are
//! best-effort — this runs when diagnostics are already half-broken, so no
//! error here can escalate.

use windows::{
    Win32::{
        Foundation::PSID,
        System::EventLog::{
            DeregisterEventSource,
            EVENTLOG_ERROR_TYPE,
            RegisterEventSourceW,
            ReportEventW,
        },
    },
    core::{
        HSTRING,
        PCWSTR,
    },
};

/// Event Log source name — matches the service name so Event Viewer groups
/// these entries with the service's SCM records.
const SOURCE_NAME: &str = "secoutfall";
/// Synthetic event id. No message DLL is registered; the text rides as the
/// entry's insert string and Event Viewer shows it after its standard
/// "description not found" notice.
const FAILURE_EVENT_ID: u32 = 1;
/// Append-only fallback file (the config's default log directory — at
/// pre-config failure time the config cannot be trusted to name one).
const FALLBACK_FILE: &str = r"C:\ProgramData\SecOutfall\logs\service-errors.log";

/// Reports one failure line to the Event Log and the fallback file.
pub fn report_failure(message: &str) {
    event_log(message);
    fallback_file(message);
}

/// Best-effort Event Log write. Any failure (source registration denied,
/// log full) is swallowed — the caller still has the fallback file.
fn event_log(message: &str) {
    let source = HSTRING::from(SOURCE_NAME);
    let text = HSTRING::from(message);
    let strings = [PCWSTR(text.as_ptr())];
    // SAFETY: `handle` is owned for this scope only; `strings` outlives the
    // ReportEventW call; the null PSID means "no user SID".
    unsafe {
        let Ok(handle) = RegisterEventSourceW(PCWSTR::null(), &source) else {
            return;
        };
        let _ = ReportEventW(
            handle,
            EVENTLOG_ERROR_TYPE,
            0,
            FAILURE_EVENT_ID,
            PSID(std::ptr::null_mut()),
            0,
            Some(&strings),
            None,
        );
        let _ = DeregisterEventSource(handle);
    }
}

/// Best-effort append under the default log directory. A missing directory
/// is created; any failure is swallowed.
fn fallback_file(message: &str) {
    use std::io::Write as _;
    let path = std::path::Path::new(FALLBACK_FILE);
    if let Some(parent) = path.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return;
    }
    let Ok(mut file) = std::fs::OpenOptions::new().append(true).create(true).open(path) else {
        return;
    };
    let unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let _ = writeln!(file, "{unix_ms}\t{message}");
}
