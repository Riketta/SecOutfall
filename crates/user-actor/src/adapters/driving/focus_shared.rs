//! Shared `Win32` window resolution for the focus sources (polling and
//! `WinEvent` hooks): pid, window title, process image name.

use windows::Win32::{
    Foundation::{
        CloseHandle,
        HWND,
    },
    System::Threading::{
        OpenProcess,
        PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    },
    UI::WindowsAndMessaging::{
        GetForegroundWindow,
        GetWindowTextLengthW,
        GetWindowTextW,
        GetWindowThreadProcessId,
    },
};

use crate::domain::FocusInfo;

/// Maximum window title characters kept (titles can be attacker-chosen; the
/// wire only needs a hint).
const MAX_TITLE_CHARS: usize = 512;

/// Maximum process image path characters kept.
const MAX_IMAGE_CHARS: usize = 1024;

/// Resolve the foreground window snapshot; `None` when there is no usable
/// foreground window (desktop switching, invalid handle).
#[must_use]
pub fn resolve_foreground() -> Option<FocusInfo> {
    // SAFETY: no preconditions; a default handle means "no foreground".
    let hwnd = unsafe { GetForegroundWindow() };
    if hwnd == HWND::default() {
        return None;
    }
    Some(resolve_window(hwnd))
}

/// Resolve one window handle into a [`FocusInfo`] (best-effort fields).
#[must_use]
pub fn resolve_window(hwnd: HWND) -> FocusInfo {
    let mut pid = 0_u32;
    // SAFETY: `hwnd` is a valid window handle handed to us by the OS.
    unsafe { GetWindowThreadProcessId(hwnd, Some(std::ptr::from_mut(&mut pid))) };

    FocusInfo { pid, title: window_text(hwnd), process: process_image_name(pid) }
}

/// Read the window title, clamped to [`MAX_TITLE_CHARS`].
#[must_use]
fn window_text(hwnd: HWND) -> String {
    // SAFETY: `hwnd` is a valid window handle.
    let length = unsafe { GetWindowTextLengthW(hwnd) };
    if length <= 0 {
        return String::new();
    }
    // +1 for the NUL terminator the API writes; clamp attacker-chosen sizes.
    let capacity = usize::try_from(length).map_or(MAX_TITLE_CHARS, |len| len + 1);
    let capacity = capacity.min(MAX_TITLE_CHARS);
    let mut buffer = vec![0_u16; capacity];
    // SAFETY: `buffer` is a valid UTF-16 buffer of the given length.
    let copied = unsafe { GetWindowTextW(hwnd, &mut buffer) };
    if copied <= 0 {
        return String::new();
    }
    let end = usize::try_from(copied).unwrap_or(0).min(buffer.len());
    match buffer.get(..end) {
        Some(slice) => String::from_utf16_lossy(slice),
        None => String::new(),
    }
}

/// Resolve a pid to its image name (`None` when the process is gone or the
/// path is unreadable).
#[must_use]
pub fn process_image_name(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    // SAFETY: query-limited access on an arbitrary pid; the handle is closed
    // on every path below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut buffer = vec![0_u16; MAX_IMAGE_CHARS];
    let mut length = u32::try_from(buffer.len()).unwrap_or(0);
    // SAFETY: `buffer`/`length` describe a valid writable UTF-16 buffer; the
    // handle is owned and closed after the call.
    let resolved = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buffer.as_mut_ptr()),
            std::ptr::from_mut(&mut length),
        )
    };
    // SAFETY: the handle is owned and closed exactly once.
    let _ = unsafe { CloseHandle(handle) };
    resolved.ok()?;
    let end = usize::try_from(length).ok()?.min(buffer.len());
    let slice = buffer.get(..end)?;
    if slice.is_empty() {
        return None;
    }
    // Keep only the image name (last path component), matching ETW feeds.
    String::from_utf16_lossy(slice).rsplit(['\\', '/']).next().map(ToString::to_string)
}
