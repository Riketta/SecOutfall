//! Current-process privilege enablement (Windows).
//!
//! `LocalSystem` carries its privileges **present-but-disabled**: `SetSystemTime`
//! needs `SeSystemtimePrivilege` enabled, `CreateProcessAsUserW` needs
//! `SeAssignPrimaryTokenPrivilege` + `SeIncreaseQuotaPrivilege`, and
//! `WTSQueryUserToken` needs `SeTcbPrivilege`. Without enablement every one of
//! those calls fails with `ERROR_PRIVILEGE_NOT_HELD` — silently degrading the
//! core study features (fake clock, interactive launches).

use windows::{
    Win32::{
        Foundation::{
            CloseHandle,
            ERROR_NOT_ALL_ASSIGNED,
            GetLastError,
            HANDLE,
            LUID,
        },
        Security::{
            AdjustTokenPrivileges,
            LUID_AND_ATTRIBUTES,
            LookupPrivilegeValueW,
            SE_PRIVILEGE_ENABLED,
            TOKEN_ADJUST_PRIVILEGES,
            TOKEN_PRIVILEGES,
            TOKEN_QUERY,
        },
        System::Threading::{
            GetCurrentProcess,
            OpenProcessToken,
        },
    },
    core::{
        HSTRING,
        PCWSTR,
    },
};

/// Enable one privilege by name on the current process token. Returns `false`
/// when the privilege is not held (or the token API fails) — never panics.
/// Callers log and continue: the subsequent API then fails with its own
/// precise Win32 error, which is the better diagnostic.
#[must_use]
pub fn enable(name: &str) -> bool {
    let mut token = HANDLE::default();
    // SAFETY: pseudo-handle for the current process + valid out-parameter.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            std::ptr::from_mut(&mut token),
        )
    };
    if opened.is_err() {
        return false;
    }

    let name_wide = HSTRING::from(name);
    let mut luid = LUID::default();
    // SAFETY: null system name (local machine) + valid name/out pointers; the
    // HSTRING outlives the call.
    let looked_up = unsafe {
        LookupPrivilegeValueW(
            None,
            PCWSTR::from_raw(name_wide.as_ptr()),
            std::ptr::from_mut(&mut luid),
        )
    };
    if looked_up.is_err() {
        // SAFETY: owned handle, closed exactly once.
        unsafe {
            let _ = CloseHandle(token);
        }
        return false;
    }

    let state = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
    };
    // The raw pointer makes the new-state lifetime explicit for the FFI call.
    let state_ptr: *const TOKEN_PRIVILEGES = std::ptr::from_ref(&state);
    // SAFETY: `state_ptr` is valid for the call and the token handle is open.
    let adjusted = unsafe { AdjustTokenPrivileges(token, false, Some(state_ptr), 0, None, None) };
    // AdjustTokenPrivileges reports success even when the privilege is not
    // held by the token; ERROR_NOT_ALL_ASSIGNED is the real verdict. Read it
    // BEFORE anything else runs — an intervening FFI call may clobber the
    // thread's last error (the review found the old order misreporting
    // not-held as held).
    // SAFETY: reads the last Win32 error of this thread.
    let not_assigned = unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED;
    // SAFETY: owned handle, closed exactly once.
    unsafe {
        let _ = CloseHandle(token);
    }
    adjusted.is_ok() && !not_assigned
}

#[cfg(test)]
mod tests {
    use super::enable;

    #[test]
    fn unknown_privilege_names_are_rejected() {
        // LookupPrivilegeValueW fails for a name the local system does not
        // know — the deterministic failure path.
        assert!(!enable("SeNoSuchPrivilegeExists"));
        assert!(!enable(""));
    }
}
