//! `NtDelayExecution` hook: evasion-timing signal (long sleeps between
//! malicious stages). Observe-only — the delay passes through untouched.

#![allow(clippy::too_many_arguments, clippy::cast_sign_loss, clippy::cast_lossless, clippy::doc_markdown)]

crate::hook! {
    /// Reports delay calls, passes them through unchanged.
    in "ntdll.dll"!NtDelayExecution as NTDELAYEXECUTION_ORIGINAL
    fn ntdelayexecution_detour(alertable: u8, delay_interval: *const i64) -> i32 {
        crate::sensor::emit(
            crate::sensor::api::NT_DELAY_EXECUTION,
            [u64::from(alertable), delay_interval as u64, 0, 0],
        );
        unsafe { NTDELAYEXECUTION_ORIGINAL.call(alertable, delay_interval) }
    }
}
