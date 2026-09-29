//! Example hooking the `ntdll!NtDelayExecution` export.
//!
//! Relative delays are logged in milliseconds before passing through.

crate::hook! {
    /// Logs relative delays before passing them through unchanged.
    in "ntdll.dll"!NtDelayExecution as NT_DELAY_EXECUTION_ORIGINAL
    fn nt_delay_execution_detour(alertable: bool, delay_interval: *const i64) -> i32 {
        // SAFETY: the delay interval is valid while the call is running.
        let delay = unsafe { *delay_interval };

        // Negative - relative, positive - absolute timestamp.
        if delay.is_negative() {
            println!("Sleep: {} ms.", delay / -10_000);
        }

        unsafe { NT_DELAY_EXECUTION_ORIGINAL.call(alertable, delay_interval) }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::install;
    use crate::hooking::get_module_symbol_address;

    #[test]
    fn passes_delay_through() -> anyhow::Result<()> {
        install()?;

        let address = get_module_symbol_address(Some("ntdll.dll"), "NtDelayExecution")?;
        // SAFETY: the address belongs to the exported function.
        let nt_delay_execution: unsafe extern "system" fn(bool, *const i64) -> i32 =
            unsafe { core::mem::transmute(address) };

        // 100 ms in 100 ns units, negative for a relative delay.
        let delay_interval: i64 = -1_000_000;
        let start = Instant::now();
        // SAFETY: the delay interval is valid while the call is running.
        let status = unsafe { nt_delay_execution(false, &raw const delay_interval) };
        let elapsed = start.elapsed();

        assert_eq!(status, 0, "NtDelayExecution failed");
        assert!(
            elapsed >= Duration::from_millis(100),
            "delay was not passed through: {elapsed:?}"
        );

        Ok(())
    }
}
