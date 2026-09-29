//! Example hooking the `kernel32!Sleep` export.
//!
//! Every call is capped at one second, no matter the requested duration.

crate::hook! {
    /// Caps every `Sleep` call at one second.
    in "kernel32.dll"!Sleep as SLEEP_ORIGINAL
    fn sleep_detour(dwmilliseconds: u32) {
        println!("Expected sleep time: {dwmilliseconds}.");
        unsafe { SLEEP_ORIGINAL.call(1000) }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use windows_sys::Win32::System::Threading::Sleep;

    use super::install;

    #[test]
    fn shortens_sleep() -> anyhow::Result<()> {
        install()?;

        let requested = Duration::from_millis(3000);
        let start = Instant::now();
        // SAFETY: `Sleep` has no preconditions beyond a valid duration.
        unsafe { Sleep(3000) };
        let elapsed = start.elapsed();

        assert!(
            elapsed >= Duration::from_millis(500),
            "original was not called: {elapsed:?}"
        );
        assert!(
            elapsed < requested,
            "detour did not shorten the sleep: {elapsed:?}"
        );

        Ok(())
    }
}
