//! Clock manipulation adapters: the Windows `SetSystemTime` shifter and the
//! explicit stand-in for builds without the `time_shift` feature.
//!
//! Legacy bug #11 fix by construction: all math is absolute unix
//! milliseconds → FILETIME (UTC); local-wall time is never involved.

use async_trait::async_trait;

use crate::ports::driven::clock::{
    ClockShiftError,
    ClockShiftPort,
};

/// Explicit stand-in when clock manipulation is not compiled in: every call
/// fails with a typed, explanatory error — the finalizer logs it and the
/// study continues with drifting time (never a panic, never a silent skip).
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableClockShifter;

#[async_trait]
impl ClockShiftPort for UnavailableClockShifter {
    async fn set_unix_ms(&self, _unix_ms: i64) -> Result<(), ClockShiftError> {
        Err(ClockShiftError::Unavailable("build with --features time_shift on Windows".to_owned()))
    }
}

/// Windows `SetSystemTime` implementation (feature `time_shift`).
///
/// Requires the clock-set privilege — the agent runs as `LocalSystem` inside
/// the analysis VM, where this is the whole point.
#[cfg(all(windows, feature = "time_shift"))]
pub mod windows_shifter {
    use async_trait::async_trait;
    use windows::Win32::{
        Foundation::{
            FILETIME,
            SYSTEMTIME,
        },
        System::{
            SystemInformation::SetSystemTime,
            Time::FileTimeToSystemTime,
        },
    };

    use crate::ports::driven::clock::{
        ClockShiftError,
        ClockShiftPort,
    };

    /// 100 ns intervals between 1601-01-01 and 1970-01-01.
    const UNIX_EPOCH_FILETIME_100NS: i64 = 116_444_736_000_000_000;

    /// Windows clock shifter.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct WindowsClockShifter;

    impl WindowsClockShifter {
        /// Assemble the adapter.
        #[must_use]
        pub const fn new() -> Self {
            Self
        }
    }

    /// unix milliseconds → FILETIME (100 ns ticks since 1601).
    fn unix_ms_to_filetime(unix_ms: i64) -> Result<i64, ClockShiftError> {
        unix_ms
            .checked_mul(10_000)
            .and_then(|ticks| ticks.checked_add(UNIX_EPOCH_FILETIME_100NS))
            .ok_or_else(|| ClockShiftError::System(format!("timestamp {unix_ms} out of range")))
    }

    fn split_filetime(file_time: i64) -> Result<FILETIME, ClockShiftError> {
        let low = u32::try_from(file_time & 0xFFFF_FFFF)
            .map_err(|error| ClockShiftError::System(error.to_string()))?;
        let high = u32::try_from((file_time >> 32) & 0xFFFF_FFFF)
            .map_err(|error| ClockShiftError::System(error.to_string()))?;
        Ok(FILETIME { dwLowDateTime: low, dwHighDateTime: high })
    }

    fn set_blocking(unix_ms: i64) -> Result<(), ClockShiftError> {
        let target = split_filetime(unix_ms_to_filetime(unix_ms)?)?;
        let mut system_time = SYSTEMTIME::default();
        // SAFETY: all pointers reference initialized locals owned by this call.
        unsafe {
            FileTimeToSystemTime(&raw const target, &raw mut system_time)
                .map_err(|error| ClockShiftError::System(error.to_string()))?;
            SetSystemTime(&raw const system_time)
                .map_err(|error| ClockShiftError::System(error.to_string()))?;
        }
        Ok(())
    }

    #[async_trait]
    impl ClockShiftPort for WindowsClockShifter {
        async fn set_unix_ms(&self, unix_ms: i64) -> Result<(), ClockShiftError> {
            // Microseconds of blocking work — keep the async executor honest.
            tokio::task::spawn_blocking(move || set_blocking(unix_ms))
                .await
                .map_err(|error| ClockShiftError::System(error.to_string()))?
        }
    }

    /// Sanity check for the epoch math (UTC by construction — bug #11).
    #[cfg(test)]
    mod tests {
        #![allow(clippy::unwrap_used, clippy::expect_used)]

        use super::*;

        #[test]
        fn unix_epoch_maps_to_the_filetime_epoch_constant() {
            assert_eq!(unix_ms_to_filetime(0).unwrap(), UNIX_EPOCH_FILETIME_100NS);
            assert_eq!(unix_ms_to_filetime(1).unwrap(), UNIX_EPOCH_FILETIME_100NS + 10_000);
        }

        #[test]
        fn filetime_split_roundtrips_through_low_and_high() {
            let ft = unix_ms_to_filetime(1_465_182_366_000).unwrap();
            let split = split_filetime(ft).unwrap();
            let joined = i64::from(split.dwHighDateTime) << 32 | i64::from(split.dwLowDateTime);
            assert_eq!(joined, ft);
        }
    }
}
