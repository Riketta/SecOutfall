//! System clock port — the agent's only way to read time.
//!
//! The system clock is deliberately fake inside analysis VMs; tests inject a
//! [`FakeClock`](crate::adapters::driven::clock::fake::FakeClock) so a full study
//! simulates in milliseconds.
//!
//! Time *manipulation* (setting the fake timestamp / applying the finalize
//! offset) is a separate port: reading happens everywhere, writing happens in
//! the finalizer only, and the writer is platform-specific.

/// Driven port: wall clock in unix milliseconds.
pub trait SystemClockPort: Send + Sync + 'static {
    /// Current wall clock, unix milliseconds (from the manipulated clock).
    fn now_ms(&self) -> i64;
}

/// Clock manipulation failures.
#[derive(Debug, thiserror::Error)]
pub enum ClockShiftError {
    /// The platform adapter is not compiled in (or not supported here).
    #[error("clock manipulation unavailable: {0}")]
    Unavailable(String),
    /// The OS refused the change.
    #[error("clock manipulation failed: {0}")]
    System(String),
}

/// Driven port: force the wall clock to a specific unix-millisecond value.
///
/// Legacy bug #11 fixed at the port level: implementers must do all math in
/// UTC — the value set here is absolute unix time, never local-wall arithmetic.
#[async_trait::async_trait]
pub trait ClockShiftPort: Send + Sync + 'static {
    /// Set the system clock. The next [`SystemClockPort::now_ms`] must read
    /// (at least) this value.
    ///
    /// # Errors
    /// [`ClockShiftError`] — unavailable adapter or OS refusal.
    async fn set_unix_ms(&self, unix_ms: i64) -> Result<(), ClockShiftError>;
}
