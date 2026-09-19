//! System clock port — the agent's only way to read time.
//!
//! The system clock is deliberately fake inside analysis VMs; tests inject a
//! [`super::fake_clock`-style](crate::adapters::clock_fake::FakeClock) clock so a
//! full study simulates in milliseconds.

/// Driven port: wall clock in unix milliseconds.
pub trait SystemClockPort: Send + Sync + 'static {
    /// Current wall clock, unix milliseconds (from the manipulated clock).
    fn now_ms(&self) -> i64;
}
