//! Driver control port (driven): the agent's policy + status channel to the
//! kernel driver. The composition root pushes the `[driver]` config through
//! this port at startup; the real adapter wraps `DeviceIoControl` against
//! `\\.\secoutfall` (feature `driver`), the fake records calls for tests.
//!
//! Policies mirror the driver's input blobs — the adapter serializes; the
//! port speaks structured values only (no wire types leak past this port).

use std::collections::HashMap;

/// Injection policy: sensor DLL path + extra per-process exclusions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InjectionPolicy {
    /// Sensor DLL path (verbatim to `LdrLoadDll` — NT form recommended).
    pub sensor_path: String,
    /// Extra per-process exclusion names (with extension).
    pub exclusions: Vec<String>,
}

/// Drop-capture policy: target directory + extension filter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DropPolicy {
    /// Drops directory in normalized NT form.
    pub dir: String,
    /// Extension filter (with the dot; empty = all files).
    pub extensions: Vec<String>,
}

/// Protection policy: process names with `ObCallbacks` handle-stripping.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtectionPolicy {
    /// Protected image names (with extension).
    pub names: Vec<String>,
}

/// Every policy in one application — atomic from the agent's perspective
/// (the adapter serializes each blob; order between them is irrelevant).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DriverPolicies {
    /// Sensor injection (disabled when the path is empty).
    pub injection: Option<InjectionPolicy>,
    /// Drop capture (disabled when the dir is empty).
    pub drops: Option<DropPolicy>,
    /// Process protection (disabled when the name list is empty).
    pub protection: Option<ProtectionPolicy>,
}

/// Loss/health snapshot from the driver (`GET_STATS`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DriverStatsSnapshot {
    /// Control-queue depth.
    pub queue_depth: u32,
    /// Control-queue capacity.
    pub queue_capacity: u32,
    /// File-queue depth.
    pub file_queue_depth: u32,
    /// File-queue capacity.
    pub file_queue_capacity: u32,
    /// Drops-queue depth.
    pub drops_queue_depth: u32,
    /// Drops-queue capacity.
    pub drops_queue_capacity: u32,
    /// Last assigned per-boot sequence.
    pub sequence: u64,
    /// Control-class drop-oldest events.
    pub queue_overwritten: u64,
    /// Pool allocation failures in callbacks.
    pub alloc_failures: u64,
    /// Drain-side oversized skip+count.
    pub oversized_skipped: u64,
    /// Identity lookups for unknown pids.
    pub identity_misses: u64,
    /// File-class drop-oldest events.
    pub files_overwritten: u64,
    /// File-name query failures (skipped records).
    pub file_name_queries_failed: u64,
    /// Write-noise heuristic skips.
    pub noise_writes_skipped: u64,
    /// Drops-class stop-collect events (queue full).
    pub drops_stopped: u64,
    /// Capture attempts above `PASSIVE_LEVEL`.
    pub drops_missed_busy: u64,
    /// Hard-link failures that fell back to copy.
    pub drops_link_failed: u64,
    /// Stream-copy failures at cleanup.
    pub drops_copy_failed: u64,
    /// APCs queued onto first threads.
    pub injections_queued: u64,
    /// Injection allocation / thread-gone / queue failures.
    pub injections_failed: u64,
    /// Nonce echoes accepted.
    pub sensors_registered: u64,
    /// Challenge/register denials.
    pub sensors_rejected: u64,
    /// Ring slots promoted to records.
    pub sensor_events_drained: u64,
    /// Slots skipped: torn, stale or garbage.
    pub sensor_events_dropped: u64,
    /// Currently registered sensors with rings.
    pub sensor_rings_active: u32,
    /// Handle-open attempts stripped.
    pub protections_stripped: u64,
    /// Attempts allowed (trusted caller).
    pub protection_trusted: u64,
}

/// The device DACL the agent pushes: the driver's compiled SDDL
/// (SYSTEM + Administrators, `GA`) plus, when a console-session user exists,
/// a generic-all ACE for that user — the sensor reaches the device from a
/// non-elevated target. Pure: the adapter does the Win32 conversion.
#[must_use]
pub fn device_security_sddl(console_user_sid: Option<&str>) -> String {
    match console_user_sid {
        Some(sid) => format!(r"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid})"),
        None => r"D:P(A;;GA;;;SY)(A;;GA;;;BA)".to_owned(),
    }
}

/// Errors from the control device.
#[derive(Debug, thiserror::Error)]
pub enum DriverControlError {
    /// The control device is not present (driver not installed/started).
    #[error("driver device not found: \\\\.\\secoutfall")]
    DeviceMissing,
    /// The driver rejected a policy (invalid blob or resource failure).
    #[error("driver rejected policy: {0}")]
    Rejected(String),
    /// Any other Win32 failure, message carries the context.
    #[error("driver control io error: {0}")]
    Io(String),
}

/// Driven port: agent → driver policy + status channel.
pub trait DriverControlPort: Send + Sync + 'static {
    /// Applies all policies. Idempotent; safe to re-send on config reload.
    ///
    /// # Errors
    /// [`DriverControlError`] when the device is missing or a policy is
    /// rejected.
    fn apply_policies(&self, policies: &DriverPolicies) -> Result<(), DriverControlError>;

    /// Replaces the device object's DACL. `sddl` is an SDDL string; the
    /// adapter converts it to a self-relative descriptor. Idempotent.
    ///
    /// Used to grant the console-session user access so the injected sensor
    /// (running in the analysis user's context) can reach the device for its
    /// challenge/register handshake from a non-elevated target.
    ///
    /// # Errors
    /// [`DriverControlError`] when the device is missing or the driver
    /// rejects the descriptor.
    fn apply_device_security(&self, sddl: &str) -> Result<(), DriverControlError>;

    /// Queries the loss/health snapshot.
    ///
    /// # Errors
    /// [`DriverControlError`] when the device is missing or the stats blob
    /// is malformed.
    fn query_stats(&self) -> Result<DriverStatsSnapshot, DriverControlError>;

    /// Loss counters keyed for reporting (default: flattened snapshot).
    ///
    /// # Errors
    /// [`DriverControlError`] from [`Self::query_stats`].
    fn loss_counters(&self) -> Result<HashMap<String, u64>, DriverControlError> {
        let stats = self.query_stats()?;
        let mut map = HashMap::new();
        map.insert("queue_overwritten".to_owned(), stats.queue_overwritten);
        map.insert("alloc_failures".to_owned(), stats.alloc_failures);
        map.insert("oversized_skipped".to_owned(), stats.oversized_skipped);
        map.insert("identity_misses".to_owned(), stats.identity_misses);
        map.insert("files_overwritten".to_owned(), stats.files_overwritten);
        map.insert("file_name_queries_failed".to_owned(), stats.file_name_queries_failed);
        map.insert("noise_writes_skipped".to_owned(), stats.noise_writes_skipped);
        map.insert("drops_stopped".to_owned(), stats.drops_stopped);
        map.insert("drops_missed_busy".to_owned(), stats.drops_missed_busy);
        map.insert("drops_link_failed".to_owned(), stats.drops_link_failed);
        map.insert("drops_copy_failed".to_owned(), stats.drops_copy_failed);
        map.insert("injections_queued".to_owned(), stats.injections_queued);
        map.insert("injections_failed".to_owned(), stats.injections_failed);
        map.insert("sensors_registered".to_owned(), stats.sensors_registered);
        map.insert("sensors_rejected".to_owned(), stats.sensors_rejected);
        map.insert("sensor_events_drained".to_owned(), stats.sensor_events_drained);
        map.insert("sensor_events_dropped".to_owned(), stats.sensor_events_dropped);
        map.insert("protections_stripped".to_owned(), stats.protections_stripped);
        map.insert("protection_trusted".to_owned(), stats.protection_trusted);
        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn device_sddl_covers_system_admins_and_optional_console_user() {
        assert_eq!(device_security_sddl(None), r"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        assert_eq!(
            device_security_sddl(Some("S-1-5-21-1004336348-1176667385-1801674531-1001")),
            r"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;S-1-5-21-1004336348-1176667385-1801674531-1001)"
        );
        // Degenerate input cannot break the builder's shape; the driver's
        // SD validation stays the real gate.
        assert!(device_security_sddl(Some("")).ends_with("(A;;GA;;;)"));
    }
}
