//! Sensor materialization port (driven): the agent never pushes the configured
//! sensor path straight into the driver's injection policy. The DLL is copied
//! once per boot under a randomized name into a DACL-protected directory and
//! the copy is hash-pinned to the source — malware that watches the known
//! config path sees nothing, and a tampered/incomplete copy never arms
//! injection.
//!
//! The port speaks structured values only (no filesystem semantics leak past
//! it): `materialize(source) -> MaterializedSensor`.

/// One materialized sensor copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedSensor {
    /// NT-form path of the copy (`\??\C:\...`) — verbatim into the driver's
    /// injection policy (`LdrLoadDll` input).
    pub nt_path: String,
    /// Win32 form of the same path (logs, diagnostics).
    pub dos_path: String,
    /// SHA-256 of the copy, hex — pinned to the source before the push.
    pub sha256_hex: String,
}

/// Errors from materialization.
#[derive(Debug, thiserror::Error)]
pub enum SensorStoreError {
    /// The configured sensor DLL does not exist / is unreadable.
    #[error("sensor source missing: {0}")]
    SourceMissing(String),
    /// Copy or hashing failed midway; nothing usable was produced.
    #[error("sensor copy failed: {0}")]
    Io(String),
    /// The copy's hash differs from the source's — the source changed or was
    /// tampered with mid-copy. Injection must NOT be armed.
    #[error("sensor hash mismatch: copy {actual} != source {expected}")]
    HashMismatch {
        /// Hash of the source file.
        expected: String,
        /// Hash of the produced copy.
        actual: String,
    },
    /// Directory/DACL creation failed.
    #[error("sensor store security error: {0}")]
    Security(String),
}

/// Driven port: per-boot sensor materialization.
pub trait SensorStorePort: Send + Sync + 'static {
    /// Copies `source` into this boot's randomized, DACL-protected location
    /// and returns the hash-pinned result. Idempotent per call (each call
    /// produces a fresh randomized name — the composition root calls it once
    /// per boot).
    ///
    /// # Errors
    /// [`SensorStoreError`] — see the variants. On any error injection must
    /// stay disarmed.
    fn materialize(&self, source: &str) -> Result<MaterializedSensor, SensorStoreError>;
}
