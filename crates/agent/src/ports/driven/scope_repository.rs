//! Scope persistence port — the only durable state inside the VM.

use async_trait::async_trait;

use crate::domain::scope::ScopeState;

/// Persistence failures.
#[derive(Debug, thiserror::Error)]
pub enum ScopeRepositoryError {
    /// File content does not deserialize into the schema.
    #[error("scope state is corrupted: {0}")]
    Corrupt(#[from] serde_json::Error),
    /// Filesystem I/O failed.
    #[error("scope state I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Driven port: atomic scope state storage (temp + rename; never truncate).
#[async_trait]
pub trait ScopeRepository: Send + Sync + 'static {
    /// Load persisted state; a missing file yields the default (nil study id =
    /// "no study yet").
    ///
    /// # Errors
    /// [`ScopeRepositoryError`] on I/O or corruption.
    async fn load(&self) -> Result<ScopeState, ScopeRepositoryError>;

    /// Persist state atomically.
    ///
    /// # Errors
    /// [`ScopeRepositoryError`] on I/O failure.
    async fn save(&self, state: &ScopeState) -> Result<(), ScopeRepositoryError>;
}
