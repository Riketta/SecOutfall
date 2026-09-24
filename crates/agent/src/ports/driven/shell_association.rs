//! Shell association port — resolves non-executable targets to launch commands.
//!
//! Legacy crash (bug #7) root cause: the association command string was split
//! on spaces, crashing on single-token commands and mangling quoted paths. The
//! port returns a full, already-substituted command line; the parsing and
//! `%1` substitution live in the adapter and are unit-tested as pure logic.

use async_trait::async_trait;

/// Association lookup failures.
#[derive(Debug, thiserror::Error)]
pub enum ShellAssociationError {
    /// The extension has no registered shell-open command.
    #[error("no shell association for {0}")]
    NotFound(String),
    /// The registry yielded a command string the parser cannot interpret.
    #[error("shell association for {extension} is unusable: {detail}")]
    Unusable {
        /// The document extension that was resolved.
        extension: String,
        /// What is wrong with the registered command.
        detail: String,
    },
    /// The registry itself failed to answer.
    #[error("shell association registry I/O failed: {0}")]
    Registry(String),
}

/// Driven port: resolve a document path (e.g. `C:\sample\evil.js`) to the
/// command line Windows would run for "open" on it, with `%1`-style
/// placeholders substituted by the quoted document path.
#[async_trait]
pub trait ShellAssociationPort: Send + Sync + 'static {
    /// Resolve the launch command for a document path.
    ///
    /// # Errors
    /// [`ShellAssociationError`] — no association, unusable command, or
    /// registry I/O failure.
    async fn resolve_open_command(
        &self,
        document_path: &str,
    ) -> Result<String, ShellAssociationError>;
}
