//! Fake shell-association resolver: an extension → command map for tests, and
//! the always-`NotFound` stand-in for production builds without the
//! `associations` feature (a non-exe target then fails to launch with a
//! precise, logged error instead of silently doing nothing).

use std::collections::HashMap;

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::{
    domain::shell_command::substitute_command,
    ports::shell_association::{
        ShellAssociationError,
        ShellAssociationPort,
    },
};

/// Map-based resolver; unknown extensions resolve to [`ShellAssociationError::NotFound`].
#[derive(Debug, Default)]
pub struct FakeShellAssociation {
    /// Extension (lowercase, with dot) → open command template.
    commands: Mutex<HashMap<String, String>>,
}

impl FakeShellAssociation {
    /// Resolver with an empty map (everything `NotFound`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register one association.
    pub fn register(&self, extension: &str, command: &str) {
        self.commands.lock().insert(extension.to_lowercase(), command.to_owned());
    }
}

fn extension_of(document: &str) -> Option<String> {
    let extension = std::path::Path::new(document).extension()?.to_str()?;
    Some(format!(".{}", extension.to_lowercase()))
}

#[async_trait]
impl ShellAssociationPort for FakeShellAssociation {
    async fn resolve_open_command(
        &self,
        document_path: &str,
    ) -> Result<String, ShellAssociationError> {
        let Some(extension) = extension_of(document_path) else {
            return Err(ShellAssociationError::NotFound(document_path.to_owned()));
        };
        let command = self
            .commands
            .lock()
            .get(&extension)
            .cloned()
            .ok_or_else(|| ShellAssociationError::NotFound(document_path.to_owned()))?;
        // Contract parity with the registry adapter: the port returns the
        // command with placeholders already substituted.
        substitute_command(&command, document_path)
            .map_err(|_| ShellAssociationError::NotFound(document_path.to_owned()))
    }
}

/// Production stand-in when the registry adapter is not compiled in: every
/// resolution fails with a typed, explanatory error.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableShellAssociation;

#[async_trait]
impl ShellAssociationPort for UnavailableShellAssociation {
    async fn resolve_open_command(
        &self,
        document_path: &str,
    ) -> Result<String, ShellAssociationError> {
        Err(ShellAssociationError::Registry(format!(
            "shell associations are unavailable (build with --features associations to resolve {document_path})"
        )))
    }
}
