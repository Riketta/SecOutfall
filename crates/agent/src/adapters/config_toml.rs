//! TOML config file loader — the composition root's way in.
//!
//! The hexagon receives an already-parsed `Arc<AgentConfig>`; reading and
//! validating the file is an adapter concern. Strictness is inherited from
//! the schema (`deny_unknown_fields` + cross-field `validate`): a hostile or
//! corrupted `C:\Agent.toml` fails the boot with a precise error instead of
//! silently degrading the sandbox.

use std::path::Path;

use protocol::config::{
    AgentConfig,
    ConfigError,
};

/// Config load failures.
#[derive(Debug, thiserror::Error)]
pub enum ConfigLoadError {
    /// The file could not be read (missing, unreadable, invalid UTF-8).
    #[error("config read failed ({path}): {source}")]
    Read {
        /// The attempted path, for diagnosis.
        path: std::path::PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The schema or cross-field validation rejected the document.
    #[error("config rejected: {0}")]
    Schema(#[from] ConfigError),
}

/// Load and fully validate the agent config from a TOML file.
///
/// # Errors
/// [`ConfigLoadError::Read`] on I/O failure, [`ConfigLoadError::Schema`] when
/// the document violates the schema or cross-field invariants.
pub fn load(path: &Path) -> Result<AgentConfig, ConfigLoadError> {
    let source = std::fs::read_to_string(path)
        .map_err(|source| ConfigLoadError::Read { path: path.to_path_buf(), source })?;
    let config = AgentConfig::from_toml_str(&source)?;
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn temp_toml(name: &str, contents: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("secoutfall-cfg-{}-{name}.toml", std::process::id()));
        std::fs::write(&path, contents).expect("write temp config");
        path
    }

    #[test]
    fn valid_document_loads_and_validates() {
        // TOML literal string: no escape processing, single backslashes.
        let path = temp_toml("valid", "[target]\npath = 'C:\\Samples\\evil.exe'\n");
        let config = load(&path).expect("valid config must load");
        assert_eq!(config.target.path, "C:\\Samples\\evil.exe");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn schema_violation_is_rejected() {
        let path = temp_toml("unknown", "[target]\nbogus_key = 1\n");
        let error = load(&path).expect_err("unknown key must be rejected");
        assert!(matches!(error, ConfigLoadError::Schema(_)));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn missing_file_reports_the_path() {
        let error =
            load(Path::new("Z:\\no\\such\\Agent.toml")).expect_err("missing file must fail");
        match error {
            ConfigLoadError::Read { path, .. } => {
                assert!(path.ends_with("Agent.toml"));
            }
            other @ ConfigLoadError::Schema(_) => panic!("expected Read error, got {other}"),
        }
    }
}
