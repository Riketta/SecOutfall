//! Atomic JSON file scope repository (`scope.json`, temp + rename).
//!
//! Doctrine: never truncate persistent state in place. The temp file is written
//! fully, then renamed over the target — a crash mid-write leaves the previous
//! state intact.

use tokio::fs;

use crate::{
    domain::scope::ScopeState,
    ports::scope_repository::{
        ScopeRepository,
        ScopeRepositoryError,
    },
};

/// File-backed repository. Missing file == no study yet (default state).
pub struct JsonScopeRepository {
    path: std::path::PathBuf,
}

impl JsonScopeRepository {
    /// Repository bound to one scope DB path (e.g. `scope.json`).
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait::async_trait]
impl ScopeRepository for JsonScopeRepository {
    async fn load(&self) -> Result<ScopeState, ScopeRepositoryError> {
        match fs::read(&self.path).await {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ScopeState::default()),
            Err(error) => Err(error.into()),
        }
    }

    async fn save(&self, state: &ScopeState) -> Result<(), ScopeRepositoryError> {
        let bytes = serde_json::to_vec_pretty(state)?;
        let temp = self.path.with_extension("json.tmp");
        fs::write(&temp, bytes).await?;
        fs::rename(&temp, &self.path).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use uuid::Uuid;

    use super::*;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("secoutfall-scope-store-tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(format!("{tag}-{}.json", Uuid::new_v4()))
    }

    #[tokio::test]
    async fn missing_file_loads_default() {
        let repo = JsonScopeRepository::new(temp_path("missing"));
        let state = repo.load().await.unwrap();
        assert!(state.study_id.is_nil());
        assert!(state.sessions.is_empty());
    }

    #[tokio::test]
    async fn save_then_load_roundtrips_and_leaves_no_temp() {
        let path = temp_path("roundtrip");
        let repo = JsonScopeRepository::new(&path);
        let state = ScopeState { study_id: Uuid::from_u128(42), ..ScopeState::default() };

        repo.save(&state).await.unwrap();
        assert_eq!(repo.load().await.unwrap(), state);
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[tokio::test]
    async fn corrupted_file_is_reported_as_corrupt() {
        let path = temp_path("corrupt");
        fs::write(&path, b"{ not json").await.unwrap();
        let repo = JsonScopeRepository::new(&path);
        assert!(matches!(repo.load().await, Err(ScopeRepositoryError::Corrupt(_))));
    }
}
