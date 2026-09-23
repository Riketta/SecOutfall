//! Atomic JSON file scope repository (`scope.json`, temp + fsync + rename).
//!
//! Doctrine: never truncate persistent state in place. The temp file is written
//! fresh, fsynced, then renamed over the target — a crash mid-write leaves the
//! previous state intact, and a VM power bounce in the rename window cannot
//! leave a stale or empty `scope.json` (a nil study id would silently start a
//! new study).

use tokio::{
    fs,
    io::AsyncWriteExt,
};

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
        // A temp left behind by a crash must not block the fresh create below.
        match fs::remove_file(&temp).await {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(error.into());
            }
            _ => {}
        }
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&temp).await?;
        file.write_all(&bytes).await?;
        // Durability BEFORE the rename: this agent reboots the VM every
        // session, so a power bounce inside the rename window is routine —
        // without fsync it can persist an empty or stale scope DB.
        file.sync_all().await?;
        // Close the handle deterministically before renaming: on Windows the
        // rename fails while the source is still open, and tokio closes the
        // file lazily on its blocking pool.
        drop(file.into_std().await);
        fs::rename(&temp, &self.path).await?;
        // Best-effort directory fsync so the rename itself survives a power
        // loss. Not done on Windows: `File::open` on a directory fails there.
        #[cfg(unix)]
        if let Some(parent) = self.path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
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
    async fn leftover_temp_from_a_crash_does_not_block_save() {
        let path = temp_path("leftover-temp");
        fs::write(path.with_extension("json.tmp"), b"stale junk").await.unwrap();
        let repo = JsonScopeRepository::new(&path);
        let state = ScopeState { study_id: Uuid::from_u128(7), ..ScopeState::default() };

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

    #[tokio::test]
    async fn pre_abandoned_schema_still_loads_with_defaulted_field() {
        // Backward compatibility: a scope DB written before `abandoned` existed
        // (upgraded agent on an in-progress study) must parse — the field
        // defaults to false, because a persisted open session from THAT boot
        // means "running normally then", not "hard-reset leftover".
        let path = temp_path("legacy-schema");
        fs::write(
            &path,
            format!(
                "{{\"study_id\":\"{}\",\"sessions\":[{{\"id\":0,\
                 \"scheduled_duration_secs\":6000,\"started_at_ms\":1000,\
                 \"ended_at_ms\":null,\"scoped_processes\":[],\
                 \"observed_drops\":[]}}]}}",
                Uuid::from_u128(9)
            )
            .bytes()
            .collect::<Vec<u8>>(),
        )
        .await
        .unwrap();
        let repo = JsonScopeRepository::new(&path);
        let state = repo.load().await.unwrap();
        assert_eq!(state.study_id, Uuid::from_u128(9));
        let session = state.sessions.first().unwrap();
        assert!(!session.abandoned);
        assert!(session.ended_at_ms.is_none());
    }
}
