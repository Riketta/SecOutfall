//! Local-run scope repository: always loads a FRESH state (every `local` run
//! is a clean session 0 — the target-launch precondition), but persists saves
//! to a JSON file so the final scope snapshot (scoped processes, observed
//! drops, timestamps) survives the run for inspection.
//!
//! Dev-grade by design: the previous run's file is never read back, so the
//! repeat-run trap of a persisted session DB cannot happen.

use crate::{
    adapters::driven::scope_store::json::JsonScopeRepository,
    domain::scope::ScopeState,
    ports::driven::scope_repository::{
        ScopeRepository,
        ScopeRepositoryError,
    },
};

/// Fresh-load, persisting scope repository for `local` mode.
pub struct LocalScopeRepository {
    inner: JsonScopeRepository,
}

impl LocalScopeRepository {
    /// Bind to one snapshot path (e.g. `local-scope.json`).
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { inner: JsonScopeRepository::new(path) }
    }
}

#[async_trait::async_trait]
impl ScopeRepository for LocalScopeRepository {
    async fn load(&self) -> Result<ScopeState, ScopeRepositoryError> {
        // Deliberately NOT reading the file back: a fresh session 0 per run.
        Ok(ScopeState::default())
    }

    async fn save(&self, state: &ScopeState) -> Result<(), ScopeRepositoryError> {
        self.inner.save(state).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use uuid::Uuid;

    use super::*;

    #[tokio::test]
    async fn load_is_always_fresh_but_save_persists_the_snapshot() {
        let path = std::env::temp_dir().join(format!(
            "secoutfall-local-scope-{}-{}.json",
            std::process::id(),
            Uuid::new_v4().simple()
        ));
        let repo = LocalScopeRepository::new(&path);

        // First "run": fresh load, save a session.
        let fresh = repo.load().await.unwrap();
        assert!(fresh.study_id.is_nil() && fresh.sessions.is_empty());
        let with_session = ScopeState {
            study_id: Uuid::from_u128(11),
            sessions: vec![crate::domain::scope::SessionRecord {
                id: 0,
                scheduled_duration_secs: Some(3),
                started_at_ms: 1,
                ended_at_ms: Some(2),
                abandoned: false,
                scoped_processes: Vec::new(),
                observed_drops: std::collections::BTreeSet::new(),
            }],
        };
        repo.save(&with_session).await.unwrap();

        // The snapshot is on disk …
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"abandoned\""), "full snapshot written");
        // … but the next run still loads fresh (no repeat-run session trap).
        let second_run = repo.load().await.unwrap();
        assert!(second_run.sessions.is_empty());

        let _ = std::fs::remove_file(&path);
    }
}
