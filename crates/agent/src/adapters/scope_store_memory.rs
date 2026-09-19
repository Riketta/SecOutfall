//! In-memory scope repository — powers the multi-reboot simulation and tests.

use parking_lot::Mutex;

use crate::{
    domain::scope::ScopeState,
    ports::scope_repository::{
        ScopeRepository,
        ScopeRepositoryError,
    },
};

/// Volatile repository; the state simply lives in memory between "boots".
#[derive(Default)]
pub struct InMemoryScopeRepository {
    state: Mutex<ScopeState>,
}

impl InMemoryScopeRepository {
    /// Preload with an initial state (e.g. a fixed study id for assertions).
    #[must_use]
    pub fn with_state(state: ScopeState) -> Self {
        Self { state: Mutex::new(state) }
    }
}

#[async_trait::async_trait]
impl ScopeRepository for InMemoryScopeRepository {
    async fn load(&self) -> Result<ScopeState, ScopeRepositoryError> {
        Ok(self.state.lock().clone())
    }

    async fn save(&self, state: &ScopeState) -> Result<(), ScopeRepositoryError> {
        *self.state.lock() = state.clone();
        Ok(())
    }
}
