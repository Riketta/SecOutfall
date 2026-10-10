//! Fake driver control port: records applied policies and returns a
//! fixed stats snapshot. Platform-independent — composition tests use it
//! whenever the `driver` feature is off or the config points at a fake.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::ports::driven::driver_control::{
    DriverControlError,
    DriverControlPort,
    DriverPolicies,
    DriverStatsSnapshot,
};

/// Fake: records every `apply_policies` call (latest wins) and serves a
/// builder-configured stats snapshot.
#[derive(Default)]
pub struct FakeDriverControl {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    applied: Option<DriverPolicies>,
    stats: DriverStatsSnapshot,
    fail_policies: bool,
}

impl FakeDriverControl {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The last applied policies, if any.
    #[must_use]
    pub fn applied(&self) -> Option<DriverPolicies> {
        self.inner.lock().expect("mutex poisoned").applied.clone()
    }

    /// Configures the stats snapshot served by `query_stats`.
    pub fn set_stats(&self, stats: DriverStatsSnapshot) {
        self.inner.lock().expect("mutex poisoned").stats = stats;
    }

    /// Makes `apply_policies` fail (device-missing simulation).
    pub fn fail_policies(&self) {
        self.inner.lock().expect("mutex poisoned").fail_policies = true;
    }
}

impl DriverControlPort for FakeDriverControl {
    fn apply_policies(&self, policies: &DriverPolicies) -> Result<(), DriverControlError> {
        let mut inner = self.inner.lock().expect("mutex poisoned");
        if inner.fail_policies {
            return Err(DriverControlError::DeviceMissing);
        }
        inner.applied = Some(policies.clone());
        Ok(())
    }

    fn query_stats(&self) -> Result<DriverStatsSnapshot, DriverControlError> {
        Ok(self.inner.lock().expect("mutex poisoned").stats.clone())
    }
}
