//! Fake driver control port: records applied policies, device-security pushes
//! and returns a fixed stats snapshot. Platform-independent — tests and
//! non-driver builds use it whenever the real device is absent.

use std::collections::HashMap;

use parking_lot::Mutex;

use crate::ports::driven::driver_control::{
    DriverControlError,
    DriverControlPort,
    DriverPolicies,
    DriverStatsSnapshot,
};

/// Fake: records every `apply_policies` call (latest wins) and every
/// device-security SDDL push (latest wins); serves a builder-configured
/// stats snapshot; failures are injectable.
#[derive(Default)]
pub struct FakeDriverControl {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    applied: Option<DriverPolicies>,
    device_security: Option<String>,
    stats: DriverStatsSnapshot,
    fail_policies: bool,
}

impl FakeDriverControl {
    /// Fresh fake, no policies recorded, no injected failures.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The last applied policies, if any.
    #[must_use]
    pub fn applied(&self) -> Option<DriverPolicies> {
        self.inner.lock().applied.clone()
    }

    /// The last device-security SDDL pushed, if any.
    #[must_use]
    pub fn device_security(&self) -> Option<String> {
        self.inner.lock().device_security.clone()
    }

    /// Serve this snapshot from `query_stats`.
    pub fn set_stats(&self, stats: DriverStatsSnapshot) {
        self.inner.lock().stats = stats;
    }

    /// Make `apply_policies` fail (simulates a missing/rejecting device).
    pub fn fail_policies(&self, fail: bool) {
        self.inner.lock().fail_policies = fail;
    }
}

impl DriverControlPort for FakeDriverControl {
    fn apply_policies(&self, policies: &DriverPolicies) -> Result<(), DriverControlError> {
        let mut inner = self.inner.lock();
        if inner.fail_policies {
            return Err(DriverControlError::DeviceMissing);
        }
        inner.applied = Some(policies.clone());
        Ok(())
    }

    fn apply_device_security(&self, sddl: &str) -> Result<(), DriverControlError> {
        let mut inner = self.inner.lock();
        if inner.fail_policies {
            return Err(DriverControlError::DeviceMissing);
        }
        inner.device_security = Some(sddl.to_owned());
        Ok(())
    }

    fn query_stats(&self) -> Result<DriverStatsSnapshot, DriverControlError> {
        Ok(self.inner.lock().stats.clone())
    }

    fn loss_counters(&self) -> Result<HashMap<String, u64>, DriverControlError> {
        Ok(HashMap::new())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::ports::driven::driver_control::{
        DropPolicy,
        ProtectionPolicy,
    };

    #[test]
    fn policies_and_device_security_are_recorded() {
        let fake = FakeDriverControl::new();
        let policies = DriverPolicies {
            injection: None,
            drops: Some(DropPolicy {
                dir: r"\??\C:\drops".to_owned(),
                extensions: vec![".exe".to_owned()],
            }),
            protection: Some(ProtectionPolicy { names: vec!["agent.exe".to_owned()] }),
        };
        fake.apply_policies(&policies).unwrap();
        assert_eq!(fake.applied(), Some(policies));

        fake.apply_device_security("D:P(A;;GA;;;SY)").unwrap();
        assert_eq!(fake.device_security(), Some("D:P(A;;GA;;;SY)".to_owned()));
    }

    #[test]
    fn injected_failure_reports_device_missing() {
        let fake = FakeDriverControl::new();
        fake.fail_policies(true);
        assert!(matches!(
            fake.apply_policies(&DriverPolicies::default()),
            Err(DriverControlError::DeviceMissing)
        ));
        assert!(matches!(
            fake.apply_device_security("D:P(A;;GA;;;SY)"),
            Err(DriverControlError::DeviceMissing)
        ));
    }
}
