//! Fake sensor store: deterministic materialization for tests on every host.
//! Paths are derived from a call counter; failures are injectable.

use parking_lot::Mutex;

use crate::ports::driven::sensor_store::{
    MaterializedSensor,
    SensorStoreError,
    SensorStorePort,
};

/// Records every source it was asked to materialize; never touches the
/// filesystem.
#[derive(Default)]
pub struct FakeSensorStore {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    sources: Vec<String>,
    calls: u64,
    fail: Option<SensorStoreError>,
}

impl FakeSensorStore {
    /// Every source handed to [`SensorStorePort::materialize`], in order.
    #[must_use]
    pub fn sources(&self) -> Vec<String> {
        self.inner.lock().sources.clone()
    }

    /// Make the next `materialize` call fail with `error`.
    pub fn fail_next_with(&self, error: SensorStoreError) {
        self.inner.lock().fail = Some(error);
    }
}

impl SensorStorePort for FakeSensorStore {
    fn materialize(&self, source: &str) -> Result<MaterializedSensor, SensorStoreError> {
        let mut inner = self.inner.lock();
        inner.sources.push(source.to_owned());
        if let Some(error) = inner.fail.take() {
            return Err(error);
        }
        inner.calls += 1;
        let tag = format!("{:016x}", inner.calls);
        let dos_path = format!("C:\\ProgramData\\SecOutfall\\sensors\\boot{tag}\\sensor-{tag}.dll");
        Ok(MaterializedSensor {
            nt_path: crate::adapters::driven::sensor_store::to_nt_path(&dos_path),
            dos_path,
            // Deterministic stand-in digest; tests assert presence, not value.
            sha256_hex: format!("fake-{tag}"),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn fake_records_sources_and_produces_distinct_nt_paths() {
        let store = FakeSensorStore::default();
        let first = store.materialize("C:/s/sensor.dll").unwrap();
        let second = store.materialize("C:/s/sensor.dll").unwrap();
        assert_eq!(store.sources(), vec!["C:/s/sensor.dll", "C:/s/sensor.dll"]);
        assert_ne!(first.nt_path, second.nt_path, "per-boot names differ");
        assert!(first.nt_path.starts_with(r"\??\C:\"));
    }

    #[test]
    fn injected_failure_is_one_shot() {
        let store = FakeSensorStore::default();
        store.fail_next_with(SensorStoreError::SourceMissing("x".to_owned()));
        assert!(store.materialize("s.dll").is_err());
        assert!(store.materialize("s.dll").is_ok(), "the failure must not stick");
    }
}
