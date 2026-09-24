//! Regression: `run_until_stop` must wait for the finalize to FULLY complete.
//!
//! The host loop used to poll `ended_at_ms` — stamped at the START of
//! finalize — so it could break and tear the kernel down while the finalize
//! future was still inside its scope persist, silently killing the scope
//! write and the `session.ended` publish. Here the scope save is gated until
//! after the host would have (wrongly) broken; with the fix the run waits,
//! the snapshot lands on disk, and `session.ended` is published.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    sync::{
        Arc,
        atomic::{
            AtomicBool,
            Ordering,
        },
    },
    time::Duration,
};

use agent::{
    adapters::{
        broker_fake::FakeBroker,
        clock_fake::FakeClock,
        launcher_fake::FakeLauncher,
        scope_store_json::JsonScopeRepository,
        shell_association_fake::FakeShellAssociation,
        upload_fake::FakeUploader,
    },
    app::runtime::{
        RunningSession,
        SessionDeps,
    },
    domain::scope::ScopeState,
    ports::{
        broker::Channel,
        clock::{
            ClockShiftPort,
            SystemClockPort,
        },
        scope_repository::{
            ScopeRepository,
            ScopeRepositoryError,
        },
    },
};
use protocol::{
    config::AgentConfig,
    events::EventType,
};

/// Scope repository whose save blocks on an external gate — simulating a
/// persist that takes long enough for the host poll to race it.
struct SlowScopeRepository {
    inner: JsonScopeRepository,
    gate: Arc<tokio::sync::Notify>,
    save_started: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl ScopeRepository for SlowScopeRepository {
    async fn load(&self) -> Result<ScopeState, ScopeRepositoryError> {
        self.inner.load().await
    }

    async fn save(&self, state: &ScopeState) -> Result<(), ScopeRepositoryError> {
        self.save_started.store(true, Ordering::SeqCst);
        self.gate.notified().await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        self.inner.save(state).await
    }
}

#[tokio::test]
async fn finalize_survives_host_teardown() -> Result<(), Box<dyn std::error::Error>> {
    let scope_path = std::env::temp_dir().join(format!(
        "secoutfall-finalize-race-{}-{}.json",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let gate = Arc::new(tokio::sync::Notify::new());
    let save_started = Arc::new(AtomicBool::new(false));
    let repo = SlowScopeRepository {
        inner: JsonScopeRepository::new(&scope_path),
        gate: Arc::clone(&gate),
        save_started: Arc::clone(&save_started),
    };

    let mut config = AgentConfig::default();
    config.target.path = "C:\\Targets\\evil.exe".into();
    config.study.uptimes = vec![1]; // deadline fires 1 simulated second in

    let clock = Arc::new(FakeClock::new(1_465_182_366_000));
    let broker = Arc::new(FakeBroker::default());
    let deps = SessionDeps {
        config: Arc::new(config),
        scope_repo: Arc::new(repo) as Arc<dyn ScopeRepository>,
        broker: Arc::clone(&broker) as Arc<dyn agent::ports::broker::BrokerPort>,
        clock: Arc::clone(&clock) as Arc<dyn SystemClockPort>,
        uploader: Arc::new(FakeUploader::default())
            as Arc<dyn agent::ports::uploader::FileUploadPort>,
        launcher: Arc::new(FakeLauncher::default())
            as Arc<dyn agent::ports::process_launcher::ProcessLauncherPort>,
        shell: Arc::new(FakeShellAssociation::new())
            as Arc<dyn agent::ports::shell_association::ShellAssociationPort>,
        killer: Arc::new(agent::adapters::process_killer_fake::FakeProcessKiller::default())
            as Arc<dyn agent::ports::process_killer::ProcessKillerPort>,
        shifter: Arc::clone(&clock) as Arc<dyn ClockShiftPort>,
        statistics: Arc::new(agent::plugins::statistics::SessionStatistics::default()),
        user_actor_nonce: "finalize-race-nonce".to_owned(),
        seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        user_actor_pid_gate: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        finalize_done: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };

    let (session, _stop_tx, stop_rx) = RunningSession::start(deps).await?;

    // Release the gated save repeatedly: the scheduler's persist tick saves
    // immediately at boot (interval first tick), and the finalize's own save
    // comes later — each waiter must get a permit. Bounded so a regression
    // cannot spin forever.
    // Bounded: even under a regression the watcher must not spin forever.
    let watcher_gate = Arc::clone(&gate);
    let watcher_started = Arc::clone(&save_started);
    let watcher = tokio::spawn(async move {
        for _ in 0..56 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            watcher_gate.notify_one();
            if watcher_started.load(Ordering::SeqCst) {}
        }
    });

    let result =
        tokio::time::timeout(Duration::from_secs(15), session.run_until_stop(stop_rx)).await;
    watcher.abort(); // the gate-releaser is done; never wait out its loop
    let result = result.expect("run_until_stop hung waiting for the finalize");
    result.unwrap();

    // stop_tx still alive here — dropped by scope end.

    // The persist survived the host teardown …
    let raw = std::fs::read_to_string(&scope_path)
        .expect("scope snapshot must be written by the finalize");
    let parsed: serde_json::Value = serde_json::from_str(&raw).expect("snapshot is valid JSON");
    assert_eq!(
        parsed.get("sessions").and_then(|s| s.get(0)).and_then(|s| s.get("id")),
        Some(&serde_json::Value::from(0)),
        "session record persisted: {raw}"
    );
    // … and the final publish reached the wire.
    assert!(
        broker
            .of_channel(Channel::Event)
            .iter()
            .any(|envelope| envelope.event_type == EventType::SessionEnded),
        "session.ended must be published by the completed finalize"
    );

    let _ = std::fs::remove_file(&scope_path);
    Ok(())
}
