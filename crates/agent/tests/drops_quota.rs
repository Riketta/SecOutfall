//! Drop-collection quota regressions: failed collections must never consume
//! the `limit_per_session` budget.
//!
//! - vanished drops (malware writes + deletes temp files) leave the quota
//!   intact — a later real drop is still collected;
//! - with a tiny quota, failures reserve room for the real artifact;
//! - the quota itself is still enforced after successful collections;
//! - failed collections leave no `.part` litter in the drops directory.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use agent::{
    adapters::{
        clock_fake::FakeClock,
        launcher_fake::FakeLauncher,
        scope_store_memory::InMemoryScopeRepository,
        shell_association_fake::FakeShellAssociation,
        upload_fake::FakeUploader,
    },
    app::{
        builder::{
            AgentDeps,
            assemble,
            load_scope_state,
        },
        event::{
            SandboxEvent,
            SourceEvent,
        },
    },
    ports::{
        broker::BrokerPort,
        scope_repository::ScopeRepository,
    },
};
use kernel::{
    app::api_ports::EventInletPort,
    bus::InMemoryEventBus,
};
use protocol::{
    config::AgentConfig,
    payload::{
        FileReleasedData,
        FileWrittenData,
        ProcessStartedData,
    },
};

fn temp_dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("secoutfall-drops-quota-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn base_config(drops_dir: &std::path::Path, limit_per_session: u32) -> AgentConfig {
    let mut config = AgentConfig::default();
    config.target.path = "C:\\Targets\\evil.exe".into();
    config.study.uptimes = vec![6000];
    config.target.every_session = false;
    config.drops.extensions = vec![".txt".to_owned()];
    config.drops.path = drops_dir.display().to_string();
    config.drops.limit_per_session = limit_per_session;
    config
}

fn process_started(pid: u32, parent: Option<u32>, name: &str) -> SandboxEvent {
    SandboxEvent::Source(SourceEvent::ProcessStarted(ProcessStartedData {
        pid,
        parent_pid: parent,
        name: name.to_owned(),
        image_path: None,
        command_line: None,
        os_session_id: Some(1),
    }))
}

fn file_written(pid: u32, path: &str) -> SandboxEvent {
    SandboxEvent::Source(SourceEvent::FileWritten(FileWrittenData {
        pid,
        file_object: Some(1),
        file_key: Some(2),
        file_name: Some(path.to_owned()),
        io_size: Some(512),
        offset: Some(0),
    }))
}

fn file_closed(pid: u32, path: &str) -> SandboxEvent {
    SandboxEvent::Source(SourceEvent::FileClosed(FileReleasedData {
        pid,
        file_object: Some(1),
        file_key: Some(2),
        file_name: Some(path.to_owned()),
    }))
}

/// A drop the malware already deleted: observed on write, gone from disk by
/// the time the collector opens it.
fn vanished_drop(pid: u32, path: &str) -> [SandboxEvent; 2] {
    [file_written(pid, path), file_closed(pid, path)]
}

/// A drop that exists on disk and survives collection.
fn real_drop(pid: u32, path: &std::path::Path, content: &[u8]) -> Vec<SandboxEvent> {
    std::fs::write(path, content).unwrap();
    vec![file_written(pid, path.to_str().unwrap()), file_closed(pid, path.to_str().unwrap())]
}

struct Harness {
    kernel: agent::app::builder::AgentKernel,
}

/// Boot one session over a real drops directory with the default broker fake.
async fn boot(config: &AgentConfig) -> Harness {
    let clock = Arc::new(FakeClock::new(1_465_182_366_000));
    let repo = Arc::new(InMemoryScopeRepository::default());
    let state = load_scope_state(repo.as_ref()).await.unwrap();
    let kernel = assemble(AgentDeps {
        config: Arc::new(config.clone()),
        scope_state: state,
        scope_repo: Arc::clone(&repo) as Arc<dyn ScopeRepository>,
        broker: Arc::new(agent::adapters::broker_fake::FakeBroker::default())
            as Arc<dyn BrokerPort>,
        clock: Arc::clone(&clock) as Arc<dyn agent::ports::clock::SystemClockPort>,
        uploader: Arc::new(FakeUploader::default())
            as Arc<dyn agent::ports::uploader::FileUploadPort>,
        launcher: Arc::new(FakeLauncher::default())
            as Arc<dyn agent::ports::process_launcher::ProcessLauncherPort>,
        shell: Arc::new(FakeShellAssociation::new())
            as Arc<dyn agent::ports::shell_association::ShellAssociationPort>,
        killer: Arc::new(agent::adapters::process_killer_fake::FakeProcessKiller::default())
            as Arc<dyn agent::ports::process_killer::ProcessKillerPort>,
        shifter: Arc::clone(&clock) as Arc<dyn agent::ports::clock::ClockShiftPort>,
        statistics: Arc::new(agent::plugins::statistics::SessionStatistics::default()),
        bus: InMemoryEventBus::new(4096),
        user_actor_nonce: "drops-quota-nonce".to_owned(),
        seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        user_actor_pid_gate: Arc::new(std::sync::atomic::AtomicU32::new(0)),
    });
    kernel.boot().await.unwrap();
    Harness { kernel }
}

impl Harness {
    async fn feed(&self, events: &[SandboxEvent]) {
        for event in events {
            self.kernel.accept(event.clone()).await;
            tokio::task::yield_now().await;
        }
    }

    async fn settle(&self) {
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn shutdown(self) {
        self.kernel.shutdown().await;
    }
}

/// Copy names currently in the drops directory.
fn drop_names(drops: &std::path::Path) -> Vec<String> {
    std::fs::read_dir(drops)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
        .collect()
}

/// A stream of vanished drops (more than a full default quota) must not
/// disable collection: the real artifact arriving afterwards is still copied.
#[tokio::test]
async fn vanished_drops_never_exhaust_the_session_quota() {
    let drops = temp_dir("quota-vanished");
    let source_dir = temp_dir("quota-vanished-src");
    let config = base_config(&drops, 30);
    let harness = boot(&config).await;

    let mut events =
        vec![process_started(999, None, "explorer.exe"), process_started(1000, None, "evil.exe")];
    for index in 0..35 {
        events.extend(vanished_drop(1000, &format!("C:\\Temp\\gone-{index}.txt")));
    }
    harness.feed(&events).await;
    harness.settle().await;
    assert!(
        drop_names(&drops).is_empty(),
        "vanished drops collected nothing and left no litter: {:?}",
        drop_names(&drops)
    );

    let real = source_dir.join("real.txt");
    let copied = real_drop(1000, &real, b"the actual payload");
    harness.feed(&copied).await;
    harness.settle().await;

    let names = drop_names(&drops);
    assert_eq!(names.len(), 1, "the real drop was collected despite 35 vanished ones: {names:?}");
    assert!(
        std::path::Path::new(names.first().unwrap())
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("txt")),
        "copy name carries the sanitized extension: {names:?}"
    );
    let copy_path = drops.join(names.first().unwrap());
    assert_eq!(std::fs::read(&copy_path).unwrap(), b"the actual payload", "content survived");

    harness.shutdown().await;
}

/// With a tiny quota, two vanished drops + one real still collects the real
/// one — failures must reserve the budget for actual artifacts.
#[tokio::test]
async fn tiny_quota_failures_still_reserve_room_for_the_real_drop() {
    let drops = temp_dir("quota-tiny");
    let source_dir = temp_dir("quota-tiny-src");
    let config = base_config(&drops, 2);
    let harness = boot(&config).await;

    let mut events =
        vec![process_started(999, None, "explorer.exe"), process_started(1000, None, "evil.exe")];
    events.extend(vanished_drop(1000, "C:\\Temp\\first.txt"));
    events.extend(vanished_drop(1000, "C:\\Temp\\second.txt"));
    harness.feed(&events).await;

    let real = source_dir.join("real.txt");
    let copied = real_drop(1000, &real, b"survivor");
    harness.feed(&copied).await;
    harness.settle().await;

    let names = drop_names(&drops);
    assert_eq!(names.len(), 1, "the real drop beat the two vanished ones: {names:?}");
    assert!(
        names.iter().all(|name| !std::path::Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("part"))),
        "no .part litter from failed collections: {names:?}"
    );

    harness.shutdown().await;
}

/// The quota still bites once real collections fill it: a third distinct drop
/// over `limit_per_session = 2` is refused.
#[tokio::test]
async fn quota_still_enforced_after_successful_collections() {
    let drops = temp_dir("quota-enforced");
    let source_dir = temp_dir("quota-enforced-src");
    let config = base_config(&drops, 2);
    let harness = boot(&config).await;

    let mut events =
        vec![process_started(999, None, "explorer.exe"), process_started(1000, None, "evil.exe")];
    for (index, content) in ["one", "two", "three"].iter().enumerate() {
        let path = source_dir.join(format!("drop-{index}.txt"));
        events.extend(real_drop(1000, &path, content.as_bytes()));
    }
    harness.feed(&events).await;
    harness.settle().await;

    let names = drop_names(&drops);
    assert_eq!(names.len(), 2, "exactly `limit_per_session` drops collected: {names:?}");
    assert!(
        names.iter().all(|name| !std::path::Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("part"))),
        "no .part litter: {names:?}"
    );

    harness.shutdown().await;
}
