//! Chaos flows: infrastructure failures and hostile filesystems must degrade
//! — log, continue, persist — never crash the session.
//!
//! - the broker dying mid-finalize must not prevent the scope persist;
//! - a locked (share-none) drop file is skipped, collection continues;
//! - a drop that vanishes before collection is a debug note, not an error;
//! - Unicode drop paths survive copy + upload naming;
//! - a drops volume that refuses every write (disk full) never blocks
//!   finalization or the scope persist;
//! - a failed copy leaves no `.part` litter and does not poison collection.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{
            AtomicU32,
            Ordering,
        },
    },
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
        broker::{
            BrokerError,
            BrokerPort,
            Channel,
        },
        scope_repository::ScopeRepository,
    },
};
use async_trait::async_trait;
use kernel::{
    app::api_ports::EventInletPort,
    bus::InMemoryEventBus,
};
use protocol::{
    config::AgentConfig,
    nats::{
        Envelope,
        Payload,
    },
    payload::{
        FileReleasedData,
        FileWrittenData,
        ProcessStartedData,
    },
};

/// A broker that accepts the first `remaining` publishes, then loses the
/// connection (the Controller/NATS went away mid-study).
struct DyingBroker {
    inner: Arc<agent::adapters::broker_fake::FakeBroker>,
    remaining: AtomicU32,
}

impl DyingBroker {
    fn new(inner: Arc<agent::adapters::broker_fake::FakeBroker>, die_after: u32) -> Self {
        Self { inner, remaining: AtomicU32::new(die_after) }
    }
}

#[async_trait]
impl BrokerPort for DyingBroker {
    async fn publish(
        &self,
        channel: Channel,
        envelope: &Envelope<Payload>,
    ) -> Result<(), BrokerError> {
        if self.remaining.fetch_sub(1, Ordering::SeqCst) == 0 {
            return Err(BrokerError::ConnectionLost);
        }
        self.inner.publish(channel, envelope).await
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("secoutfall-chaos-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn base_config(drops_dir: &std::path::Path) -> AgentConfig {
    let mut config = AgentConfig::default();
    config.target.path = "C:\\Targets\\evil.exe".into();
    config.study.uptimes = vec![6000];
    config.target.every_session = false;
    config.drops.extensions = vec![".txt".to_owned()];
    config.drops.path = drops_dir.display().to_string();
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

struct Harness {
    kernel: agent::app::builder::AgentKernel,
    repo: Arc<InMemoryScopeRepository>,
}

/// Boot one session with a custom broker over a real drops directory.
async fn boot(config: &AgentConfig, broker: Arc<dyn BrokerPort>) -> Harness {
    let clock = Arc::new(FakeClock::new(1_465_182_366_000));
    let repo = Arc::new(InMemoryScopeRepository::default());
    let state = load_scope_state(repo.as_ref()).await.unwrap();
    let kernel = assemble(AgentDeps {
        config: Arc::new(config.clone()),
        scope_state: state,
        scope_repo: Arc::clone(&repo) as Arc<dyn ScopeRepository>,
        broker,
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
        user_actor_nonce: "chaos-nonce".to_owned(),
    });
    kernel.boot().await.unwrap();
    Harness { kernel, repo }
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

    async fn deadline_and_shutdown(self) -> Arc<InMemoryScopeRepository> {
        self.kernel.accept(SandboxEvent::SessionDeadline).await;
        self.settle().await;
        self.kernel.shutdown().await;
        self.repo
    }
}

/// The broker connection dies in the middle of the study: the session still
/// finalizes and the scope persists — the Controller loses telemetry, not
/// the analysis record.
#[tokio::test]
async fn broker_dying_mid_session_still_persists_the_scope() {
    let drops = temp_dir("dying-broker");
    let config = base_config(&drops);
    let fake = Arc::new(agent::adapters::broker_fake::FakeBroker::default());
    let broker: Arc<dyn BrokerPort> = Arc::new(DyingBroker::new(Arc::clone(&fake), 4)); // dies mid-session
    let harness = boot(&config, broker).await;

    harness
        .feed(&[
            process_started(999, None, "explorer.exe"),
            process_started(1000, None, "evil.exe"),
            process_started(1001, Some(1000), "cmd.exe"),
        ])
        .await;

    let repo = harness.deadline_and_shutdown().await;
    let state = repo.load().await.unwrap();
    assert_eq!(state.sessions.len(), 1);
    let session = state.sessions.first().unwrap();
    assert!(session.ended_at_ms.is_some(), "finalize completed despite broker loss");
    assert_eq!(session.scoped_processes.len(), 2, "scope record intact");
    // Some publishes landed before the death; everything after was refused.
    assert!(
        !fake.event_sequence().is_empty() && fake.event_sequence().len() < 10,
        "broker died partway through, not before or after the session"
    );
}

/// A drop held locked (share-none, malware keeping its artifact open) is
/// skipped; collection keeps working for the next one. Windows-only: the
/// share-mode knob does not exist elsewhere.
#[cfg(windows)]
#[tokio::test]
async fn locked_drop_is_skipped_and_collection_continues() {
    let drops = temp_dir("locked-drop");
    let source_dir = temp_dir("locked-src");
    let config = base_config(&drops);
    let fake = Arc::new(agent::adapters::broker_fake::FakeBroker::default());
    let harness = boot(&config, fake).await;

    let locked_path = source_dir.join("locked.txt");
    std::fs::write(&locked_path, b"locked content").unwrap();
    // Hold the file with no sharing at all.
    let lock_handle = {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().read(true).share_mode(0).open(&locked_path).unwrap()
    };

    harness
        .feed(&[
            process_started(999, None, "explorer.exe"),
            process_started(1000, None, "evil.exe"),
            file_written(1000, locked_path.to_str().unwrap()),
            file_closed(1000, locked_path.to_str().unwrap()),
        ])
        .await;
    harness.settle().await;
    assert!(
        std::fs::read_dir(&drops).unwrap().next().is_none(),
        "a share-locked drop cannot be copied"
    );

    // The lock releases (malware closed its artifact) and the next drop
    // flows normally — collection was not poisoned.
    drop(lock_handle);
    let healthy_path = source_dir.join("healthy.txt");
    std::fs::write(&healthy_path, b"healthy content").unwrap();
    harness
        .feed(&[
            file_written(1000, healthy_path.to_str().unwrap()),
            file_closed(1000, healthy_path.to_str().unwrap()),
        ])
        .await;
    harness.settle().await;
    let copies: Vec<String> = std::fs::read_dir(&drops)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(copies.len(), 1, "exactly the healthy drop collected: {copies:?}");
    assert!(
        std::path::Path::new(copies.first().unwrap())
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("txt"))
    );

    harness.kernel.shutdown().await;
}

/// Disk-full analog: the drops volume refuses every write (here: the target
/// path is occupied by a file, so no directory can exist). The session must
/// still finalize and persist — telemetry loss is acceptable, a lost analysis
/// record is not.
#[tokio::test]
async fn unusable_drops_target_does_not_block_finalization() {
    let base = temp_dir("disk-full");
    // Occupy the configured drops path with a plain file.
    let drops_file = base.join("drops");
    std::fs::write(&drops_file, b"not a directory").unwrap();
    let mut config = base_config(&drops_file);
    config.drops.extensions = vec![".txt".to_owned()];
    let fake = Arc::new(agent::adapters::broker_fake::FakeBroker::default());
    let harness = boot(&config, fake).await;

    let source = base.join("drop.txt");
    std::fs::write(&source, b"artifact").unwrap();
    harness
        .feed(&[
            process_started(999, None, "explorer.exe"),
            process_started(1000, None, "evil.exe"),
            file_written(1000, source.to_str().unwrap()),
            file_closed(1000, source.to_str().unwrap()),
        ])
        .await;
    harness.settle().await;

    assert!(drops_file.is_file(), "the occupation is untouched");
    let repo = harness.deadline_and_shutdown().await;
    let state = repo.load().await.unwrap();
    assert_eq!(state.sessions.len(), 1, "session finalized");
    assert!(state.sessions.first().unwrap().ended_at_ms.is_some(), "finalize completed");
}

/// A copy that fails partway (here: the "file" is a directory, so the open
/// dies after the pre-flight stat) must leave no `.part` litter in the drops
/// directory, and the next drop still collects — the pipeline is not poisoned.
#[tokio::test]
async fn failed_copy_leaves_no_part_litter_and_collection_survives() {
    let drops = temp_dir("part-litter");
    let source_dir = temp_dir("part-src");
    let config = base_config(&drops);
    let fake = Arc::new(agent::adapters::broker_fake::FakeBroker::default());
    let harness = boot(&config, fake).await;

    // A directory with a dropping extension: matches the filter, then fails
    // at open (Windows: ACCESS_DENIED) after the stat passed.
    let weird = source_dir.join("weird.txt");
    std::fs::create_dir(&weird).unwrap();
    harness
        .feed(&[
            process_started(999, None, "explorer.exe"),
            process_started(1000, None, "evil.exe"),
            file_written(1000, weird.to_str().unwrap()),
            file_closed(1000, weird.to_str().unwrap()),
        ])
        .await;
    harness.settle().await;
    let entries: Vec<String> = std::fs::read_dir(&drops)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(entries.is_empty(), "no copy and no .part litter: {entries:?}");

    // The next, healthy drop flows normally.
    let healthy = source_dir.join("healthy.txt");
    std::fs::write(&healthy, b"healthy").unwrap();
    harness
        .feed(&[
            file_written(1000, healthy.to_str().unwrap()),
            file_closed(1000, healthy.to_str().unwrap()),
        ])
        .await;
    harness.settle().await;
    let copies: Vec<String> = std::fs::read_dir(&drops)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(copies.len(), 1, "collection survived the failed copy: {copies:?}");

    harness.kernel.shutdown().await;
}
/// A drop that vanishes before collection is a debug note, not a failure;
/// Unicode paths survive the copy pipeline untouched.
#[tokio::test]
async fn vanishing_and_unicode_drops_are_handled() {
    let drops = temp_dir("unicode-drop");
    let source_dir = temp_dir("unicode-src");
    let mut config = base_config(&drops);
    // The Unicode drop is the only kind collected here; make it match.
    config.drops.extensions = vec![".txt".to_owned()];
    let fake = Arc::new(agent::adapters::broker_fake::FakeBroker::default());
    let harness = boot(&config, fake).await;

    // A drop that never existed (malware deleted it between write and
    // close — or it never was): the collector moves on.
    harness
        .feed(&[
            process_started(999, None, "explorer.exe"),
            process_started(1000, None, "evil.exe"),
            file_closed(1000, "C:\\never-existed.txt"),
        ])
        .await;
    harness.settle().await;
    assert!(std::fs::read_dir(&drops).unwrap().next().is_none());

    // Unicode source path: copied byte-for-byte with a generated ASCII name.
    let unicode_dir = source_dir.join("жертва-отчёты");
    std::fs::create_dir_all(&unicode_dir).unwrap();
    let unicode_path = unicode_dir.join("пароль.txt");
    std::fs::write(&unicode_path, "секретное содержимое").unwrap();
    harness
        .feed(&[
            file_written(1000, unicode_path.to_str().unwrap()),
            file_closed(1000, unicode_path.to_str().unwrap()),
        ])
        .await;
    harness.settle().await;

    let copies: Vec<PathBuf> =
        std::fs::read_dir(&drops).unwrap().map(|entry| entry.unwrap().path()).collect();
    assert_eq!(copies.len(), 1, "unicode drop collected once");
    let copy = copies.first().unwrap();
    let name = copy.file_name().unwrap().to_string_lossy().to_string();
    assert!(
        name.is_ascii()
            && std::path::Path::new(&name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("txt")),
        "copy name is generated ASCII: {name}"
    );
    assert_eq!(
        std::fs::read(copy).unwrap(),
        "секретное содержимое".as_bytes().to_vec(),
        "content survived the copy"
    );

    harness.kernel.shutdown().await;
}
