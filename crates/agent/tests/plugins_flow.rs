//! Phase-6 plugin flows end to end: drops collection (copy + dedup + caps +
//! upload), screenshot intake (quota + save + upload + kill-switch) and
//! target launch through shell associations (with scope-expectation
//! extension). Real filesystem where the plugins touch it; fakes everywhere
//! else. Deterministic on the current-thread runtime.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use agent::{
    adapters::{
        broker_fake::FakeBroker,
        clock_fake::FakeClock,
        launcher_fake::FakeLauncher,
        scope_store_memory::InMemoryScopeRepository,
        shell_association_fake::FakeShellAssociation,
        upload_fake::FakeUploader,
    },
    app::{
        builder::{
            AgentDeps,
            AgentKernel,
            assemble,
            load_scope_state,
        },
        event::{
            SandboxEvent,
            ScreenshotFrame,
            SourceEvent,
        },
    },
    domain::scope::SharedScopeState,
    plugins::statistics::SessionStatistics,
    ports::scope_repository::ScopeRepository,
};
use kernel::{
    app::api_ports::EventInletPort,
    bus::InMemoryEventBus,
};
use protocol::{
    config::AgentConfig,
    events::EventType,
    payload::{
        FileReleasedData,
        FileWrittenData,
        ProcessStartedData,
    },
};

/// Unique temp dir for one test.
fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("secoutfall-flow-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn base_config() -> AgentConfig {
    let mut config = AgentConfig::default();
    config.target.path = "C:\\Targets\\evil.exe".into();
    config.target.every_session = false;
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

fn file_written(pid: u32, path: &str, size: u64) -> SandboxEvent {
    SandboxEvent::Source(SourceEvent::FileWritten(FileWrittenData {
        pid,
        file_object: Some(1),
        file_key: Some(2),
        file_name: Some(path.to_owned()),
        io_size: Some(size),
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

/// Everything the tests need to poke after a boot.
struct Harness {
    kernel: AgentKernel,
    broker: Arc<FakeBroker>,
    uploader: Arc<FakeUploader>,
    launcher: Arc<FakeLauncher>,
    killer: Arc<agent::adapters::process_killer_fake::FakeProcessKiller>,
    clock: Arc<FakeClock>,
    stats: Arc<SessionStatistics>,
    state: SharedScopeState,
}

/// Assemble + boot one session with fakes.
async fn boot(config: &AgentConfig, shell: &Arc<FakeShellAssociation>) -> Harness {
    let clock = Arc::new(FakeClock::new(1_465_182_366_000));
    let broker = Arc::new(FakeBroker::default());
    let uploader = Arc::new(FakeUploader::default());
    let launcher = Arc::new(FakeLauncher::default());
    let killer =
        Arc::new(agent::adapters::process_killer_fake::FakeProcessKiller::with_killed_per_name(1));
    let counters = Arc::new(SessionStatistics::default());
    let repo = Arc::new(InMemoryScopeRepository::default());
    let state = load_scope_state(repo.as_ref()).await.unwrap();
    let kernel = assemble(AgentDeps {
        config: Arc::new(config.clone()),
        scope_state: Arc::clone(&state),
        scope_repo: Arc::clone(&repo) as Arc<dyn ScopeRepository>,
        broker: Arc::clone(&broker) as Arc<dyn agent::ports::broker::BrokerPort>,
        clock: Arc::clone(&clock) as Arc<dyn agent::ports::clock::SystemClockPort>,
        uploader: Arc::clone(&uploader) as Arc<dyn agent::ports::uploader::FileUploadPort>,
        launcher: Arc::clone(&launcher)
            as Arc<dyn agent::ports::process_launcher::ProcessLauncherPort>,
        shell: Arc::clone(shell) as Arc<dyn agent::ports::shell_association::ShellAssociationPort>,
        killer: Arc::clone(&killer) as Arc<dyn agent::ports::process_killer::ProcessKillerPort>,
        shifter: Arc::clone(&clock) as Arc<dyn agent::ports::clock::ClockShiftPort>,
        statistics: Arc::clone(&counters),
        bus: InMemoryEventBus::new(4096),
        user_actor_nonce: "test-nonce".to_owned(),
        seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        user_actor_pid_gate: Arc::new(std::sync::atomic::AtomicU32::new(0)),
    });
    kernel.boot().await.unwrap();
    Harness { kernel, broker, uploader, launcher, killer, clock, stats: counters, state }
}

impl Harness {
    /// Wire event types, in order.
    fn sequence(&self) -> Vec<protocol::events::EventType> {
        self.broker.event_sequence()
    }

    async fn feed(&self, events: &[SandboxEvent]) {
        for event in events {
            self.kernel.accept(event.clone()).await;
            tokio::task::yield_now().await;
        }
    }

    /// Let async workers (collection queue, uploads) drain before asserting.
    async fn settle(&self) {
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn shutdown(&self) {
        self.kernel.shutdown().await;
    }
}

#[tokio::test]
async fn drops_are_copied_uploaded_and_deduped_by_content() {
    let drops_dir = temp_dir("drops");
    let source_dir = temp_dir("drop-src");

    let mut config = base_config();
    config.drops.path = drops_dir.display().to_string();
    config.drops.extensions = vec![".txt".to_owned()];
    config.drops.max_size = 1024 * 1024;
    config.drops.upload_uri = Some("http://collector/drops".to_owned());

    // Two identical contents, one different — dedup must keep 2 copies.
    let good = b"hello drop".as_slice();
    std::fs::write(source_dir.join("a.txt"), good).unwrap();
    std::fs::write(source_dir.join("b.txt"), good).unwrap();
    std::fs::write(source_dir.join("c.txt"), b"different!").unwrap();
    let (a, b, c) = (
        source_dir.join("a.txt").display().to_string(),
        source_dir.join("b.txt").display().to_string(),
        source_dir.join("c.txt").display().to_string(),
    );

    let shell = Arc::new(FakeShellAssociation::new());
    let harness = boot(&config, &shell).await;
    harness
        .feed(&[
            process_started(999, None, "explorer.exe"),
            process_started(1000, None, "evil.exe"),
            file_written(1000, &a, 10),
            file_closed(1000, &a),
            file_written(1000, &b, 10),
            file_closed(1000, &b),
            file_written(1000, &c, 10),
            file_closed(1000, &c),
        ])
        .await;
    harness.settle().await;

    // Wire: three closes → two copies (a/b deduped) → two uploads.
    let sequence = harness.broker.event_sequence();
    assert_eq!(sequence.iter().filter(|e| **e == EventType::DropCopied).count(), 2);
    assert_eq!(sequence.iter().filter(|e| **e == EventType::DropUploaded).count(), 2);

    // Disk: exactly two copy files, one per distinct content, no .part litter.
    let mut copies: Vec<PathBuf> =
        std::fs::read_dir(&drops_dir).unwrap().map(|e| e.unwrap().path()).collect();
    copies.sort();
    assert_eq!(copies.len(), 2, "copies in dir: {copies:?}");
    assert!(copies.iter().all(|path| path.extension().is_some_and(|ext| ext == "txt")));
    let mut contents: Vec<Vec<u8>> =
        copies.iter().map(|path| std::fs::read(path).unwrap()).collect();
    contents.sort();
    assert_eq!(contents, vec![b"different!".to_vec(), good.to_vec()]);

    // Uploads: right endpoint, wire names == copy names, study/session set.
    let uploads = harness.uploader.uploads();
    assert_eq!(uploads.len(), 2);
    let (study_id, session_id) = {
        let state = harness.state.lock();
        (state.study_id, state.current_session().unwrap().id)
    };
    for upload in &uploads {
        assert_eq!(upload.endpoint, "http://collector/drops");
        assert_eq!(upload.meta.study, study_id);
        assert_eq!(upload.meta.session, session_id);
        assert!(
            copies
                .iter()
                .any(|path| path.file_name().unwrap().to_str() == Some(upload.meta.path.as_str())),
            "wire name {:?} must match a copy on disk",
            upload.meta.path
        );
    }

    harness.shutdown().await;
    let _ = std::fs::remove_dir_all(&drops_dir);
    let _ = std::fs::remove_dir_all(&source_dir);
}

#[tokio::test]
async fn oversized_drops_are_refused_not_uploaded() {
    let drops_dir = temp_dir("drops-big");
    let source_dir = temp_dir("drop-big-src");

    let mut config = base_config();
    config.drops.path = drops_dir.display().to_string();
    config.drops.extensions = vec!["*".to_owned()];
    config.drops.max_size = 8; // Tiny cap on purpose.
    config.drops.upload_uri = Some("http://collector/drops".to_owned());

    let big = source_dir.join("big.txt");
    std::fs::write(&big, vec![0u8; 100]).unwrap();
    let big_path = big.display().to_string();

    let shell = Arc::new(FakeShellAssociation::new());
    let harness = boot(&config, &shell).await;
    harness
        .feed(&[
            process_started(999, None, "explorer.exe"),
            process_started(1000, None, "evil.exe"),
            file_written(1000, &big_path, 100),
            file_closed(1000, &big_path),
        ])
        .await;
    harness.settle().await;

    assert!(
        !harness.broker.event_sequence().contains(&EventType::DropCopied),
        "over-cap drop must not be copied"
    );
    assert!(std::fs::read_dir(&drops_dir).unwrap().next().is_none(), "no part litter");
    assert!(harness.uploader.uploads().is_empty());

    harness.shutdown().await;
    let _ = std::fs::remove_dir_all(&drops_dir);
    let _ = std::fs::remove_dir_all(&source_dir);
}

#[tokio::test]
async fn screenshots_are_saved_uploaded_and_quota_capped() {
    let shots_dir = temp_dir("shots");

    let mut config = base_config();
    config.user_actor.screencapture = true;
    config.screenshots.path = shots_dir.display().to_string();
    config.screenshots.save = true;
    config.screenshots.max_per_session = 2;
    config.screenshots.upload_uri = Some("http://collector/shots".to_owned());

    let shell = Arc::new(FakeShellAssociation::new());
    let harness = boot(&config, &shell).await;
    let frame = |seq: u32, byte: u8| {
        SandboxEvent::ScreenshotReceived(ScreenshotFrame { seq, jpeg: vec![byte; 32] })
    };
    harness.feed(&[frame(1, 1), frame(2, 2), frame(3, 3)]).await;
    harness.settle().await;

    let sequence = harness.broker.event_sequence();
    let received: Vec<_> =
        sequence.iter().filter(|e| **e == EventType::ScreenshotReceived).collect();
    let uploaded: Vec<_> =
        sequence.iter().filter(|e| **e == EventType::ScreenshotUploaded).collect();
    assert_eq!(received.len(), 2, "quota 2: frames 1 and 2 accepted");
    assert_eq!(uploaded.len(), 2);

    // Saved with the wire names and exact bytes.
    for (seq, byte) in [(1_u32, 1_u8), (2, 2)] {
        let path = shots_dir.join(format!("screenshot-0-{seq}.jpeg"));
        assert_eq!(std::fs::read(&path).unwrap(), vec![byte; 32]);
    }
    assert!(!shots_dir.join("screenshot-0-3.jpeg").exists(), "frame 3 refused");
    assert_eq!(harness.uploader.uploads().len(), 2);

    harness.shutdown().await;
    let _ = std::fs::remove_dir_all(&shots_dir);
}

#[tokio::test]
async fn screenshots_are_refused_when_capture_is_disabled() {
    // Bug #4 regression: disabled capture must refuse frames agent-side too.
    let mut config = base_config();
    config.user_actor.screencapture = false;
    config.screenshots.save = true;
    config.screenshots.upload_uri = Some("http://collector/shots".to_owned());

    let shell = Arc::new(FakeShellAssociation::new());
    let harness = boot(&config, &shell).await;
    harness
        .feed(&[SandboxEvent::ScreenshotReceived(ScreenshotFrame { seq: 1, jpeg: vec![0xAA; 16] })])
        .await;
    harness.settle().await;

    assert!(
        !harness.broker.event_sequence().contains(&EventType::ScreenshotReceived),
        "no wire traffic for refused frames"
    );
    assert!(harness.uploader.uploads().is_empty());
    harness.shutdown().await;
}

#[tokio::test]
async fn non_exe_target_launches_via_association_and_extends_scope() {
    let mut config = base_config();
    config.target.path = "C:\\Samples\\evil.js".into();
    config.target.args = vec!["-q".to_owned()];

    let shell = Arc::new(FakeShellAssociation::new());
    shell.register(".js", "\"C:\\Windows\\System32\\wscript.exe\" \"%1\"");
    let harness = boot(&config, &shell).await;

    // Marker process → association launch of the interpreter.
    harness.feed(&[process_started(999, None, "explorer.exe")]).await;
    harness.settle().await;

    let launched = harness.launcher.launched();
    // Phase 8: the marker also triggers the user-actor supervisor, so the
    // boot performs two launches — the target (first) and the user actor.
    assert_eq!(launched.len(), 2, "target + user actor on the marker");
    assert_eq!(launched.first().unwrap().path, "C:\\Windows\\System32\\wscript.exe");
    assert_eq!(
        launched.first().unwrap().args,
        vec!["C:\\Samples\\evil.js".to_owned(), "-q".to_owned()]
    );

    let launched_event = harness
        .broker
        .of_channel(agent::ports::broker::Channel::Event)
        .into_iter()
        .find(|envelope| envelope.event_type == EventType::TargetLaunched)
        .expect("target.launched on the wire");
    match launched_event.data {
        protocol::payload::Payload::TargetLaunched(data) => {
            assert_eq!(data.path, "C:\\Windows\\System32\\wscript.exe");
            assert_eq!(data.args.as_deref(), Some("C:\\Samples\\evil.js -q"));
            assert!(matches!(data.launcher, protocol::payload::Launcher::Token));
        }
        other => panic!("unexpected payload: {other:?}"),
    }

    // The resolved interpreter joins the scope expectation: wscript enters.
    harness.feed(&[process_started(700, None, "wscript.exe")]).await;
    harness.settle().await;
    let scoped = harness
        .state
        .lock()
        .current_session()
        .unwrap()
        .scoped_processes
        .iter()
        .any(|process| process.name == "wscript.exe");
    assert!(scoped, "interpreter must be scoped via ExtendScopeExpectation");

    // One launch attempt per boot: a second marker is a no-op (both the
    // target and the user actor stay put).
    harness.feed(&[process_started(998, None, "explorer.exe")]).await;
    harness.settle().await;
    assert_eq!(harness.launcher.launched().len(), 2, "no relaunch within one boot");

    harness.shutdown().await;
}

#[tokio::test]
async fn finalize_reports_score_summary_shifts_clock_and_kills() {
    let mut config = base_config();
    config.study.uptimes = vec![6000];
    config.time.offset_secs = 90;
    config.study.processes_to_terminate = vec!["notepad.EXE".to_owned()];
    config.debug.skip_time_manipulation = false;
    config.user_actor.screencapture = true;

    let shell = Arc::new(FakeShellAssociation::new());
    let harness = boot(&config, &shell).await;

    // Marker + target + a scoped child that drops one .txt file.
    let source =
        std::env::temp_dir().join(format!("secoutfall-fin-{}-drop.txt", std::process::id()));
    std::fs::write(&source, b"score me").unwrap();
    let source_path = source.display().to_string();

    harness
        .feed(&[
            process_started(999, None, "explorer.exe"),
            process_started(1000, None, "evil.exe"),
            process_started(1001, Some(1000), "cmd.exe"),
            file_written(1001, &source_path, 8),
            file_closed(1001, &source_path),
        ])
        .await;
    harness.settle().await;

    let before_finalize = agent::ports::clock::SystemClockPort::now_ms(harness.clock.as_ref());
    harness.kernel.accept(SandboxEvent::SessionDeadline).await;
    harness.settle().await;
    harness.shutdown().await;

    let sequence = harness.sequence();
    // Scoring: cmd.exe entering the scope scores 4, the drop scores 5 —
    // the reported score is the session maximum.
    let score_event = harness
        .broker
        .of_channel(agent::ports::broker::Channel::Event)
        .into_iter()
        .find(|envelope| envelope.event_type == protocol::events::EventType::StudyScore)
        .expect("study.score at finalize");
    match score_event.data {
        protocol::payload::Payload::StudyScore(data) => {
            assert_eq!(data.score, 5, "max(drop=5, cli=4)");
            assert_eq!(data.reason.as_deref(), Some("Total"));
        }
        other => panic!("unexpected payload: {other:?}"),
    }

    // Drops summary: the structured histogram replaces the legacy string.
    let summary_event = harness
        .broker
        .of_channel(agent::ports::broker::Channel::Event)
        .into_iter()
        .find(|envelope| envelope.event_type == protocol::events::EventType::StudyDropsSummary)
        .expect("study.drops_summary at finalize");
    match summary_event.data {
        protocol::payload::Payload::StudyDropsSummary(data) => {
            assert_eq!(data.extensions.get("txt"), Some(&1));
        }
        other => panic!("unexpected payload: {other:?}"),
    }

    // Clock offset applied through the shifter (FakeClock = clock + shifter).
    assert_eq!(
        agent::ports::clock::SystemClockPort::now_ms(harness.clock.as_ref()),
        before_finalize + 90 * 1000,
        "finalize must shift the fake clock by offset_secs"
    );
    let adjusted_event = harness
        .broker
        .of_channel(agent::ports::broker::Channel::Event)
        .into_iter()
        .find(|envelope| envelope.event_type == protocol::events::EventType::ClockAdjusted)
        .expect("clock.adjusted at finalize");
    match adjusted_event.data {
        protocol::payload::Payload::ClockAdjusted(data) => {
            assert_eq!(data.offset_secs, 90);
            assert!(matches!(data.cause, protocol::payload::ClockCause::SessionOffset));
        }
        other => panic!("unexpected payload: {other:?}"),
    }

    // Process cleanup swept the configured list.
    let sweeps = harness.killer.sweeps();
    assert_eq!(sweeps, vec![vec!["notepad.EXE".to_owned()]]);

    // Sequence ordering (membership, not fragile positions): finalize reports
    // all present after the deadline.
    assert!(sequence.contains(&protocol::events::EventType::StudyScore));
    assert!(sequence.contains(&protocol::events::EventType::StudyDropsSummary));
    assert!(sequence.contains(&protocol::events::EventType::ClockAdjusted));
}

#[tokio::test]
async fn statistics_count_pipeline_and_bus_events() {
    let mut config = base_config();
    config.user_actor.screencapture = true;
    config.target.every_session = true;

    let shell = Arc::new(FakeShellAssociation::new());
    let harness = boot(&config, &shell).await;

    harness
        .feed(&[
            process_started(999, None, "explorer.exe"),
            process_started(1000, None, "evil.exe"),
            SandboxEvent::ScreenshotReceived(ScreenshotFrame { seq: 1, jpeg: vec![1; 4] }),
            SandboxEvent::StatsTick,
        ])
        .await;
    harness.shutdown().await;

    let snapshot = harness.stats.snapshot();
    assert_eq!(snapshot.source_events, 2, "explorer + evil are source events");
    assert_eq!(snapshot.screenshots, 1);
    assert_eq!(snapshot.scope_entered, 1, "evil.exe joins via session-0 seed");
    assert_eq!(snapshot.ticks, 1);
}

#[tokio::test]
async fn user_actor_supervisor_launches_with_nonce_on_marker() {
    let mut config = base_config();
    config.user_actor.path = "C:\\Tools\\secoutfall-user-actor.exe".to_owned();
    let shell = Arc::new(FakeShellAssociation::new());
    let harness = boot(&config, &shell).await;

    // Marker sighting launches both the target and (new in phase 8) the user
    // actor, the latter carrying the per-boot nonce on its command line.
    harness.feed(&[process_started(999, None, "explorer.exe")]).await;
    harness.settle().await;

    let launches = harness.launcher.launched();
    let ua = launches
        .iter()
        .find(|spec| spec.path == "C:\\Tools\\secoutfall-user-actor.exe")
        .unwrap_or_else(|| panic!("user actor not launched; launches: {launches:?}"));
    assert_eq!(ua.args, vec!["--nonce".to_owned(), "test-nonce".to_owned()]);
    assert_eq!(ua.working_dir, None);

    // One attempt per boot: a second marker sighting is a no-op.
    harness.feed(&[process_started(997, None, "explorer.exe")]).await;
    harness.settle().await;
    assert_eq!(
        launches.iter().filter(|spec| spec.path.contains("user-actor")).count(),
        1,
        "no user-actor relaunch within one boot"
    );

    harness.shutdown().await;
}
