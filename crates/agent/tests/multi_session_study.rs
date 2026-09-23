//! The core regression suite: a full multi-reboot study simulated in
//! milliseconds, asserting the complete wire sequence, scope persistence and
//! the FIXED legacy behaviors (dead-scope logic, `uptimes` overrun).
//!
//! Determinism contract: bus consumers run on the same runtime; `feed` yields
//! after every event so derived wire events land in a stable order, and both
//! consumers use `biased` select so shutdown never races pending events.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

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
            SourceEvent,
        },
    },
    ports::{
        broker::Channel,
        scope_repository::ScopeRepository,
    },
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
        ProcessStoppedData,
    },
};

fn base_config(uptimes: Vec<u64>, autoshutdown: bool) -> AgentConfig {
    let mut config = AgentConfig::default();
    config.target.path = "C:\\Targets\\evil.exe".into();
    config.study.uptimes = uptimes;
    config.study.autoshutdown = autoshutdown;
    config.target.every_session = true;
    config.drops.extensions = vec![".txt".to_owned()];
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

fn process_stopped(pid: u32, name: &str) -> SandboxEvent {
    SandboxEvent::Source(SourceEvent::ProcessStopped(ProcessStoppedData {
        pid,
        name: name.to_owned(),
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

/// Feed events into the pipeline, yielding after each so bus consumers flush.
async fn feed(kernel: &AgentKernel, events: &[SandboxEvent]) {
    for event in events {
        kernel.accept(event.clone()).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
    }
}

struct Boot {
    broker: Arc<FakeBroker>,
}

/// One boot against the shared repo: assemble, boot, feed, optional deadline,
/// shutdown. Deterministic on the current-thread test runtime.
async fn run_boot(
    config: &AgentConfig,
    repo: &Arc<InMemoryScopeRepository>,
    script: &[SandboxEvent],
    deadline: bool,
) -> Boot {
    let clock = Arc::new(FakeClock::new(1_465_182_366_000));
    let broker = Arc::new(FakeBroker::default());
    let state = load_scope_state(repo.as_ref()).await.unwrap();
    let kernel = assemble(AgentDeps {
        config: Arc::new(config.clone()),
        scope_state: state,
        scope_repo: Arc::clone(repo) as Arc<dyn ScopeRepository>,
        broker: Arc::clone(&broker) as Arc<dyn agent::ports::broker::BrokerPort>,
        clock: Arc::clone(&clock) as Arc<dyn agent::ports::clock::SystemClockPort>,
        uploader: Arc::new(FakeUploader::default())
            as Arc<dyn agent::ports::uploader::FileUploadPort>,
        launcher: Arc::new(FakeLauncher::default())
            as Arc<dyn agent::ports::process_launcher::ProcessLauncherPort>,
        shell: Arc::new(FakeShellAssociation::new())
            as Arc<dyn agent::ports::shell_association::ShellAssociationPort>,
        killer: Arc::new(
            agent::adapters::process_killer_fake::FakeProcessKiller::with_killed_per_name(1),
        ) as Arc<dyn agent::ports::process_killer::ProcessKillerPort>,
        shifter: Arc::clone(&clock) as Arc<dyn agent::ports::clock::ClockShiftPort>,
        statistics: Arc::new(agent::plugins::statistics::SessionStatistics::default()),
        bus: InMemoryEventBus::new(1024),
    });

    kernel.boot().await.unwrap();
    feed(&kernel, script).await;
    if deadline {
        kernel.accept(SandboxEvent::SessionDeadline).await;
        tokio::task::yield_now().await;
    }
    kernel.shutdown().await;

    // Study/reboot must come from the control channel, telemetry from events.
    Boot { broker }
}

fn boot0_sequence() -> Vec<EventType> {
    vec![
        EventType::AgentState,
        EventType::SessionStarted,
        EventType::ProcessStarted, // explorer.exe (marker)
        EventType::TargetLaunched, // launcher detonates on the marker
        EventType::ProcessStarted, // evil.exe
        EventType::ProcessStarted, // cmd.exe
        EventType::ProcessStarted, // notepad.exe (unscoped, still forwarded)
        EventType::FileWritten,    // a.txt
        EventType::DropObserved,
        EventType::FileWritten, // unscoped.txt (no drop: unscoped writer)
        EventType::FileClosed,  // a.txt
        EventType::DropClosed,
        EventType::ProcessStopped, // cmd.exe (no scope.died: evil alive)
        EventType::SessionFinalizing,
        EventType::StudyScore,
        EventType::StudyDropsSummary,
        EventType::SessionEnded,
    ]
}

/// Find the `target.launched` envelope and assert its launcher-reported facts.
fn assert_fake_launch(broker: &FakeBroker, expected_path: &str) {
    let launched = broker
        .of_channel(Channel::Event)
        .into_iter()
        .find(|envelope| envelope.event_type == EventType::TargetLaunched)
        .unwrap();
    match launched.data {
        protocol::payload::Payload::TargetLaunched(data) => {
            assert_eq!(data.path, expected_path);
            assert_eq!(data.pid, Some(0), "FakeLauncher assigns sequential pids");
            assert!(matches!(data.launcher, protocol::payload::Launcher::Token));
        }
        other => panic!("unexpected payload: {other:?}"),
    }
}

#[tokio::test]
async fn three_session_study_reboots_then_shuts_down() {
    let config = base_config(vec![6000, 6000, 6000], false);
    let repo = Arc::new(InMemoryScopeRepository::default());

    // Session 0: marker (launch) + target + child join, one drop observed and
    // closed, one unscoped process whose telemetry still forwards.
    let boot0 = run_boot(
        &config,
        &repo,
        &[
            process_started(999, None, "explorer.exe"),
            process_started(1000, None, "evil.exe"),
            process_started(1001, Some(1000), "cmd.exe"),
            process_started(2000, None, "notepad.exe"),
            file_written(1001, "C:\\Users\\victim\\a.txt"),
            file_written(2000, "C:\\Users\\victim\\unscoped.txt"),
            file_closed(1001, "C:\\Users\\victim\\a.txt"),
            process_stopped(1001, "cmd.exe"),
        ],
        true,
    )
    .await;

    assert_eq!(boot0.broker.event_sequence(), boot0_sequence(), "session 0 wire sequence");
    // The launcher owns target.launched and reports real facts.
    assert_fake_launch(&boot0.broker, "C:\\Targets\\evil.exe");
    assert_eq!(
        boot0.broker.of_channel(Channel::Control).len(),
        1,
        "exactly one control message in session 0"
    );
    assert_eq!(
        boot0.broker.of_channel(Channel::Control).first().unwrap().event_type,
        EventType::StudyRebootRequested
    );
    // Session id stamped on every event-channel envelope.
    assert!(boot0.broker.of_channel(Channel::Event).iter().all(|envelope| envelope.session == 0));
    // Sequence numbers are gap-free per boot across both publishers.
    let mut seqs: Vec<u64> =
        boot0.broker.of_channel(Channel::Event).iter().map(|envelope| envelope.seq).collect();
    seqs.sort_unstable();
    assert_eq!(seqs, (0..seqs.len() as u64).collect::<Vec<u64>>());

    // Session 1: the marker re-triggers the launch (every_session), the target
    // rejoins, no closes, deadline.
    let boot1 = run_boot(
        &config,
        &repo,
        &[
            process_started(4000, None, "explorer.exe"),
            process_started(3000, None, "evil.exe"),
            file_written(3000, "C:\\Users\\victim\\b.txt"),
        ],
        true,
    )
    .await;
    assert_eq!(
        boot1.broker.event_sequence(),
        [
            EventType::AgentState,
            EventType::SessionStarted,
            EventType::ProcessStarted, // explorer.exe (marker)
            EventType::TargetLaunched,
            EventType::ProcessStarted,
            EventType::FileWritten,
            EventType::DropObserved,
            EventType::SessionFinalizing,
            EventType::StudyScore,
            EventType::StudyDropsSummary,
            EventType::SessionEnded,
        ],
        "session 1 wire sequence"
    );
    assert!(boot1.broker.of_channel(Channel::Event).iter().all(|envelope| envelope.session == 1));

    // Session 2 (last): immediate deadline -> shutdown requested.
    let boot2 = run_boot(&config, &repo, &[], true).await;
    assert_eq!(
        boot2.broker.event_sequence(),
        [
            EventType::AgentState,
            EventType::SessionStarted,
            EventType::SessionFinalizing,
            EventType::StudyScore,
            EventType::StudyDropsSummary,
            EventType::SessionEnded,
        ],
        "session 2 wire sequence"
    );
    assert_eq!(
        boot2.broker.of_channel(Channel::Control).first().unwrap().event_type,
        EventType::StudyShutdownRequested
    );

    // Scope persistence across the whole study lives in the shared repository.
    let final_state = repo.load().await.unwrap();
    assert_eq!(final_state.sessions.len(), 3);
    assert!(!final_state.study_id.is_nil());
    assert_eq!(final_state.sessions.first().unwrap().scoped_processes.len(), 2);
    assert_eq!(
        final_state.sessions.first().unwrap().observed_drops,
        ["C:\\Users\\victim\\a.txt".to_owned()].into_iter().collect()
    );
    assert!(final_state.sessions.iter().all(|s| s.ended_at_ms.is_some()));
    // Study id is stable across reboots.
    let boot0_events = boot0.broker.of_channel(Channel::Event);
    assert_eq!(boot0_events.first().unwrap().study, final_state.study_id);
}

#[tokio::test]
async fn autoshutdown_finalizes_on_real_scope_death_only_once() {
    let config = base_config(vec![6000, 6000], true);
    let repo = Arc::new(InMemoryScopeRepository::default());

    // Fixed logic: ScopeDied fires only after the LAST scoped process exits,
    // then finalize runs exactly once — the extra deadline is a no-op.
    let boot = run_boot(
        &config,
        &repo,
        &[
            process_started(999, None, "explorer.exe"),
            process_started(1000, None, "evil.exe"),
            process_started(1001, Some(1000), "cmd.exe"),
            process_stopped(1001, "cmd.exe"),
            process_stopped(1000, "evil.exe"),
            // The deadline after a dead scope must NOT re-finalize.
        ],
        true,
    )
    .await;

    let sequence = boot.broker.event_sequence();
    // The scope.died wire event (reporter consumer) and the finalize reports
    // (session-manager consumer) are independent bus consumers — their relative
    // order is not deterministic; membership and post-stop placement are.
    let last_stop = sequence.iter().rposition(|event| *event == EventType::ProcessStopped).unwrap();
    let tail = sequence.get(last_stop + 1..).unwrap();
    // ScopeDied (event-reporter) races the finalize reports (session-manager):
    // relative order is nondeterministic, membership and count are not.
    assert_eq!(tail.len(), 5, "five derived events after the last stop: {tail:?}");
    assert!(tail.contains(&EventType::ScopeDied));
    assert!(tail.contains(&EventType::SessionFinalizing));
    assert!(tail.contains(&EventType::StudyScore));
    assert!(tail.contains(&EventType::StudyDropsSummary));
    assert!(tail.contains(&EventType::SessionEnded));
    assert_eq!(
        sequence.get(..=last_stop).unwrap(),
        vec![
            EventType::AgentState,
            EventType::SessionStarted,
            EventType::ProcessStarted, // explorer.exe (marker)
            EventType::TargetLaunched,
            EventType::ProcessStarted, // evil.exe
            EventType::ProcessStarted, // cmd.exe
            EventType::ProcessStopped, // cmd.exe (evil still alive: no death)
            EventType::ProcessStopped, // evil.exe
        ],
        "autoshutdown sequence up to scope death"
    );
    assert_eq!(
        sequence.iter().filter(|event| **event == EventType::SessionFinalizing).count(),
        1,
        "exactly one finalize per session"
    );
    // Session 0 of 2 planned: autoshutdown triggers a REBOOT, not a shutdown.
    assert_eq!(
        boot.broker.of_channel(Channel::Control).first().unwrap().event_type,
        EventType::StudyRebootRequested
    );
}

#[tokio::test]
async fn uptimes_overrun_is_dynamic_not_a_panic() {
    // Legacy crashed with IndexOutOfRange on boot 2; the rewrite runs dynamic.
    let config = base_config(vec![6000], false);
    let repo = Arc::new(InMemoryScopeRepository::default());

    let boot0 = run_boot(&config, &repo, &[], true).await;
    assert_eq!(
        boot0.broker.of_channel(Channel::Control).first().unwrap().event_type,
        EventType::StudyShutdownRequested
    );
    assert_eq!(boot0.broker.event_sequence().get(1), Some(&EventType::SessionStarted));
    // The controller ignores the request and reboots anyway (VM bounced again):
    let boot1 = run_boot(
        &config,
        &repo,
        &[process_started(4000, None, "explorer.exe"), process_started(5000, None, "evil.exe")],
        true,
    )
    .await;
    // Session 1 runs dynamic (no scheduled duration) and still finalizes.
    assert_eq!(
        boot1.broker.event_sequence(),
        vec![
            EventType::AgentState,
            EventType::SessionStarted,
            EventType::ProcessStarted, // explorer.exe (marker)
            EventType::TargetLaunched,
            EventType::ProcessStarted,
            EventType::SessionFinalizing,
            EventType::StudyScore,
            EventType::StudyDropsSummary,
            EventType::SessionEnded,
        ]
    );
    let started = boot1
        .broker
        .of_channel(Channel::Event)
        .into_iter()
        .find(|envelope| envelope.event_type == EventType::SessionStarted)
        .unwrap();
    // scheduled_duration_secs is None in dynamic mode.
    match started.data {
        protocol::payload::Payload::SessionStarted(data) => {
            assert_eq!(data.scheduled_duration_secs, None, "dynamic session");
        }
        other => panic!("unexpected payload: {other:?}"),
    }
    // And it still requests shutdown cleanly (count 2 >= planned 1).
    assert_eq!(
        boot1.broker.of_channel(Channel::Control).first().unwrap().event_type,
        EventType::StudyShutdownRequested
    );
}
