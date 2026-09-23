//! Fake event source + fake clock harness that drives a full multi-reboot study
//! simulation in milliseconds — the shape of the core regression suite.
//!
//! The strict assertions live in `agent/tests/multi_session_study.rs`; this bin
//! runs a bigger study (24 sessions) and prints a summary.

use std::sync::Arc;

use agent::{
    adapters::{
        broker_fake::FakeBroker,
        clock_fake::FakeClock,
        scope_store_memory::InMemoryScopeRepository,
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
    ports::scope_repository::ScopeRepository,
};
use kernel::app::api_ports::EventInletPort;
use protocol::{
    config::AgentConfig,
    events::EventType,
    payload::ProcessStartedData,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let sessions = 24;
    let mut config = AgentConfig::default();
    config.target.path = "C:\\Targets\\evil.exe".into();
    config.study.uptimes = vec![6000; sessions];
    config.target.every_session = true;
    config.drops.extensions = vec![".txt".to_owned()];

    let repo = Arc::new(InMemoryScopeRepository::default());
    let mut total_events = 0_usize;
    let mut control_requests: Vec<EventType> = Vec::new();

    for boot in 0..sessions {
        let boot_ms = i64::try_from(boot).unwrap_or_default() * 6_000_000;
        let clock = Arc::new(FakeClock::new(1_465_182_366_000 + boot_ms));
        let broker = Arc::new(FakeBroker::default());
        let state = load_scope_state(repo.as_ref()).await?;
        let kernel = assemble(AgentDeps {
            config: Arc::new(config.clone()),
            scope_state: state,
            scope_repo: Arc::clone(&repo)
                as Arc<dyn agent::ports::scope_repository::ScopeRepository>,
            broker: Arc::clone(&broker) as Arc<dyn agent::ports::broker::BrokerPort>,
            clock: Arc::clone(&clock) as Arc<dyn agent::ports::clock::SystemClockPort>,
            uploader: Arc::new(agent::adapters::upload_fake::FakeUploader::default())
                as Arc<dyn agent::ports::uploader::FileUploadPort>,
            launcher: Arc::new(agent::adapters::launcher_fake::FakeLauncher::default())
                as Arc<dyn agent::ports::process_launcher::ProcessLauncherPort>,
            shell: Arc::new(agent::adapters::shell_association_fake::FakeShellAssociation::new())
                as Arc<dyn agent::ports::shell_association::ShellAssociationPort>,
            killer: Arc::new(agent::adapters::process_killer_fake::FakeProcessKiller::default())
                as Arc<dyn agent::ports::process_killer::ProcessKillerPort>,
            shifter: Arc::clone(&clock) as Arc<dyn agent::ports::clock::ClockShiftPort>,
            statistics: Arc::new(agent::plugins::statistics::SessionStatistics::default()),
            user_actor_nonce: "sim-nonce".to_owned(),
            seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            user_actor_pid_gate: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            bus: kernel::bus::InMemoryEventBus::new(1024),
        });

        kernel.boot().await?;
        kernel
            .accept(SandboxEvent::Source(SourceEvent::ProcessStarted(ProcessStartedData {
                pid: 1000 + u32::try_from(boot).unwrap_or_default(),
                parent_pid: None,
                name: "evil.exe".to_owned(),
                image_path: None,
                command_line: None,
                os_session_id: Some(1),
            })))
            .await;
        tokio::task::yield_now().await;
        kernel.accept(SandboxEvent::SessionDeadline).await;
        kernel.shutdown().await;

        total_events += broker.event_sequence().len();
        for envelope in broker.of_channel(agent::ports::broker::Channel::Control) {
            control_requests.push(envelope.event_type);
        }
    }

    let reboots =
        control_requests.iter().filter(|event| **event == EventType::StudyRebootRequested).count();
    let shutdowns = control_requests
        .iter()
        .filter(|event| **event == EventType::StudyShutdownRequested)
        .count();

    println!("simulated a {sessions}-session study:");
    println!("  wire events published : {total_events}");
    println!("  reboot requests       : {reboots}");
    println!("  shutdown requests     : {shutdowns}");
    let final_state = repo.load().await?;
    println!("  persisted sessions    : {}", final_state.sessions.len());
    assert_eq!(reboots, sessions - 1);
    assert_eq!(shutdowns, 1);
    assert_eq!(final_state.sessions.len(), sessions);
    println!("study simulation OK");
    Ok(())
}
