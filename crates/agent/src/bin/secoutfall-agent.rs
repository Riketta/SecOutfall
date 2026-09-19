//! Composition root for the `SecOutfall` agent.
//!
//! Phase 3: console-mode walking skeleton — the agent runs one simulated
//! session against fake adapters (real ETW/NATS/scheduler land in phases 4–6).

use kernel::app::api_ports::EventInletPort;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("{} v{} (console walking skeleton)", agent::NAME, env!("CARGO_PKG_VERSION"));

    // Demo configuration standing in for C:\Agent.toml until the config
    // subcommand lands; validation runs exactly like production would.
    let mut config = protocol::config::AgentConfig::default();
    config.target.path = "C:\\Targets\\evil.exe".into();
    config.study.uptimes = vec![6000];
    config.drops.extensions = vec![".txt".to_owned(), ".exe".to_owned()];
    config.validate()?;

    let clock = std::sync::Arc::new(agent::adapters::clock_fake::FakeClock::new(1_465_182_366_000));
    let broker = std::sync::Arc::new(agent::adapters::broker_fake::FakeBroker::default());
    let repo = std::sync::Arc::new(agent::adapters::scope_store_json::JsonScopeRepository::new(
        "scope.json",
    ));

    let scope_state = agent::app::builder::load_scope_state(repo.as_ref()).await?;
    let kernel = agent::app::builder::assemble(agent::app::builder::AgentDeps {
        config: std::sync::Arc::new(config),
        scope_state,
        scope_repo: std::sync::Arc::clone(&repo)
            as std::sync::Arc<dyn agent::ports::scope_repository::ScopeRepository>,
        broker: std::sync::Arc::clone(&broker)
            as std::sync::Arc<dyn agent::ports::broker::BrokerPort>,
        clock: std::sync::Arc::clone(&clock)
            as std::sync::Arc<dyn agent::ports::clock::SystemClockPort>,
        bus: kernel::bus::InMemoryEventBus::new(1024),
    });

    kernel.boot().await?;

    // Demo script: a target that spawns a child dropping a file, then dies.
    let script = vec![
        demo_process_started(1000, None, "evil.exe"),
        demo_process_started(1001, Some(1000), "cmd.exe"),
        demo_file_written(1001, "C:\\Users\\victim\\payload.txt"),
        demo_process_stopped(1001, "cmd.exe"),
        demo_process_stopped(1000, "evil.exe"),
    ];
    for event in script {
        kernel.accept(event).await;
        tokio::task::yield_now().await;
    }
    kernel.accept(agent::app::event::SandboxEvent::SessionDeadline).await;
    kernel.shutdown().await;

    println!("published {} wire events this session", broker.event_sequence().len());
    for envelope in broker.of_channel(agent::ports::broker::Channel::Control) {
        println!("control: {}", envelope.event_type);
    }
    println!("scope persisted to scope.json");
    Ok(())
}

fn demo_process_started(
    pid: u32,
    parent: Option<u32>,
    name: &str,
) -> agent::app::event::SandboxEvent {
    agent::app::event::SandboxEvent::Source(agent::app::event::SourceEvent::ProcessStarted(
        protocol::payload::ProcessStartedData {
            pid,
            parent_pid: parent,
            name: name.to_owned(),
            image_path: None,
            command_line: None,
            os_session_id: Some(1),
        },
    ))
}

fn demo_process_stopped(pid: u32, name: &str) -> agent::app::event::SandboxEvent {
    agent::app::event::SandboxEvent::Source(agent::app::event::SourceEvent::ProcessStopped(
        protocol::payload::ProcessStoppedData { pid, name: name.to_owned() },
    ))
}

fn demo_file_written(pid: u32, path: &str) -> agent::app::event::SandboxEvent {
    agent::app::event::SandboxEvent::Source(agent::app::event::SourceEvent::FileWritten(
        protocol::payload::FileWrittenData {
            pid,
            file_object: Some(1),
            file_key: Some(2),
            file_name: Some(path.to_owned()),
            io_size: Some(512),
            offset: Some(0),
        },
    ))
}
