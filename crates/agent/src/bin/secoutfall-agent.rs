//! Composition root for the `SecOutfall` agent.
//!
//! Modes:
//! - *(default)* `console` — full runtime on this host; Ctrl+C finalizes.
//! - `simulate` — the phase-3 scripted single-session demo.
//! - `service` — SCM service mode (`--features service`).
//! - `etw-probe [seconds]` — live kernel-trace spike probe (`--features etw`).

use std::sync::Arc;

use agent::app::event::SandboxEvent;
#[cfg(all(windows, feature = "etw"))]
use agent::ports::event_source::EventSourcePort;
use kernel::app::api_ports::EventInletPort;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("simulate") => simulate().await,
        Some("service") => service_mode().await,
        Some("etw-probe") => etw_probe().await,
        _ => console().await,
    }
}

/// Demo configuration standing in for `C:\Agent.toml` until the config
/// subcommand lands; validation runs exactly like production would.
fn demo_config() -> anyhow::Result<protocol::config::AgentConfig> {
    let mut config = protocol::config::AgentConfig::default();
    config.target.path = "C:\\Targets\\evil.exe".into();
    config.study.uptimes = vec![6000];
    config.drops.extensions = vec![".txt".into(), ".exe".into()];
    config.validate()?;
    Ok(config)
}

fn demo_script() -> Vec<SandboxEvent> {
    vec![
        source_process_started(1000, None, "evil.exe"),
        source_process_started(1001, Some(1000), "cmd.exe"),
        source_file_written(1001, "C:\\Users\\victim\\payload.txt"),
        source_process_stopped(1001, "cmd.exe"),
        source_process_stopped(1000, "evil.exe"),
    ]
}

fn source_process_started(pid: u32, parent: Option<u32>, name: &str) -> SandboxEvent {
    SandboxEvent::Source(agent::app::event::SourceEvent::ProcessStarted(
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

fn source_process_stopped(pid: u32, name: &str) -> SandboxEvent {
    SandboxEvent::Source(agent::app::event::SourceEvent::ProcessStopped(
        protocol::payload::ProcessStoppedData { pid, name: name.to_owned() },
    ))
}

fn source_file_written(pid: u32, path: &str) -> SandboxEvent {
    SandboxEvent::Source(agent::app::event::SourceEvent::FileWritten(
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

/// Phase-3 demo: one scripted session against fakes (kept for the walking
/// skeleton history and quick end-to-end sanity checks).
async fn simulate() -> anyhow::Result<()> {
    println!("{} v{} (simulate)", agent::NAME, env!("CARGO_PKG_VERSION"));
    let config = demo_config()?;
    let clock = Arc::new(agent::adapters::clock_fake::FakeClock::new(1_465_182_366_000));
    let broker = Arc::new(agent::adapters::broker_fake::FakeBroker::default());
    let repo = Arc::new(agent::adapters::scope_store_json::JsonScopeRepository::new("scope.json"));

    let scope_state = agent::app::builder::load_scope_state(repo.as_ref()).await?;
    let kernel = agent::app::builder::assemble(agent::app::builder::AgentDeps {
        config: Arc::new(config),
        scope_state,
        scope_repo: Arc::clone(&repo) as Arc<dyn agent::ports::scope_repository::ScopeRepository>,
        broker: Arc::clone(&broker) as Arc<dyn agent::ports::broker::BrokerPort>,
        clock: Arc::clone(&clock) as Arc<dyn agent::ports::clock::SystemClockPort>,
        bus: kernel::bus::InMemoryEventBus::new(1024),
    });

    kernel.boot().await?;
    for event in demo_script() {
        kernel.accept(event).await;
        tokio::task::yield_now().await;
    }
    kernel.accept(SandboxEvent::SessionDeadline).await;
    kernel.shutdown().await;

    println!("published {} wire events this session", broker.event_sequence().len());
    for envelope in broker.of_channel(agent::ports::broker::Channel::Control) {
        println!("control: {}", envelope.event_type);
    }
    println!("scope persisted to scope.json");
    Ok(())
}

/// Full runtime on this host: real clock, file-backed scope, Ctrl+C to stop.
async fn console() -> anyhow::Result<()> {
    println!("{} v{} (console)", agent::NAME, env!("CARGO_PKG_VERSION"));
    let clock = Arc::new(agent::adapters::clock_system::SystemClock);
    let broker = Arc::new(agent::adapters::broker_fake::FakeBroker::default());
    let repo = Arc::new(agent::adapters::scope_store_json::JsonScopeRepository::new("scope.json"));

    let (session, stop_tx, stop_rx) =
        agent::app::runtime::RunningSession::start(agent::app::runtime::SessionDeps {
            config: Arc::new(demo_config()?),
            scope_repo: repo,
            broker,
            clock,
        })
        .await?;

    // Ctrl+C → ServiceStop (the same event SCM delivers).
    let ctrl_c_tx = stop_tx.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = ctrl_c_tx.send(SandboxEvent::ServiceStop).await;
    });

    #[cfg(all(windows, feature = "etw"))]
    attach_etw(&session).await;

    #[cfg(not(all(windows, feature = "etw")))]
    println!("ETW disabled (build with --features etw)");

    drop(stop_tx);
    session.run_until_stop(stop_rx).await?;
    println!("session finalized, agent stopped");
    Ok(())
}

#[cfg(all(windows, feature = "etw"))]
#[allow(clippy::unused_async)] // keeps the console flow shape uniform across features
async fn attach_etw(session: &agent::app::runtime::RunningSession) {
    let adapter = Arc::new(agent::adapters::etw_adapter::EtwKernelTraceAdapter::new(
        8192,
        agent::adapters::etw_adapter::SESSION_NAME,
    ));
    let inlet = session.inlet();
    tokio::spawn(async move {
        if let Err(error) = adapter.run(inlet).await {
            println!("ETW attach failed (admin required?): {error}");
        }
    });
    println!("ETW kernel trace attached");
}

/// SCM service mode (feature `service`).
#[cfg(all(windows, feature = "service"))]
#[allow(clippy::unused_async)] // dispatch signature parity across features
async fn service_mode() -> anyhow::Result<()> {
    windows_service::service_dispatcher::start(
        agent::adapters::service_control::SERVICE_NAME,
        ffi_service_main,
    )
    .map_err(|error| anyhow::anyhow!("service dispatch failed: {error}"))
}

/// Console fallback when built without the `service` feature.
#[cfg(not(all(windows, feature = "service")))]
#[allow(clippy::unused_async)] // signature parity with the real service mode
async fn service_mode() -> anyhow::Result<()> {
    anyhow::bail!("service mode requires building with --features service")
}

/// ETW probe: run a live kernel trace for N seconds and summarize what we see.
#[cfg(all(windows, feature = "etw"))]
async fn etw_probe() -> anyhow::Result<()> {
    struct RecordingInlet;
    #[async_trait::async_trait]
    impl EventInletPort<SandboxEvent> for RecordingInlet {
        async fn accept(&self, event: SandboxEvent) {
            if let SandboxEvent::Source(source) = event {
                println!("  {} :: {source:?}", source.event_type());
            }
        }
    }

    let seconds: u64 = std::env::args().nth(2).and_then(|raw| raw.parse().ok()).unwrap_or(10);
    println!("ETW probe: consuming kernel trace for {seconds}s (admin required)");
    let adapter = Arc::new(agent::adapters::etw_adapter::EtwKernelTraceAdapter::new(
        65_536,
        format!("{}-probe", agent::adapters::etw_adapter::SESSION_NAME),
    ));

    let inlet: Arc<dyn EventInletPort<SandboxEvent>> = Arc::new(RecordingInlet);
    let run = adapter.run(inlet);
    match tokio::time::timeout(std::time::Duration::from_secs(seconds), run).await {
        Err(_elapsed) => {
            adapter.stop().await;
            println!("probe finished; dropped by full queue: {}", adapter.loss_count());
            Ok(())
        }
        Ok(result) => result.map_err(|error| anyhow::anyhow!("{error:?}")),
    }
}

/// Console fallback when built without the `etw` feature.
#[cfg(not(all(windows, feature = "etw")))]
#[allow(clippy::unused_async)] // signature parity with the real probe
async fn etw_probe() -> anyhow::Result<()> {
    anyhow::bail!("etw-probe requires building with --features etw")
}

// Service main (SCM entry point) — only meaningful with the `service` feature.
#[cfg(all(windows, feature = "service"))]
windows_service::define_windows_service!(ffi_service_main, service_main);

/// Service entry: same runtime as console, stop fed by the SCM handler.
#[cfg(all(windows, feature = "service"))]
fn service_main(_args: Vec<std::ffi::OsString>) {
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build();
    match runtime {
        Ok(rt) => {
            if let Err(error) = rt.block_on(run_service_body()) {
                eprintln!("service body failed: {error}");
            }
        }
        Err(error) => eprintln!("failed to build tokio runtime: {error}"),
    }
}

/// Same runtime as console; stop fed by the SCM control handler.
#[cfg(all(windows, feature = "service"))]
async fn run_service_body() -> anyhow::Result<()> {
    let clock = Arc::new(agent::adapters::clock_system::SystemClock);
    let broker = Arc::new(agent::adapters::broker_fake::FakeBroker::default());
    let repo = Arc::new(agent::adapters::scope_store_json::JsonScopeRepository::new("scope.json"));

    let (session, stop_tx, stop_rx) =
        agent::app::runtime::RunningSession::start(agent::app::runtime::SessionDeps {
            config: Arc::new(demo_config()?),
            scope_repo: repo,
            broker,
            clock,
        })
        .await?;

    // SCM handler (sync thread) → runtime stop channel (async).
    let (scm_tx, scm_rx) = std::sync::mpsc::channel::<SandboxEvent>();
    let status = agent::adapters::service_control::register_control_handler(scm_tx)?;
    status.running()?;
    tokio::task::spawn_blocking(move || {
        for event in &scm_rx {
            if stop_tx.blocking_send(event).is_err() {
                break;
            }
        }
    });

    session.run_until_stop(stop_rx).await?;
    status.stopped()?;
    Ok(())
}
