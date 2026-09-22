//! Composition root for the `SecOutfall` agent.
//!
//! Modes (first positional argument):
//! - *(default)* `console` — full runtime on this host; Ctrl+C finalizes.
//! - `simulate` — the phase-3 scripted single-session demo (fakes only).
//! - `service` — SCM service mode (`--features service`).
//! - `etw-probe [seconds]` — live kernel-trace spike probe (`--features etw`).
//!
//! Flags:
//! - `--config <path>` — TOML config location (default `C:\Agent.toml`;
//!   ignored by `simulate` and `etw-probe`).
//! - `--demo` — console mode over fakes (demo config + captured broker) for
//!   dev boxes without a NATS broker; never use in a real VM.

use std::{
    path::PathBuf,
    sync::Arc,
};

#[cfg(all(windows, feature = "etw"))]
use agent::ports::event_source::EventSourcePort;
use agent::{
    app::{
        event::SandboxEvent,
        runtime::SessionDeps,
    },
    ports::{
        broker::BrokerPort,
        process_launcher::ProcessLauncherPort,
        shell_association::ShellAssociationPort,
        uploader::FileUploadPort,
    },
};
use kernel::app::api_ports::EventInletPort;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    match args.mode.as_deref() {
        Some("simulate") => simulate().await,
        Some("service") => service_mode(&args).await,
        Some("etw-probe") => etw_probe().await,
        _ => console(&args).await,
    }
}

/// Parsed command line.
struct Args {
    /// Positional mode (`None` = console).
    mode: Option<String>,
    /// Config file location.
    config_path: PathBuf,
    /// Console mode over fakes (dev only).
    demo: bool,
}

impl Args {
    fn parse() -> Self {
        Self::parse_from(std::env::args_os().skip(1))
    }

    /// Parse an explicit argv (SCM passes the service command line here).
    fn parse_from<I>(args: I) -> Self
    where
        I: IntoIterator<Item = std::ffi::OsString>,
    {
        let mut parsed =
            Self { mode: None, config_path: PathBuf::from("C:\\Agent.toml"), demo: false };
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.to_string_lossy().as_ref() {
                "--config" => {
                    if let Some(path) = args.next() {
                        parsed.config_path = PathBuf::from(path);
                    }
                }
                "--demo" => parsed.demo = true,
                positional => {
                    if parsed.mode.is_none() {
                        parsed.mode = Some(positional.to_owned());
                    }
                }
            }
        }
        parsed
    }
}

/// Demo configuration standing in for `C:\Agent.toml` in fake-backed modes;
/// validation runs exactly like production would. Writes go to the temp dir
/// so the demo never pollutes the working directory.
fn demo_config() -> anyhow::Result<protocol::config::AgentConfig> {
    let mut config = protocol::config::AgentConfig::default();
    config.target.path = "C:\\Targets\\evil.exe".into();
    config.study.uptimes = vec![6000];
    config.drops.extensions = vec![".txt".into(), ".exe".into()];
    config.drops.path = std::env::temp_dir().join("secoutfall-demo-drops").display().to_string();
    config.drops.upload_uri = None;
    config.screenshots.path =
        std::env::temp_dir().join("secoutfall-demo-shots").display().to_string();
    config.validate()?;
    Ok(config)
}

/// Production wiring: strict TOML config, real NATS broker (legacy retry
/// budget), HTTP uploader, config-driven scope DB location.
async fn production_session_deps(config_path: &std::path::Path) -> anyhow::Result<SessionDeps> {
    let config = Arc::new(agent::adapters::config_toml::load(config_path)?);
    let broker = agent::adapters::broker_nats::NatsBrokerAdapter::connect(&config.broker).await?;
    tracing::info!(uri = %config.broker.uri, "NATS broker connected");
    Ok(SessionDeps {
        config: Arc::clone(&config),
        scope_repo: Arc::new(agent::adapters::scope_store_json::JsonScopeRepository::new(
            config.study.scope_path.clone(),
        )),
        broker: Arc::new(broker),
        clock: Arc::new(agent::adapters::clock_system::SystemClock),
        uploader: Arc::new(
            agent::adapters::http_upload::HttpUploadAdapter::new()
                .map_err(|error| anyhow::anyhow!("HTTP uploader unavailable: {error}"))?,
        ),
        launcher: production_launcher(&config),
        shell: production_shell(),
    })
}

/// Launcher selection by config mechanism (adapter availability per feature).
fn production_launcher(config: &protocol::config::AgentConfig) -> Arc<dyn ProcessLauncherPort> {
    match config.platform.launch_mechanism {
        protocol::config::LaunchMechanism::SchedTask => {
            tracing::warn!("sched-task launcher not built yet; launching will fail");
            Arc::new(agent::adapters::launcher_unavailable::UnavailableLauncher::new(
                "the sched-task launcher adapter is not implemented yet",
            ))
        }
        protocol::config::LaunchMechanism::Token => token_launcher(),
    }
}

#[cfg(all(windows, feature = "launcher"))]
fn token_launcher() -> Arc<dyn ProcessLauncherPort> {
    Arc::new(agent::adapters::launcher_token::TokenProcessLauncher::new())
}

#[cfg(not(all(windows, feature = "launcher")))]
fn token_launcher() -> Arc<dyn ProcessLauncherPort> {
    tracing::warn!("token launcher not compiled in (build with --features launcher)");
    Arc::new(agent::adapters::launcher_unavailable::UnavailableLauncher::new(
        "build with --features launcher",
    ))
}

/// Shell-association resolver (registry adapter is feature-gated).
#[cfg(all(windows, feature = "associations"))]
fn production_shell() -> Arc<dyn ShellAssociationPort> {
    Arc::new(agent::adapters::shell_association_registry::RegistryShellAssociationAdapter::new())
}

#[cfg(not(all(windows, feature = "associations")))]
fn production_shell() -> Arc<dyn ShellAssociationPort> {
    Arc::new(agent::adapters::shell_association_fake::UnavailableShellAssociation)
}

fn demo_script() -> Vec<SandboxEvent> {
    vec![
        source_process_started(1000, None, "evil.exe"),
        source_process_started(1001, Some(1000), "cmd.exe"),
        source_file_written(1001, "C:\\Users\\victim\\payload.txt"),
        // The close frees the drop for the collector (copy on close, not write).
        SandboxEvent::Source(agent::app::event::SourceEvent::FileCleanedUp(
            protocol::payload::FileReleasedData {
                pid: 1001,
                file_object: Some(1),
                file_key: Some(2),
                file_name: Some("C:\\Users\\victim\\payload.txt".to_owned()),
            },
        )),
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
/// skeleton history and quick end-to-end sanity checks). In-memory scope DB:
/// a demo must not inherit sessions from previous runs (a non-zero session
/// count disables the session-0 target seeding — and rightly so).
async fn simulate() -> anyhow::Result<()> {
    println!("{} v{} (simulate)", agent::NAME, env!("CARGO_PKG_VERSION"));
    let config = demo_config()?;
    let clock = Arc::new(agent::adapters::clock_fake::FakeClock::new(1_465_182_366_000));
    let broker = Arc::new(agent::adapters::broker_fake::FakeBroker::default());
    let uploader = Arc::new(agent::adapters::upload_fake::FakeUploader::default());
    let repo = Arc::new(agent::adapters::scope_store_memory::InMemoryScopeRepository::default());

    let scope_state = agent::app::builder::load_scope_state(repo.as_ref()).await?;
    let kernel = agent::app::builder::assemble(agent::app::builder::AgentDeps {
        config: Arc::new(config),
        scope_state,
        scope_repo: Arc::clone(&repo) as Arc<dyn agent::ports::scope_repository::ScopeRepository>,
        broker: Arc::clone(&broker) as Arc<dyn agent::ports::broker::BrokerPort>,
        clock: Arc::clone(&clock) as Arc<dyn agent::ports::clock::SystemClockPort>,
        uploader: Arc::clone(&uploader) as Arc<dyn FileUploadPort>,
        launcher: Arc::new(agent::adapters::launcher_fake::FakeLauncher::default()),
        shell: Arc::new(agent::adapters::shell_association_fake::FakeShellAssociation::new()),
        bus: kernel::bus::InMemoryEventBus::new(1024),
    });

    kernel.boot().await?;
    for event in demo_script() {
        kernel.accept(event).await;
        // The collector acts on the bus asynchronously; yield between events.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    kernel.accept(SandboxEvent::SessionDeadline).await;
    kernel.shutdown().await;

    println!("published {} wire events this session", broker.event_sequence().len());
    for envelope in broker.of_channel(agent::ports::broker::Channel::Event) {
        println!("  event: {}", envelope.event_type);
    }
    for envelope in broker.of_channel(agent::ports::broker::Channel::Control) {
        println!("  control: {}", envelope.event_type);
    }
    println!("collector uploads: {} (demo drop source does not exist)", uploader.uploads().len());
    println!("scope state: in-memory (demo)");
    Ok(())
}

/// Full runtime on this host: real config + broker, real clock, Ctrl+C to
/// stop. `--demo` swaps every adapter for a fake (dev boxes without NATS).
async fn console(args: &Args) -> anyhow::Result<()> {
    let (session_deps, broker_kind) = if args.demo {
        println!("{} v{} (console, demo)", agent::NAME, env!("CARGO_PKG_VERSION"));
        (
            SessionDeps {
                config: Arc::new(demo_config()?),
                scope_repo: Arc::new(agent::adapters::scope_store_json::JsonScopeRepository::new(
                    "scope.json",
                )),
                broker: Arc::new(agent::adapters::broker_fake::FakeBroker::default())
                    as Arc<dyn BrokerPort>,
                clock: Arc::new(agent::adapters::clock_system::SystemClock),
                uploader: Arc::new(agent::adapters::upload_fake::FakeUploader::default())
                    as Arc<dyn FileUploadPort>,
                launcher: Arc::new(agent::adapters::launcher_fake::FakeLauncher::default())
                    as Arc<dyn ProcessLauncherPort>,
                shell: Arc::new(agent::adapters::shell_association_fake::FakeShellAssociation::new())
                    as Arc<dyn ShellAssociationPort>,
            },
            "fake broker (demo)".to_owned(),
        )
    } else {
        println!("{} v{} (console)", agent::NAME, env!("CARGO_PKG_VERSION"));
        (production_session_deps(&args.config_path).await?, args.config_path.display().to_string())
    };
    println!("config: {broker_kind}");

    let (session, stop_tx, stop_rx) =
        agent::app::runtime::RunningSession::start(session_deps).await?;

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
async fn service_mode(_args: &Args) -> anyhow::Result<()> {
    windows_service::service_dispatcher::start(
        agent::adapters::service_control::SERVICE_NAME,
        ffi_service_main,
    )
    .map_err(|error| anyhow::anyhow!("service dispatch failed: {error}"))
}

/// Console fallback when built without the `service` feature.
#[cfg(not(all(windows, feature = "service")))]
#[allow(clippy::unused_async)] // signature parity with the real service mode
async fn service_mode(_args: &Args) -> anyhow::Result<()> {
    anyhow::bail!("service mode requires building with --features service")
}

/// ETW probe: run a live kernel trace for N seconds and summarize what we see.
#[cfg(all(windows, feature = "etw"))]
async fn etw_probe() -> anyhow::Result<()> {
    struct RecordingInlet;
    #[async_trait::async_trait]
    impl kernel::app::api_ports::EventInletPort<SandboxEvent> for RecordingInlet {
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

    let inlet: Arc<dyn kernel::app::api_ports::EventInletPort<SandboxEvent>> =
        Arc::new(RecordingInlet);
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
fn service_main(args: Vec<std::ffi::OsString>) {
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build();
    match runtime {
        Ok(rt) => {
            if let Err(error) = rt.block_on(run_service_body(args)) {
                eprintln!("service body failed: {error}");
            }
        }
        Err(error) => eprintln!("failed to build tokio runtime: {error}"),
    }
}

/// Same runtime as console; stop fed by the SCM control handler.
#[cfg(all(windows, feature = "service"))]
async fn run_service_body(args: Vec<std::ffi::OsString>) -> anyhow::Result<()> {
    // SCM passes the service command line (ImagePath arguments included), so
    // `--config <path>` set at install time lands here.
    let args = Args::parse_from(args);
    let deps = production_session_deps(&args.config_path).await?;

    let (session, stop_tx, stop_rx) = agent::app::runtime::RunningSession::start(deps).await?;

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
