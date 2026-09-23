//! Composition root for the `SecOutfall` agent.
//!
//! Modes (first positional argument):
//! - *(default)* `console` — full runtime on this host; Ctrl+C finalizes.
//! - `simulate` — the phase-3 scripted single-session demo (fakes only).
//! - `service` — SCM service mode (`--features service`).
//! - `install` / `uninstall` — manage the SCM entry (`--features service`).
//! - `etw-probe [seconds]` — live kernel-trace spike probe (`--features etw`).
//!
//! Flags:
//! - `--config <path>` — TOML config location (default `C:\Agent.toml`;
//!   used by console/service/install, ignored by `simulate`/`etw-probe`).
//! - `--start` — with `install`: start the service immediately after creating
//!   it (otherwise it starts at the next boot).
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
        clock::ClockShiftPort,
        process_killer::ProcessKillerPort,
        process_launcher::ProcessLauncherPort,
        shell_association::ShellAssociationPort,
        uploader::FileUploadPort,
    },
};
use kernel::app::api_ports::EventInletPort;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let args = Args::parse();
    match args.mode.as_deref() {
        Some("simulate") => simulate().await,
        Some("service") => service_mode(&args).await,
        Some("install") => service_install(&args),
        Some("uninstall") => service_uninstall(),
        Some("etw-probe") => etw_probe().await,
        _ => console(&args).await,
    }
}

/// Single global subscriber: `registry` + `EnvFilter` (`RUST_LOG`-aware) +
/// console fmt + the `sentry-tracing` layer. The Sentry layer is a no-op
/// until [`init_sentry`] activates a client — layer wiring is fixed at init,
/// the client is not.
fn init_tracing() {
    use tracing_subscriber::{
        EnvFilter,
        layer::SubscriberExt,
        util::SubscriberInitExt,
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,agent=debug"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(sentry_tracing::layer())
        .init();
}

/// Activate Sentry egress to the local `GlitchTip` (doctrine: gated by
/// `[telemetry] sentry_enabled`; timestamps will be skewed by the fake clock
/// — correlate by study/session ids, never by wall time). A malformed DSN is
/// hostile config: warn and continue without egress, never crash.
fn init_sentry(config: &protocol::config::AgentConfig) -> Option<sentry::ClientInitGuard> {
    if !config.telemetry.sentry_enabled {
        tracing::debug!("sentry egress disabled by config");
        return None;
    }
    match config.telemetry.dsn.parse::<sentry::types::Dsn>() {
        Ok(dsn) => {
            let guard = sentry::init(sentry::ClientOptions {
                dsn: Some(dsn),
                release: Some(env!("CARGO_PKG_VERSION").to_owned().into()),
                ..sentry::ClientOptions::default()
            });
            tracing::info!("sentry egress active");
            Some(guard)
        }
        Err(error) => {
            tracing::warn!(%error, "invalid telemetry.dsn; sentry egress disabled");
            None
        }
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
    /// `install`: start the service after creating it.
    start: bool,
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
        let mut parsed = Self {
            mode: None,
            config_path: PathBuf::from("C:\\Agent.toml"),
            demo: false,
            start: false,
        };
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.to_string_lossy().as_ref() {
                "--config" => {
                    if let Some(path) = args.next() {
                        parsed.config_path = PathBuf::from(path);
                    }
                }
                "--demo" => parsed.demo = true,
                "--start" => parsed.start = true,
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

/// Per-boot nonce for the user-actor IPC handshake (uuid-shaped, 32 hex).
fn generate_nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Production wiring: strict TOML config, real NATS broker (legacy retry
/// budget), HTTP uploader, config-driven scope DB location.
async fn production_session_deps(
    config_path: &std::path::Path,
    user_actor_nonce: String,
) -> anyhow::Result<SessionDeps> {
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
        killer: production_killer(),
        shifter: production_shifter(),
        statistics: Arc::new(agent::plugins::statistics::SessionStatistics::default()),
        user_actor_nonce,
        seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        user_actor_pid_gate: Arc::new(std::sync::atomic::AtomicU32::new(0)),
    })
}

/// Launcher selection by config mechanism (adapter availability per feature).
fn production_launcher(config: &protocol::config::AgentConfig) -> Arc<dyn ProcessLauncherPort> {
    match config.platform.launch_mechanism {
        protocol::config::LaunchMechanism::SchedTask => {
            schedtask_launcher(config.platform.runas_utility_path.clone())
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

#[cfg(all(windows, feature = "schedtask"))]
fn schedtask_launcher(helper_path: String) -> Arc<dyn ProcessLauncherPort> {
    Arc::new(agent::adapters::launcher_schedtask::SchedTaskLauncher::new(helper_path))
}

#[cfg(not(all(windows, feature = "schedtask")))]
fn schedtask_launcher(_helper_path: String) -> Arc<dyn ProcessLauncherPort> {
    tracing::warn!("sched-task launcher not compiled in (build with --features schedtask)");
    Arc::new(agent::adapters::launcher_unavailable::UnavailableLauncher::new(
        "build with --features schedtask",
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

/// Finalize process cleanup (Toolhelp adapter is feature-gated).
#[cfg(all(windows, feature = "killer"))]
fn production_killer() -> Arc<dyn ProcessKillerPort> {
    Arc::new(agent::adapters::process_killer_windows::WindowsProcessKiller::new())
}

#[cfg(not(all(windows, feature = "killer")))]
fn production_killer() -> Arc<dyn ProcessKillerPort> {
    Arc::new(agent::adapters::process_killer_fake::UnavailableProcessKiller)
}

/// Clock manipulation (`SetSystemTime` adapter is feature-gated).
#[cfg(all(windows, feature = "time_shift"))]
fn production_shifter() -> Arc<dyn ClockShiftPort> {
    Arc::new(agent::adapters::clock_shift::windows_shifter::WindowsClockShifter::new())
}

#[cfg(not(all(windows, feature = "time_shift")))]
fn production_shifter() -> Arc<dyn ClockShiftPort> {
    Arc::new(agent::adapters::clock_shift::UnavailableClockShifter)
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
        killer: Arc::new(agent::adapters::process_killer_fake::FakeProcessKiller::default()),
        shifter: Arc::clone(&clock) as Arc<dyn ClockShiftPort>,
        statistics: Arc::new(agent::plugins::statistics::SessionStatistics::default()),
        user_actor_nonce: "demo-nonce".to_owned(),
        seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        user_actor_pid_gate: Arc::new(std::sync::atomic::AtomicU32::new(0)),
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
    // One per-boot nonce shared by the supervisor (launch args) and the IPC
    // server (HELLO verification).
    let nonce = generate_nonce();
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
                killer: Arc::new(agent::adapters::process_killer_fake::FakeProcessKiller::default())
                    as Arc<dyn ProcessKillerPort>,
                shifter: Arc::new(agent::adapters::clock_fake::FakeClock::new(0))
                    as Arc<dyn ClockShiftPort>,
                statistics: Arc::new(agent::plugins::statistics::SessionStatistics::default()),
                user_actor_nonce: nonce.clone(),
                seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                user_actor_pid_gate: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            },
            "fake broker (demo)".to_owned(),
        )
    } else {
        println!("{} v{} (console)", agent::NAME, env!("CARGO_PKG_VERSION"));
        (
            production_session_deps(&args.config_path, nonce.clone()).await?,
            args.config_path.display().to_string(),
        )
    };
    println!("config: {broker_kind}");
    // Held for the whole run: dropping the guard shuts the transport down.
    let _sentry_guard = init_sentry(&session_deps.config);

    // The IPC server wants the transport pieces; clone before the deps move.
    let ipc_broker = Arc::clone(&session_deps.broker);
    let ipc_clock = Arc::clone(&session_deps.clock);
    let ipc_config = Arc::clone(&session_deps.config);
    let ipc_pid_gate = Arc::clone(&session_deps.user_actor_pid_gate);

    let (session, stop_tx, stop_rx) =
        agent::app::runtime::RunningSession::start(session_deps).await?;

    if !args.demo {
        attach_ipc(&session, &ipc_config, ipc_broker, ipc_clock, &nonce, ipc_pid_gate).await;
    }

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

/// Attach the user-actor IPC server (feature `ipc`): per-boot nonce,
/// console-user-aware DACL, handshake-evidence wire reporting.
#[cfg(all(windows, feature = "ipc"))]
#[allow(clippy::too_many_arguments)] // uniform wiring shape across features
async fn attach_ipc(
    session: &agent::app::runtime::RunningSession,
    config: &Arc<protocol::config::AgentConfig>,
    broker: Arc<dyn BrokerPort>,
    clock: Arc<dyn agent::ports::clock::SystemClockPort>,
    nonce: &str,
    pid_gate: Arc<std::sync::atomic::AtomicU32>,
) {
    let sddl = agent::adapters::ipc_server::console_user_pipe_sddl().await.unwrap_or_else(|| {
        tracing::warn!("no console-session user; IPC DACL covers SYSTEM/Administrators only");
        agent::adapters::ipc_server::DEFAULT_PIPE_SDDL.to_owned()
    });
    let adapter = agent::adapters::ipc_server::IpcServerAdapter::with_sddl(
        session.scope_state().clone(),
        Arc::new(config.user_actor_config()),
        nonce.to_owned(),
        sddl,
        session.seq(),
    )
    .with_wire_reporter(broker, clock)
    .with_expected_client_pid(pid_gate);
    let inlet = session.inlet();
    tokio::spawn(async move {
        if let Err(error) = adapter.run(inlet).await {
            tracing::error!(%error, "user-actor IPC server failed");
        }
    });
    tracing::info!("user-actor IPC server attached");
}

/// Fallback when built without the `ipc` feature (also the Linux build, where
/// the real adapter never compiles).
#[cfg(not(all(windows, feature = "ipc")))]
#[allow(
    clippy::needless_pass_by_value,
    clippy::trivially_copy_pass_by_ref,
    clippy::too_many_arguments, // signature parity with the real adapter
    clippy::unused_async, // ditto: the real adapter awaits
)]
async fn attach_ipc(
    _session: &agent::app::runtime::RunningSession,
    _config: &Arc<protocol::config::AgentConfig>,
    _broker: Arc<dyn BrokerPort>,
    _clock: Arc<dyn agent::ports::clock::SystemClockPort>,
    _nonce: &str,
    _pid_gate: Arc<std::sync::atomic::AtomicU32>,
) {
    tracing::warn!("built without the ipc feature: user-actor transport disabled");
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

/// Create the SCM entry pointing at this exe (feature `service`).
#[cfg(all(windows, feature = "service"))]
fn service_install(args: &Args) -> anyhow::Result<()> {
    agent::adapters::service_control::install(
        &args.config_path,
        agent::adapters::service_control::InstallOptions { start_after_install: args.start },
    )?;
    println!(
        "service `{}` installed (config: {}){}",
        agent::adapters::service_control::SERVICE_NAME,
        args.config_path.display(),
        if args.start { "; started" } else { "" }
    );
    Ok(())
}

/// Console fallback when built without the `service` feature.
#[cfg(not(all(windows, feature = "service")))]
fn service_install(_args: &Args) -> anyhow::Result<()> {
    anyhow::bail!("install requires building with --features service")
}

/// Stop and delete the SCM entry (feature `service`).
#[cfg(all(windows, feature = "service"))]
fn service_uninstall() -> anyhow::Result<()> {
    agent::adapters::service_control::uninstall()?;
    println!(
        "service `{}` uninstalled; the entry disappears once the current process exits",
        agent::adapters::service_control::SERVICE_NAME
    );
    Ok(())
}

/// Console fallback when built without the `service` feature.
#[cfg(not(all(windows, feature = "service")))]
fn service_uninstall() -> anyhow::Result<()> {
    anyhow::bail!("uninstall requires building with --features service")
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
    let nonce = generate_nonce();
    let deps = production_session_deps(&args.config_path, nonce.clone()).await?;
    // Held for the whole service body: dropping the guard shuts egress down.
    let _sentry_guard = init_sentry(&deps.config);

    // The IPC server wants the transport pieces; clone before the deps move.
    let ipc_broker = Arc::clone(&deps.broker);
    let ipc_clock = Arc::clone(&deps.clock);
    let ipc_config = Arc::clone(&deps.config);
    let ipc_pid_gate = Arc::clone(&deps.user_actor_pid_gate);

    let (session, stop_tx, stop_rx) = agent::app::runtime::RunningSession::start(deps).await?;
    attach_ipc(&session, &ipc_config, ipc_broker, ipc_clock, &nonce, ipc_pid_gate).await;

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
