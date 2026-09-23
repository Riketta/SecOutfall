//! Composition root for the `SecOutfall` user-actor.
//!
//! Usage: `secoutfall-user-actor --nonce <hex>` (the per-boot nonce the agent
//! generated and passed at launch). Everything else arrives through the IPC
//! `WELCOME` push — the module reads no files. The focus source starts only
//! after the config push names it.

use std::sync::{
    Arc,
    atomic::{
        AtomicBool,
        Ordering,
    },
};

use kernel::app::{
    api_ports::EventInletPort,
    plugin_ports::event_bus_port::EventBusPort as _,
};
use user_actor::{
    adapters::capture_fake::UnavailableCapture,
    app::{
        ActorDeps,
        ActorKernel,
        assemble,
    },
    domain::{
        ActorBusEvent,
        ActorEvent,
        SharedRuntime,
    },
    ports::{
        AppLauncherPort,
        InputSynthesisPort,
        ScreenCapturePort,
        ScreenshotSinkPort,
    },
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    init_tracing();
    tracing::debug!(nonce_len = args.nonce.len(), "user actor launching");
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "user actor starting");

    let runtime: SharedRuntime = SharedRuntime::default();
    let bus = kernel::bus::InMemoryEventBus::new(1024);
    let cancel = tokio_util::sync::CancellationToken::new();

    // The screenshot sink pair is created before assembly: plugins receive
    // the sink half at construction, the IPC client (feature `ipc`) owns the
    // queue half and drains it over the wire.
    let (sink, sink_rx) = transport_parts();

    let kernel: Arc<ActorKernel> = Arc::new(assemble(ActorDeps {
        runtime: Arc::clone(&runtime),
        bus: bus.clone(),
        capture: build_capture(),
        input: build_input(),
        launcher: build_app_launcher(),
        sink,
    }));
    kernel.boot().await?;

    let inlet: Arc<dyn EventInletPort<ActorEvent>> = Arc::clone(&kernel) as _;
    let client_task = build_ipc(&args, Arc::clone(&inlet), sink_rx, cancel.clone());

    // The configured focus source starts only after the config push.
    let watcher = tokio::spawn(start_focus_source_when_configured(
        bus,
        Arc::clone(&inlet),
        cancel.child_token(),
    ));

    let client_task = client_task.unwrap_or_else(|| {
        tracing::error!("built without the ipc feature: no transport to the agent; parking");
        tokio::spawn(async {
            std::future::pending::<()>().await;
            Err(anyhow::anyhow!("unreachable"))
        })
    });

    let result = tokio::select! {
        joined = client_task => match joined {
            Ok(Ok(())) => {
                tracing::info!("ipc client finished");
                Ok(())
            }
            Ok(Err(error)) => Err(error),
            Err(error) => Err(anyhow::anyhow!("ipc task join: {error}")),
        },
        () = cancel.cancelled() => Ok(()),
        () = shutdown_signal() => {
            tracing::info!("shutdown signal received");
            Ok(())
        }
    };

    cancel.cancel();
    watcher.abort();
    kernel.shutdown().await;
    tracing::info!("user actor stopped");
    result
}

struct Args {
    nonce: String,
}

impl Args {
    fn parse() -> Self {
        let mut nonce = None;
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--nonce" => nonce = args.next(),
                unknown => {
                    eprintln!("unknown argument `{unknown}`; usage: --nonce <hex>");
                    std::process::exit(2);
                }
            }
        }
        match nonce {
            Some(nonce) if !nonce.is_empty() => Self { nonce },
            _ => {
                eprintln!("missing --nonce <hex> (the agent passes its per-boot nonce)");
                std::process::exit(2);
            }
        }
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,user_actor=debug"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_target(false).try_init();
}

/// The sink half for the plugins plus the queue for the transport. Without
/// the `ipc` feature the sink fails closed and the queue is dropped.
/// Sink half plus the queue the transport drains.
type SinkQueue = (Arc<dyn ScreenshotSinkPort>, tokio::sync::mpsc::Receiver<(u32, Vec<u8>)>);

#[cfg(all(windows, feature = "ipc"))]
fn transport_parts() -> SinkQueue {
    let (sink, rx) = user_actor::adapters::ipc_client::IpcClientAdapter::channel();
    (Arc::new(sink), rx)
}

#[cfg(not(all(windows, feature = "ipc")))]
fn transport_parts() -> SinkQueue {
    (Arc::new(user_actor::adapters::sink_fake::UnavailableSink), tokio::sync::mpsc::channel(1).1)
}

/// IPC transport (feature `ipc`): builds the client (its inlet is the
/// kernel) and returns the run task. `None` when built without the feature.
#[cfg(all(windows, feature = "ipc"))]
#[allow(clippy::unnecessary_wraps)] // the no-ipc build returns None here
fn build_ipc(
    args: &Args,
    inlet: Arc<dyn EventInletPort<ActorEvent>>,
    sink_rx: tokio::sync::mpsc::Receiver<(u32, Vec<u8>)>,
    cancel: tokio_util::sync::CancellationToken,
) -> Option<tokio::task::JoinHandle<anyhow::Result<()>>> {
    let client = user_actor::adapters::ipc_client::IpcClientAdapter::new(
        user_actor::adapters::ipc_client::IpcClientOptions::new(
            args.nonce.clone(),
            env!("CARGO_PKG_VERSION").to_owned(),
        ),
        sink_rx,
        cancel,
    );
    Some(tokio::spawn(async move {
        client.run(inlet).await.map_err(|error| anyhow::anyhow!("ipc client: {error}"))
    }))
}

#[cfg(not(all(windows, feature = "ipc")))]
#[allow(clippy::needless_pass_by_value)] // signature parity with the real transport
#[allow(clippy::ref_option)] // keep the call site identical across features
fn build_ipc(
    _args: &Args,
    _inlet: Arc<dyn EventInletPort<ActorEvent>>,
    _sink_rx: tokio::sync::mpsc::Receiver<(u32, Vec<u8>)>,
    _cancel: tokio_util::sync::CancellationToken,
) -> Option<tokio::task::JoinHandle<anyhow::Result<()>>> {
    None
}

fn build_capture() -> Arc<dyn ScreenCapturePort> {
    #[cfg(all(windows, feature = "capture"))]
    match user_actor::adapters::screen_capture::GdiScreenCapture::new(
        user_actor::adapters::screen_capture::DEFAULT_JPEG_QUALITY,
    ) {
        Ok(capture) => return Arc::new(capture),
        Err(error) => tracing::error!(%error, "GDI capture unavailable"),
    }
    #[cfg(not(all(windows, feature = "capture")))]
    tracing::warn!("built without the capture feature: screenshots disabled");
    Arc::new(UnavailableCapture)
}

fn build_input() -> Arc<dyn InputSynthesisPort> {
    #[cfg(all(windows, feature = "input"))]
    return Arc::new(user_actor::adapters::input_synthesis::SendInputSynthesizer::new());
    #[cfg(not(all(windows, feature = "input")))]
    {
        tracing::warn!("built without the input feature: reactive input disabled");
        Arc::new(user_actor::adapters::input_fake::UnavailableInput)
    }
}

fn build_app_launcher() -> Arc<dyn AppLauncherPort> {
    #[cfg(all(windows, feature = "apps"))]
    return Arc::new(user_actor::adapters::app_launcher::NativeAppLauncher::new());
    #[cfg(not(all(windows, feature = "apps")))]
    {
        tracing::warn!("built without the apps feature: scripted activities cannot launch");
        Arc::new(user_actor::adapters::app_launcher_fake::UnavailableAppLauncher)
    }
}

/// Wait for the config push on the bus, then start the configured focus
/// source (polling or `WinEvents`). Falls back with a warning when the
/// needed feature is not compiled in.
async fn start_focus_source_when_configured(
    bus: kernel::bus::InMemoryEventBus<ActorBusEvent>,
    inlet: Arc<dyn EventInletPort<ActorEvent>>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let mut rx = bus.subscribe();
    let started = AtomicBool::new(false);
    loop {
        match rx.recv().await {
            Ok(ActorBusEvent::ConfigApplied(config)) => {
                if started.swap(true, Ordering::SeqCst) {
                    continue; // re-pushes (GET_CONFIG) do not restart the source
                }
                start_focus_source(config.focus_method, Arc::clone(&inlet), cancel.child_token());
            }
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                tracing::warn!(missed, "focus watcher lagged on the bus");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
        }
    }
}

fn start_focus_source(
    method: protocol::config::FocusMethod,
    inlet: Arc<dyn EventInletPort<ActorEvent>>,
    cancel: tokio_util::sync::CancellationToken,
) {
    match method {
        protocol::config::FocusMethod::Polling => start_polling(inlet, cancel),
        protocol::config::FocusMethod::WinEvents => start_winevents(inlet, cancel),
        protocol::config::FocusMethod::WinEventsWithElements => {
            // UIA element tracking is not in scope yet; hook like WinEvents.
            tracing::info!(
                "focus_method win_events_with_elements: UIA not yet supported, hooking window events"
            );
            start_winevents(inlet, cancel);
        }
    }
}

#[cfg(all(windows, feature = "focus-poll"))]
fn start_polling(
    inlet: Arc<dyn EventInletPort<ActorEvent>>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let adapter = user_actor::adapters::focus_poll::PollingFocusAdapter::new(
        user_actor::adapters::focus_poll::DEFAULT_POLL_INTERVAL,
        cancel,
    );
    tokio::spawn(async move {
        if let Err(error) = adapter.run(Arc::clone(&inlet)).await {
            tracing::error!(%error, "polling focus source failed");
        }
    });
    tracing::info!("focus source: polling (50 ms)");
}

#[cfg(not(all(windows, feature = "focus-poll")))]
fn start_polling(
    _inlet: Arc<dyn EventInletPort<ActorEvent>>,
    _cancel: tokio_util::sync::CancellationToken,
) {
    tracing::warn!("focus_method polling needs the focus-poll feature");
}

#[cfg(all(windows, feature = "focus-winevents"))]
fn start_winevents(
    inlet: Arc<dyn EventInletPort<ActorEvent>>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let adapter = user_actor::adapters::focus_winevents::WinEventFocusAdapter::new(cancel);
    tokio::spawn(async move {
        if let Err(error) = adapter.run(Arc::clone(&inlet)).await {
            tracing::error!(%error, "win-event focus source failed");
        }
    });
    tracing::info!("focus source: win events");
}

#[cfg(not(all(windows, feature = "focus-winevents")))]
fn start_winevents(
    _inlet: Arc<dyn EventInletPort<ActorEvent>>,
    _cancel: tokio_util::sync::CancellationToken,
) {
    tracing::warn!("focus_method win_events needs the focus-winevents feature");
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
