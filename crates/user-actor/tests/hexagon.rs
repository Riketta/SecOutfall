//! User-actor hexagon flows: config push application, focus-driven
//! screenshots (quota, kill-switch, sink failure), and reactive Enter.
//! Fakes everywhere; deterministic on the current-thread runtime.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    sync::Arc,
    time::Duration,
};

use kernel::{
    app::{
        api_ports::EventInletPort,
        plugin_ports::event_bus_port::EventBusPort as _,
    },
    bus::InMemoryEventBus,
};
use protocol::{
    config::{
        FocusMethod,
        UserActorConfig,
    },
    ipc::messages::Welcome,
};
use user_actor::{
    adapters::{
        app_launcher_fake::FakeAppLauncher,
        capture_fake::{
            FailingCapture,
            FakeCapture,
        },
        input_fake::FakeInput,
        sink_fake::FakeSink,
    },
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
    plugins::reactive::ReactivePlugin,
};

fn welcome(config: UserActorConfig) -> Welcome {
    Welcome { session_id: 3, config }
}

fn focus(pid: u32, title: &str) -> ActorEvent {
    ActorEvent::FocusChanged(user_actor::domain::FocusInfo {
        pid,
        title: title.to_owned(),
        process: Some(format!("proc{pid}.exe")),
    })
}

fn config(screencapture: bool, reactive: bool, quota: u32) -> UserActorConfig {
    UserActorConfig {
        console: false,
        reactive,
        scripted: false,
        focus_method: FocusMethod::Polling,
        screencapture,
        max_screenshots_per_session: quota,
        telemetry_dsn: None,
    }
}

struct Harness {
    kernel: Arc<ActorKernel>,
    runtime: SharedRuntime,
    bus: InMemoryEventBus<ActorBusEvent>,
    capture: Arc<FakeCapture>,
    sink: Arc<FakeSink>,
    input: Arc<FakeInput>,
}

async fn boot(cfg: UserActorConfig) -> Harness {
    let runtime: SharedRuntime = SharedRuntime::default();
    let bus = InMemoryEventBus::new(1024);
    let capture = Arc::new(FakeCapture::new());
    let sink = Arc::new(FakeSink::new());
    let input = Arc::new(FakeInput::new());
    let kernel = Arc::new(assemble(ActorDeps {
        runtime: Arc::clone(&runtime),
        bus: bus.clone(),
        capture: Arc::clone(&capture) as Arc<dyn user_actor::ports::ScreenCapturePort>,
        sink: Arc::clone(&sink) as Arc<dyn user_actor::ports::ScreenshotSinkPort>,
        input: Arc::clone(&input) as Arc<dyn user_actor::ports::InputSynthesisPort>,
        launcher: Arc::new(FakeAppLauncher::default())
            as Arc<dyn user_actor::ports::AppLauncherPort>,
    }));
    kernel.boot().await.unwrap();
    // Push the config the way the IPC adapter would.
    kernel.accept(ActorEvent::Welcome(welcome(cfg))).await;
    Harness { kernel, runtime, bus, capture, sink, input }
}

async fn drain() {
    for _ in 0..6 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn welcome_applies_config_and_session_id() {
    let harness = boot(config(true, false, 5)).await;
    let state = harness.runtime.lock();
    assert_eq!(state.session_id, 3);
    assert!(state.config.as_ref().unwrap().screencapture);
}

#[tokio::test]
async fn focus_changes_capture_up_to_quota_then_stop() {
    let harness = boot(config(true, false, 2)).await;
    let mut rx = harness.bus.subscribe();

    for pid in 1..=4 {
        harness.kernel.accept(focus(pid, "window")).await;
    }
    drain().await;

    assert_eq!(harness.capture.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    let frames = harness.sink.frames();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames.first().unwrap().seq, 0);
    assert_eq!(frames.get(1).unwrap().seq, 1);

    // Exactly one quota-exhausted bus event, ever (even with more focus).
    let mut exhausted = 0;
    while let Ok(event) = rx.try_recv() {
        if matches!(event, ActorBusEvent::CaptureQuotaExhausted) {
            exhausted += 1;
        }
    }
    assert_eq!(exhausted, 1);
    harness.kernel.shutdown().await;
}

#[tokio::test]
async fn screencapture_disabled_means_zero_captures() {
    // Legacy bug #4: screenshots were produced even when disabled.
    let harness = boot(config(false, false, 5)).await;
    harness.kernel.accept(focus(7, "doc.txt")).await;
    drain().await;
    assert_eq!(harness.capture.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(harness.sink.frames().is_empty());
    harness.kernel.shutdown().await;
}

#[tokio::test]
async fn sink_failure_does_not_consume_quota_sequence() {
    let harness = boot(config(true, false, 3)).await;
    harness.sink.fail_sends.store(true, std::sync::atomic::Ordering::SeqCst);
    harness.kernel.accept(focus(1, "a")).await;
    drain().await;
    assert!(harness.sink.frames().is_empty());

    // Transport heals: the next frame keeps sequence 0 (the failed one is gone).
    harness.sink.fail_sends.store(false, std::sync::atomic::Ordering::SeqCst);
    harness.kernel.accept(focus(2, "b")).await;
    drain().await;
    let frames = harness.sink.frames();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames.first().unwrap().seq, 0);
    harness.kernel.shutdown().await;
}

#[tokio::test]
async fn capture_failure_does_not_consume_quota() {
    let runtime: SharedRuntime = SharedRuntime::default();
    let bus = InMemoryEventBus::new(64);
    let failing = Arc::new(FailingCapture::default());
    let sink = Arc::new(FakeSink::new());
    let input = Arc::new(FakeInput::new());
    let kernel = Arc::new(assemble(ActorDeps {
        runtime: Arc::clone(&runtime),
        bus: bus.clone(),
        capture: failing.clone() as Arc<dyn user_actor::ports::ScreenCapturePort>,
        sink: Arc::clone(&sink) as Arc<dyn user_actor::ports::ScreenshotSinkPort>,
        input: Arc::clone(&input) as Arc<dyn user_actor::ports::InputSynthesisPort>,
        launcher: Arc::new(FakeAppLauncher::default())
            as Arc<dyn user_actor::ports::AppLauncherPort>,
    }));
    kernel.boot().await.unwrap();
    kernel.accept(ActorEvent::Welcome(welcome(config(true, false, 2)))).await;
    kernel.accept(focus(1, "a")).await;
    kernel.accept(focus(2, "b")).await;
    kernel.accept(focus(3, "c")).await;
    drain().await;
    assert_eq!(failing.calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert!(sink.frames().is_empty());
    kernel.shutdown().await;
}

#[tokio::test]
async fn reactive_presses_enter_only_when_enabled() {
    // Disabled: focus changes produce no presses.
    let harness = boot(config(false, false, 1)).await;
    let reactive = Arc::new(ReactivePlugin::new(
        harness.bus.clone(),
        Arc::clone(&harness.input) as Arc<dyn user_actor::ports::InputSynthesisPort>,
        Arc::clone(&harness.runtime),
    ));
    let runner = tokio::spawn(reactive.clone().run());
    harness.kernel.accept(focus(5, "dialog")).await;
    drain().await;
    assert!(harness.input.holds().is_empty(), "reactive off must not press");

    // Enabled: the next distinct focus press-and-holds Enter (legacy 300 ms).
    {
        let mut state = harness.runtime.lock();
        let cfg = state.config.as_mut().unwrap();
        cfg.reactive = true;
    }
    harness.kernel.accept(focus(6, "dialog")).await;
    drain().await;
    assert_eq!(harness.input.holds(), vec![300]);
    harness.kernel.shutdown().await;
    runner.abort();
}

#[tokio::test]
async fn focus_before_welcome_is_ignored() {
    let runtime: SharedRuntime = SharedRuntime::default();
    let bus = InMemoryEventBus::new(64);
    let capture = Arc::new(FakeCapture::new());
    let sink = Arc::new(FakeSink::new());
    let input = Arc::new(FakeInput::new());
    let kernel = Arc::new(assemble(ActorDeps {
        runtime: Arc::clone(&runtime),
        bus: bus.clone(),
        capture: Arc::clone(&capture) as Arc<dyn user_actor::ports::ScreenCapturePort>,
        sink: Arc::clone(&sink) as Arc<dyn user_actor::ports::ScreenshotSinkPort>,
        input: Arc::clone(&input) as Arc<dyn user_actor::ports::InputSynthesisPort>,
        launcher: Arc::new(FakeAppLauncher::default())
            as Arc<dyn user_actor::ports::AppLauncherPort>,
    }));
    kernel.boot().await.unwrap();
    kernel.accept(focus(9, "early")).await;
    drain().await;
    assert_eq!(capture.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(runtime.lock().config.is_none());
    kernel.shutdown().await;
}

/// Legacy reactive cadence parity (300 ms Enter hold).
#[test]
fn enter_hold_constant_is_legacy_parity() {
    assert_eq!(user_actor::plugins::reactive::ENTER_HOLD, Duration::from_millis(300));
}
