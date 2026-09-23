//! Chaos: a concurrent focus storm. Several inlets hit the kernel inlet at
//! once (polling + `WinEvent` hooks can overlap); the capture quota must hold
//! exactly, no matter how the tasks interleave.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

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
        capture_fake::FakeCapture,
        input_fake::FakeInput,
        sink_fake::FakeSink,
    },
    app::{
        ActorDeps,
        assemble,
    },
    domain::{
        ActorBusEvent,
        ActorEvent,
        SharedRuntime,
    },
};

fn focus(pid: u32) -> ActorEvent {
    ActorEvent::FocusChanged(user_actor::domain::FocusInfo {
        pid,
        title: format!("storm {pid}"),
        process: Some("storm.exe".to_owned()),
    })
}

fn storm_config() -> UserActorConfig {
    UserActorConfig {
        console: false,
        reactive: false,
        scripted: false,
        focus_method: FocusMethod::Polling,
        screencapture: true,
        max_screenshots_per_session: 5,
        telemetry_dsn: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn focus_storm_cannot_exceed_the_capture_quota() {
    let runtime: SharedRuntime = SharedRuntime::default();
    let bus = InMemoryEventBus::new(4096);
    let capture = Arc::new(FakeCapture::new());
    let sink = Arc::new(FakeSink::new());
    let kernel = Arc::new(assemble(ActorDeps {
        runtime: Arc::clone(&runtime),
        bus: bus.clone(),
        capture: Arc::clone(&capture) as Arc<dyn user_actor::ports::ScreenCapturePort>,
        sink: Arc::clone(&sink) as Arc<dyn user_actor::ports::ScreenshotSinkPort>,
        input: Arc::new(FakeInput::new()) as Arc<dyn user_actor::ports::InputSynthesisPort>,
        launcher: Arc::new(FakeAppLauncher::default())
            as Arc<dyn user_actor::ports::AppLauncherPort>,
    }));
    kernel.boot().await.unwrap();
    // Subscribe before anything publishes so the exhaustion count is total.
    let mut rx = bus.subscribe();
    kernel.accept(ActorEvent::Welcome(Welcome { session_id: 0, config: storm_config() })).await;

    // 200 concurrent inlets against a quota of 5.
    let mut tasks = Vec::new();
    for pid in 0..200_u32 {
        let kernel = Arc::clone(&kernel);
        tasks.push(tokio::spawn(async move { kernel.accept(focus(pid)).await }));
    }
    for task in tasks {
        task.await.unwrap();
    }

    // The quota held exactly: five captures, no more — despite the CAS
    // losers, and every frame is one of the five reserved sequences.
    let frames = sink.frames();
    let mut seqs: Vec<u32> = frames.iter().map(|frame| frame.seq).collect();
    seqs.sort_unstable();
    assert_eq!(frames.len(), 5, "quota must cap concurrent captures");
    assert_eq!(seqs, vec![0, 1, 2, 3, 4], "sequences are the reserved slots");
    assert_eq!(
        capture.calls.load(std::sync::atomic::Ordering::SeqCst),
        5,
        "capture port is invoked only for reserved slots"
    );

    // At most one quota-exhausted event during the storm; the deterministic
    // tail event below guarantees exactly one in total.

    // After the storm the quota is full: one more focus change announces
    // exhaustion (unless a storm task already did), exactly once overall.
    kernel.accept(focus(999)).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    let exhausted = std::sync::atomic::AtomicU32::new(0);
    while let Ok(event) = rx.try_recv() {
        if matches!(event, ActorBusEvent::CaptureQuotaExhausted) {
            exhausted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    assert_eq!(
        exhausted.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "exactly one exhaustion announcement"
    );
    assert_eq!(sink.frames().len(), 5, "post-storm focus change captured nothing");
    kernel.shutdown().await;
}
