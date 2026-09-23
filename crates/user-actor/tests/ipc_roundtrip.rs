//! Cross-crate IPC roundtrip: the agent's real named-pipe server against the
//! user-actor's real client adapter — handshake, config push, screenshot
//! delivery, handshake-evidence wire reports, and one-strike rejection.
//!
//! Uses a unique pipe name so parallel test binaries never compete for
//! `first_pipe_instance` with the agent crate's own IPC tests.
#![cfg(all(windows, feature = "ipc"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    sync::{
        Arc,
        atomic::AtomicU64,
    },
    time::Duration,
};

use agent::{
    adapters::{
        broker_fake::FakeBroker,
        clock_fake::FakeClock,
        ipc_server::IpcServerAdapter,
        scope_store_memory::InMemoryScopeRepository,
    },
    app::event::SandboxEvent,
    domain::scope::SharedScopeState,
    ports::broker::Channel,
};
use kernel::app::api_ports::EventInletPort;
use protocol::{
    config::UserActorConfig,
    ipc::messages::Welcome,
};
use tokio_util::sync::CancellationToken;
use user_actor::{
    adapters::ipc_client::{
        IpcClientAdapter,
        IpcClientError,
        IpcClientOptions,
    },
    domain::ActorEvent,
    ports::ScreenshotSinkPort as _,
};

/// Screenshot bytes recognizable end to end.
fn jpeg_stub() -> Vec<u8> {
    vec![0xFF, 0xD8, 0x42, 0x00, 0x11, 0x22, 0x33]
}

/// Unique per-process pipe name (parallel test binaries).
fn test_pipe() -> String {
    format!("\\\\.\\pipe\\secoutfall\\test-ua-{}", std::process::id())
}

/// What the agent pipeline received from the pipe.
#[derive(Default)]
struct AgentInlet {
    frames: parking_lot::Mutex<Vec<(u32, Vec<u8>)>>,
}

#[async_trait::async_trait]
impl EventInletPort<SandboxEvent> for AgentInlet {
    async fn accept(&self, event: SandboxEvent) {
        if let SandboxEvent::ScreenshotReceived(frame) = event {
            self.frames.lock().push((frame.seq, frame.jpeg));
        }
    }
}

/// What the user actor received from the agent.
#[derive(Default)]
struct ActorInlet {
    welcomes: parking_lot::Mutex<Vec<Welcome>>,
}

#[async_trait::async_trait]
impl EventInletPort<ActorEvent> for ActorInlet {
    async fn accept(&self, event: ActorEvent) {
        if let ActorEvent::Welcome(welcome) = event {
            self.welcomes.lock().push(welcome);
        }
    }
}

/// Boot the agent-side server with handshake-evidence wire reporting.
async fn boot_server(
    pipe: &str,
    nonce: &str,
    inlet: Arc<AgentInlet>,
    broker: Arc<FakeBroker>,
) -> Arc<IpcServerAdapter> {
    let repo = Arc::new(InMemoryScopeRepository::default());
    let state: SharedScopeState =
        agent::app::builder::load_scope_state(repo.as_ref()).await.unwrap();
    let adapter = Arc::new(
        IpcServerAdapter::with_sddl(
            state,
            Arc::new(UserActorConfig {
                screencapture: true,
                max_screenshots_per_session: 9,
                ..UserActorConfig::default()
            }),
            nonce.to_owned(),
            // Test-only DACL: the non-elevated test client would be denied by
            // the production SYSTEM/Administrators set (AU keeps it testable).
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)".to_owned(),
            Arc::new(AtomicU64::new(0)),
        )
        .with_pipe_name(pipe.to_owned())
        .with_wire_reporter(broker, Arc::new(FakeClock::new(1_465_182_366_000))),
    );
    let runner = Arc::clone(&adapter);
    tokio::spawn(async move {
        let _ = runner.run(inlet).await;
    });
    adapter
}

fn client_options(pipe: &str, nonce: &str) -> IpcClientOptions {
    IpcClientOptions {
        pipe_name: pipe.to_owned(),
        nonce: nonce.to_owned(),
        module_version: env!("CARGO_PKG_VERSION").to_owned(),
        connect_deadline: Duration::from_secs(5),
    }
}

async fn wait_for<T>(what: &str, probe: impl Fn() -> Option<T>) -> T {
    for _ in 0..400 {
        if let Some(value) = probe() {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("{what} never arrived");
}

#[tokio::test]
async fn handshake_config_push_and_screenshot_roundtrip() {
    let pipe = test_pipe();
    let nonce = "b00bfeed".to_owned();
    let broker = Arc::new(FakeBroker::default());
    let agent_inlet = Arc::new(AgentInlet::default());
    let server = boot_server(&pipe, &nonce, Arc::clone(&agent_inlet), Arc::clone(&broker)).await;

    let (sink, queue) = IpcClientAdapter::channel();
    let actor_inlet = Arc::new(ActorInlet::default());
    let cancel = CancellationToken::new();
    let client =
        Arc::new(IpcClientAdapter::new(client_options(&pipe, &nonce), queue, cancel.clone()));
    let run = {
        let client = Arc::clone(&client);
        let inlet = Arc::clone(&actor_inlet);
        tokio::spawn(async move { client.run(inlet as Arc<dyn EventInletPort<ActorEvent>>).await })
    };

    // 1. HELLO verified → WELCOME config push reaches the user actor.
    let welcomes = wait_for("WELCOME", || {
        let guard = actor_inlet.welcomes.lock();
        (!guard.is_empty()).then(|| guard.clone())
    })
    .await;
    assert_eq!(welcomes.first().unwrap().session_id, 0);
    assert!(welcomes.first().unwrap().config.screencapture);

    // 2. Screenshot through the sink decodes at the agent inlet.
    sink.send(4, jpeg_stub()).await.unwrap();
    let frames = wait_for("screenshot at the agent", || {
        let guard = agent_inlet.frames.lock();
        (!guard.is_empty()).then(|| guard.clone())
    })
    .await;
    assert_eq!(frames.first().unwrap().0, 4);
    assert_eq!(frames.first().unwrap().1, jpeg_stub());

    // 3. Verified handshake published user_actor.started with the real
    //    module version.
    let started = wait_for("user_actor.started", || {
        broker
            .of_channel(Channel::Event)
            .into_iter()
            .find(|envelope| matches!(envelope.data, protocol::nats::Payload::UserActorStarted(_)))
            .map(|envelope| match envelope.data {
                protocol::nats::Payload::UserActorStarted(data) => data,
                _ => unreachable!(),
            })
    })
    .await;
    assert_eq!(started.module_version, env!("CARGO_PKG_VERSION"));
    assert!(started.pid.is_some(), "client pid is captured at the server");

    // 4. Shut both ends down: the established connection ending (either
    //    direction) is reported as user_actor.stopped.
    cancel.cancel();
    server.stop();
    let outcome = tokio::time::timeout(Duration::from_secs(5), run).await.unwrap();
    assert!(matches!(outcome, Ok(Ok(()))), "client run ends cleanly on cancel: {outcome:?}");
    wait_for("user_actor.stopped", || {
        broker
            .of_channel(Channel::Event)
            .into_iter()
            .any(|envelope| matches!(envelope.data, protocol::nats::Payload::UserActorStopped(_)))
            .then_some(())
    })
    .await;
}

#[tokio::test]
async fn wrong_nonce_is_fatal_for_the_client() {
    let pipe = format!("{}-wrong", test_pipe());
    let broker = Arc::new(FakeBroker::default());
    let server =
        boot_server(&pipe, "the-real-nonce", Arc::new(AgentInlet::default()), broker).await;

    let (_sink, queue) = IpcClientAdapter::channel();
    let client = Arc::new(IpcClientAdapter::new(
        client_options(&pipe, "impostor"),
        queue,
        CancellationToken::new(),
    ));
    let result = {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            client.run(Arc::new(ActorInlet::default()) as Arc<dyn EventInletPort<ActorEvent>>).await
        })
        .await
        .unwrap()
    };
    assert!(matches!(result, Err(IpcClientError::HandshakeRejected)), "{result:?}");

    // The server survived the impostor: the next client with the right nonce
    // still connects and gets the config push.
    let (sink, queue) = IpcClientAdapter::channel();
    let actor_inlet = Arc::new(ActorInlet::default());
    let client = Arc::new(IpcClientAdapter::new(
        client_options(&pipe, "the-real-nonce"),
        queue,
        CancellationToken::new(),
    ));
    let run = {
        let client = Arc::clone(&client);
        let inlet = Arc::clone(&actor_inlet);
        tokio::spawn(async move { client.run(inlet as Arc<dyn EventInletPort<ActorEvent>>).await })
    };
    wait_for("post-impostor WELCOME", || {
        let guard = actor_inlet.welcomes.lock();
        (!guard.is_empty()).then_some(())
    })
    .await;
    drop(sink);
    server.stop();
    let _ = tokio::time::timeout(Duration::from_secs(5), run).await;
}
