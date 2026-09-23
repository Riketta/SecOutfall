//! IPC v1 server end-to-end: real named pipe, real framing, real handshake —
//! the only thing faked is the user-actor at the other end of the pipe.
//!
//! Exercises: nonce rejection (one strike), the HELLO→WELCOME config push,
//! `GET_CONFIG` re-pull, screenshot frame → inlet delivery, clean shutdown.
#![cfg(all(windows, feature = "ipc"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    io,
    sync::{
        Arc,
        atomic::{
            AtomicU64,
            Ordering,
        },
    },
    time::Duration,
};

use agent::{
    adapters::{
        clock_fake::FakeClock,
        ipc_server::IpcServerAdapter,
        scope_store_memory::InMemoryScopeRepository,
    },
    app::event::{
        SandboxEvent,
        ScreenshotFrame,
    },
    domain::scope::SharedScopeState,
};
use kernel::app::api_ports::EventInletPort;
use protocol::{
    config::UserActorConfig,
    ipc::{
        FrameHeader,
        HEADER_LEN,
        message_type,
        messages::{
            Hello,
            Welcome,
            decode_screenshot,
            encode_screenshot,
        },
    },
};
use tokio::{
    io::{
        AsyncReadExt as _,
        AsyncWriteExt as _,
    },
    net::windows::named_pipe::ClientOptions,
    time::sleep,
};

/// What the pipeline received from the pipe.
#[derive(Default)]
struct RecordingInlet {
    frames: parking_lot::Mutex<Vec<ScreenshotFrame>>,
}

impl RecordingInlet {
    fn frames(&self) -> Vec<ScreenshotFrame> {
        self.frames.lock().clone()
    }
}

#[async_trait::async_trait]
impl EventInletPort<SandboxEvent> for RecordingInlet {
    async fn accept(&self, event: SandboxEvent) {
        if let SandboxEvent::ScreenshotReceived(frame) = event {
            self.frames.lock().push(frame);
        }
    }
}

struct TestClient(tokio::net::windows::named_pipe::NamedPipeClient);

impl TestClient {
    async fn open(pipe: &str) -> io::Result<Self> {
        for _ in 0..200 {
            if let Ok(client) = ClientOptions::new().open(pipe) {
                return Ok(Self(client));
            }
            sleep(Duration::from_millis(10)).await;
        }
        Err(io::Error::other("pipe never appeared"))
    }

    async fn send_frame(&mut self, message_type: u16, payload: &[u8]) {
        let header = FrameHeader {
            payload_len: u32::try_from(payload.len()).unwrap(),
            message_type,
            flags: 0,
        };
        self.0.write_all(&header.to_bytes()).await.unwrap();
        self.0.write_all(payload).await.unwrap();
        self.0.flush().await.unwrap();
    }

    async fn read_frame(&mut self) -> io::Result<(FrameHeader, Vec<u8>)> {
        let mut header = [0_u8; HEADER_LEN];
        self.0.read_exact(&mut header).await?;
        let frame = FrameHeader::from_bytes(&header).unwrap();
        let mut payload = vec![0_u8; frame.payload_len as usize];
        self.0.read_exact(&mut payload).await?;
        Ok((frame, payload))
    }

    async fn expect_disconnect(&mut self) {
        let mut byte = [0_u8; 1];
        let result = self.0.read(&mut byte).await;
        assert!(
            matches!(result, Ok(0) | Err(_)),
            "server must close the connection, got {result:?}"
        );
    }
}

fn hello_payload(nonce: &str) -> Vec<u8> {
    serde_json::to_vec(&Hello {
        protocol: protocol::ipc::messages::IPC_PROTOCOL_VERSION,
        nonce: nonce.to_owned(),
        module_version: "0.1.0".to_owned(),
    })
    .unwrap()
}

/// Unique per-test pipe name: parallel tests in one binary must not compete
/// for `first_pipe_instance` or cross-connect to each other's servers.
fn test_pipe(suffix: &str) -> String {
    format!("\\\\.\\pipe\\secoutfall\\test-{suffix}-{}", std::process::id())
}

#[tokio::test]
async fn ipc_server_handshake_config_and_screenshots() {
    let repo = Arc::new(InMemoryScopeRepository::default());
    let state: SharedScopeState =
        agent::app::builder::load_scope_state(repo.as_ref()).await.unwrap();
    let user_actor_config = Arc::new(UserActorConfig::default());
    let nonce = "feedc0ffee".to_owned();
    let seq = Arc::new(AtomicU64::new(0));
    let pipe = test_pipe("handshake");

    let adapter = Arc::new(
        IpcServerAdapter::with_sddl(
            state.clone(),
            Arc::clone(&user_actor_config),
            nonce.clone(),
            // Test-only loosening: the production DACL (SYSTEM + Administrators,
            // plus the launch user once the launcher lands) would deny this
            // non-elevated test client. AU keeps the handshake testable.
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)".to_owned(),
            Arc::clone(&seq),
        )
        .with_pipe_name(pipe.clone()),
    );
    let inlet = Arc::new(RecordingInlet::default());
    let (result_tx, mut result_rx) = tokio::sync::oneshot::channel();
    let run_handle = {
        let adapter = Arc::clone(&adapter);
        let inlet = Arc::clone(&inlet);
        tokio::spawn(async move {
            let _ = result_tx.send(adapter.run(inlet).await);
        })
    };
    let server_error = |rx: &mut tokio::sync::oneshot::Receiver<
        Result<(), agent::adapters::ipc_server::IpcServerError>,
    >| {
        match rx.try_recv() {
            Ok(Ok(())) => "completed".to_owned(),
            Ok(Err(error)) => format!("{error:?}"),
            Err(_) => "still running".to_owned(),
        }
    };

    // 1. Wrong nonce: ERROR frame, then one-strike disconnect.
    let mut client = TestClient::open(&pipe).await.unwrap_or_else(|error| {
        panic!("pipe never appeared; server: {} ({error})", server_error(&mut result_rx))
    });
    client.send_frame(message_type::HELLO, &hello_payload("wrong-nonce")).await;
    let (frame, payload) = client.read_frame().await.unwrap();
    assert_eq!(frame.message_type, message_type::ERROR);
    let error: protocol::ipc::messages::ErrorFrame = serde_json::from_slice(&payload).unwrap();
    assert!(error.error.contains("rejected"), "{error:?}");
    client.expect_disconnect().await;
    drop(client);

    // 2. Correct nonce: WELCOME carries session id + pushed config.
    let mut client = TestClient::open(&pipe).await.unwrap();
    client.send_frame(message_type::HELLO, &hello_payload(&nonce)).await;
    let (frame, payload) = client.read_frame().await.unwrap();
    assert_eq!(frame.message_type, message_type::WELCOME);
    let welcome: Welcome = serde_json::from_slice(&payload).unwrap();
    assert_eq!(welcome.session_id, 0, "fresh scope: session 0");
    assert_eq!(welcome.config, *user_actor_config);

    // 3. GET_CONFIG re-pull answers with the same WELCOME.
    client
        .send_frame(
            message_type::GET_CONFIG,
            &serde_json::to_vec(&protocol::ipc::messages::GetConfig {}).unwrap(),
        )
        .await;
    let (frame, payload) = client.read_frame().await.unwrap();
    assert_eq!(frame.message_type, message_type::WELCOME);
    let repull: Welcome = serde_json::from_slice(&payload).unwrap();
    assert_eq!(repull, welcome);

    // 4. Screenshot frame reaches the inlet decoded.
    let jpeg = [0xFF_u8, 0xD8, 0x42, 0x00, 0x11];
    client.send_frame(message_type::SCREENSHOT, &encode_screenshot(7, &jpeg)).await;
    for _ in 0..100 {
        if !inlet.frames().is_empty() {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    let frames = inlet.frames();
    assert_eq!(frames.len(), 1, "one screenshot frame delivered");
    assert_eq!(frames.first().unwrap().seq, 7);
    assert_eq!(frames.first().unwrap().jpeg, jpeg.to_vec());

    // 5. Clean shutdown: stop() ends the server task.
    adapter.stop();
    let result = tokio::time::timeout(Duration::from_secs(5), run_handle).await;
    assert!(result.is_ok(), "server task must end after stop");
    assert!(seq.load(Ordering::SeqCst) >= 1, "frames are counted");
    // decode_screenshot reference keeps the import honest on both code paths.
    let _ = decode_screenshot(&encode_screenshot(0, &[]));
    let _ = FakeClock::new(0);
}

/// A peer dying mid-frame (header sent, payload never arrives — or the
/// reverse) must hand the server back to the accept loop unharmed: the next
/// client gets a full handshake.
#[tokio::test]
async fn peer_death_mid_frame_returns_server_to_accept_loop() {
    let repo = Arc::new(InMemoryScopeRepository::default());
    let state: SharedScopeState =
        agent::app::builder::load_scope_state(repo.as_ref()).await.unwrap();
    let nonce = "deadbeef01".to_owned();
    let pipe = test_pipe("mid-frame");
    let adapter = Arc::new(
        IpcServerAdapter::with_sddl(
            state,
            Arc::new(UserActorConfig::default()),
            nonce.clone(),
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)".to_owned(),
            Arc::new(AtomicU64::new(0)),
        )
        .with_pipe_name(pipe.clone()),
    );
    let inlet = Arc::new(RecordingInlet::default());
    {
        let adapter = Arc::clone(&adapter);
        let inlet = Arc::clone(&inlet);
        tokio::spawn(async move {
            let _ = adapter.run(inlet).await;
        });
    }

    // 1. Verified client sends a screenshot header, then dies before the
    //    payload: the server abandons the half frame.
    let mut client = TestClient::open(&pipe).await.unwrap();
    client.send_frame(message_type::HELLO, &hello_payload(&nonce)).await;
    let (frame, _) = client.read_frame().await.unwrap();
    assert_eq!(frame.message_type, message_type::WELCOME);
    let header = FrameHeader { payload_len: 128, message_type: message_type::SCREENSHOT, flags: 0 };
    client.0.write_all(&header.to_bytes()).await.unwrap();
    client.0.flush().await.unwrap();
    drop(client); // die mid-frame

    // 2. The next client still gets the full handshake + config push.
    let mut client = TestClient::open(&pipe).await.unwrap();
    client.send_frame(message_type::HELLO, &hello_payload(&nonce)).await;
    let (frame, payload) = client.read_frame().await.unwrap();
    assert_eq!(frame.message_type, message_type::WELCOME);
    let welcome: Welcome = serde_json::from_slice(&payload).unwrap();
    assert_eq!(welcome.config, UserActorConfig::default());
    client.expect_disconnect_after_stop(&adapter).await;
}

impl TestClient {
    /// Stop the server and expect the connection to close.
    async fn expect_disconnect_after_stop(&mut self, adapter: &Arc<IpcServerAdapter>) {
        adapter.stop();
        self.expect_disconnect().await;
    }
}
