//! User-actor IPC server adapter (Windows named pipe, feature `ipc`).
//!
//! Pipe: `\\.\pipe\secoutfall\user-actor-v1` (IPC v1, fixed name). Security:
//! - DACL built from SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)` — protected, only
//!   SYSTEM and Administrators; the launching user's ACE joins in the
//!   user-actor-launcher phase (the nonce below already gates correctness).
//! - `PIPE_REJECT_REMOTE_CLIENTS` refuses non-local connections.
//! - Anti-impostor: the client's `HELLO` must echo the per-boot nonce the
//!   agent generated; failures are answered with `ERROR` and a disconnect.
//!   The client-PID check against the spawned child lands with the launcher
//!   (phase 8); `GetNamedPipeClientProcessId` is already captured for it.
//!
//! Framing: [`protocol::ipc::FrameHeader`] + payload, 16 MiB hard cap — the
//! header is validated before any payload allocation.

use std::{
    os::windows::io::AsRawHandle as _,
    sync::{
        Arc,
        atomic::{
            AtomicU64,
            Ordering,
        },
    },
};

use kernel::app::api_ports::EventInletPort;
use protocol::{
    config::UserActorConfig,
    events::EventType,
    ipc::{
        FrameError,
        FrameHeader,
        HEADER_LEN,
        message_type,
        messages::{
            ErrorFrame,
            Hello,
            IPC_PROTOCOL_VERSION,
            Welcome,
            decode_screenshot,
        },
    },
    nats::Payload,
    payload::{
        UserActorStartedData,
        UserActorStoppedData,
    },
};
use tokio::{
    io::{
        AsyncReadExt as _,
        AsyncWriteExt as _,
    },
    net::windows::named_pipe::NamedPipeServer,
};
use tokio_util::sync::CancellationToken;

use crate::{
    app::event::{
        SandboxEvent,
        ScreenshotFrame,
    },
    domain::scope::SharedScopeState,
    ports::{
        broker::{
            BrokerPort,
            Channel,
        },
        clock::SystemClockPort,
    },
};

/// Fixed IPC v1 pipe name.
pub const PIPE_NAME: &str = "\\\\.\\pipe\\secoutfall\\user-actor-v1";

/// Default SDDL: protected DACL, `GENERIC_ALL` for SYSTEM and Administrators.
/// The user-actor launcher (phase 8) builds a variant that also grants the
/// launching interactive user (`(A;;GA;;;<user-sid>)`), because the client
/// process runs under that user's token.
pub const DEFAULT_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

/// IPC server failures.
#[derive(Debug, thiserror::Error)]
pub enum IpcServerError {
    /// The pipe could not be created or the security descriptor failed.
    #[error("pipe setup failed: {0}")]
    Setup(String),
    /// The wait for a client or a frame read/write failed beyond disconnect.
    #[error("pipe I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A frame violated the protocol (unknown type, bad cap).
    #[error("protocol violation: {0}")]
    Protocol(#[from] FrameError),
}

/// Driving adapter: serves the user-actor pipe until stopped, feeding decoded
/// screenshot frames into the inlet and answering config pulls.
pub struct IpcServerAdapter {
    state: SharedScopeState,
    user_actor_config: Arc<UserActorConfig>,
    nonce: String,
    sddl: String,
    /// Full pipe name; the production default is [`PIPE_NAME`]. Tests override
    /// it so parallel test binaries never compete for `first_pipe_instance`.
    pipe_name: String,
    seq: Arc<AtomicU64>,
    /// Optional wire reporter: publishes `user_actor.started`/`stopped` from
    /// real handshake evidence (module version + client pid of the peer).
    wire: Option<HelloWire>,
    cancel: CancellationToken,
}

/// Wire access for handshake evidence reports.
#[derive(Clone)]
struct HelloWire {
    broker: Arc<dyn BrokerPort>,
    clock: Arc<dyn SystemClockPort>,
}

impl IpcServerAdapter {
    /// Assemble the adapter for one boot.
    ///
    /// `nonce` is the per-boot secret the user-actor receives at launch and
    /// must echo in `HELLO`.
    #[must_use]
    pub fn new(
        state: SharedScopeState,
        user_actor_config: Arc<UserActorConfig>,
        nonce: String,
        seq: Arc<AtomicU64>,
    ) -> Self {
        Self::with_sddl(state, user_actor_config, nonce, DEFAULT_PIPE_SDDL.to_owned(), seq)
    }

    /// Assemble with an explicit SDDL (launcher phase builds user-aware DACLs).
    #[must_use]
    pub fn with_sddl(
        state: SharedScopeState,
        user_actor_config: Arc<UserActorConfig>,
        nonce: String,
        sddl: String,
        seq: Arc<AtomicU64>,
    ) -> Self {
        Self {
            state,
            user_actor_config,
            nonce,
            sddl,
            pipe_name: PIPE_NAME.to_owned(),
            seq,
            wire: None,
            cancel: CancellationToken::new(),
        }
    }

    /// Override the pipe name (tests); production uses the fixed IPC v1 name.
    #[must_use]
    pub fn with_pipe_name(mut self, pipe_name: String) -> Self {
        self.pipe_name = pipe_name;
        self
    }

    /// Publish `user_actor.started`/`user_actor.stopped` wire events from
    /// verified handshakes and disconnects.
    #[must_use]
    pub fn with_wire_reporter(
        mut self,
        broker: Arc<dyn BrokerPort>,
        clock: Arc<dyn SystemClockPort>,
    ) -> Self {
        self.wire = Some(HelloWire { broker, clock });
        self
    }

    /// Publish `user_actor.started` from a verified handshake (evidence:
    /// module version + client pid, not a launch intention).
    async fn publish_user_actor_started(&self, module_version: String, pid: Option<u32>) {
        let Some(wire) = &self.wire else { return };
        let (study_id, session_id) = {
            let state = self.state.lock();
            (state.study_id, state.current_session().map_or(0, |session| session.id))
        };
        let envelope = crate::plugins::wire::envelope_raw(
            wire.clock.now_ms(),
            crate::plugins::wire::next_seq(&self.seq),
            study_id,
            session_id,
            EventType::UserActorStarted,
            Payload::UserActorStarted(UserActorStartedData { module_version, pid }),
        );
        if let Err(error) = wire.broker.publish(Channel::Event, &envelope).await {
            tracing::error!(%error, "user_actor.started publish failed");
        }
    }

    /// Publish `user_actor.stopped` when an established connection ends.
    async fn publish_user_actor_stopped(&self, reason: Option<String>) {
        let Some(wire) = &self.wire else { return };
        let (study_id, session_id) = {
            let state = self.state.lock();
            (state.study_id, state.current_session().map_or(0, |session| session.id))
        };
        let envelope = crate::plugins::wire::envelope_raw(
            wire.clock.now_ms(),
            crate::plugins::wire::next_seq(&self.seq),
            study_id,
            session_id,
            EventType::UserActorStopped,
            Payload::UserActorStopped(UserActorStoppedData { reason }),
        );
        if let Err(error) = wire.broker.publish(Channel::Event, &envelope).await {
            tracing::error!(%error, "user_actor.stopped publish failed");
        }
    }

    /// Stop the server (idempotent). `run` returns shortly after.
    pub fn stop(&self) {
        self.cancel.cancel();
    }

    /// Serve until [`stop`](Self::stop). One client at a time (the user-actor
    /// is a single process); a new pipe instance is created per connection.
    ///
    /// # Errors
    /// [`IpcServerError::Setup`] when the pipe cannot be created.
    pub async fn run(
        &self,
        inlet: Arc<dyn EventInletPort<SandboxEvent>>,
    ) -> Result<(), IpcServerError> {
        let mut first_instance = true;
        while !self.cancel.is_cancelled() {
            // The security attributes hold raw pointers — build, use, and drop
            // them without an await in scope so the future stays Send.
            let server = {
                let mut security = build_security_attributes(&self.sddl)?;
                create_pipe_instance(&mut security, first_instance, &self.pipe_name)?
            };
            first_instance = false;

            // connect() parks until a client opens the pipe (or cancel — the
            // handle is closed on drop after stop, unblocking it).
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => {
                    drop(server);
                    break;
                }
                connected = server.connect() => {
                    connected.map_err(IpcServerError::Io)?;
                }
            }
            if self.cancel.is_cancelled() {
                break;
            }

            if let Err(error) = serve_client(server, self, &self.cancel, inlet.as_ref()).await {
                tracing::warn!(%error, "user-actor IPC connection ended with error");
            }
        }
        Ok(())
    }
}

/// Per-connection context extracted for the worker task.
struct ServerContext {
    nonce: String,
    welcome: Welcome,
}

/// Serve one connected client until EOF or protocol error. Publishes
/// `user_actor.started` on a verified handshake and `user_actor.stopped` when
/// an established connection ends.
async fn serve_client(
    mut server: NamedPipeServer,
    adapter: &IpcServerAdapter,
    cancel: &CancellationToken,
    inlet: &dyn EventInletPort<SandboxEvent>,
) -> Result<(), IpcServerError> {
    let mut handshaked: Option<String> = None; // module version from HELLO
    let result = serve_client_loop(&mut server, adapter, cancel, inlet, &mut handshaked).await;
    if handshaked.is_some() {
        let reason = result.as_ref().err().map(ToString::to_string);
        adapter.publish_user_actor_stopped(reason).await;
    }
    result
}

/// The frame loop. `handshaked` records the verified HELLO's module version.
async fn serve_client_loop(
    server: &mut NamedPipeServer,
    adapter: &IpcServerAdapter,
    cancel: &CancellationToken,
    inlet: &dyn EventInletPort<SandboxEvent>,
    handshaked: &mut Option<String>,
) -> Result<(), IpcServerError> {
    let context = ServerContext {
        nonce: adapter.nonce.clone(),
        welcome: build_welcome(&adapter.state, &adapter.user_actor_config),
    };
    let mut header = [0_u8; HEADER_LEN];
    loop {
        if read_exact_or_disconnect(server, &mut header, cancel).await? {
            return Ok(()); // clean disconnect or shutdown
        }
        let frame = FrameHeader::from_bytes(&header)?;
        let mut payload = vec![0_u8; frame.payload_len as usize];
        if read_exact_or_disconnect(server, &mut payload, cancel).await? {
            return Ok(());
        }

        match frame.message_type {
            message_type::HELLO => {
                let hello: Hello = serde_json::from_slice(&payload)
                    .map_err(|error| io_plain(format!("bad HELLO: {error}")))?;
                if hello.protocol != IPC_PROTOCOL_VERSION
                    || !constant_time_eq(hello.nonce.as_bytes(), context.nonce.as_bytes())
                {
                    tracing::warn!(client_pid = client_pid(server), "HELLO rejected");
                    send_frame(
                        server,
                        message_type::ERROR,
                        &serde_json::to_vec(&ErrorFrame { error: "handshake rejected".to_owned() })
                            .map_err(|error| io_plain(error.to_string()))?,
                    )
                    .await?;
                    return Ok(()); // impostors get one strike
                }
                *handshaked = Some(hello.module_version.clone());
                tracing::info!(
                    module_version = %hello.module_version,
                    client_pid = client_pid(server),
                    "user actor handshake verified"
                );
                let pid = client_pid(server);
                adapter
                    .publish_user_actor_started(hello.module_version, (pid != 0).then_some(pid))
                    .await;
                let body = serde_json::to_vec(&context.welcome)
                    .map_err(|error| io_plain(error.to_string()))?;
                send_frame(server, message_type::WELCOME, &body).await?;
            }
            message_type::GET_CONFIG => {
                let body = serde_json::to_vec(&context.welcome)
                    .map_err(|error| io_plain(error.to_string()))?;
                send_frame(server, message_type::WELCOME, &body).await?;
            }
            message_type::SCREENSHOT => {
                let (seq, jpeg) = decode_screenshot(&payload)?;
                tracing::debug!(seq, bytes = jpeg.len(), "screenshot frame received");
                adapter.seq.fetch_add(1, Ordering::Relaxed);
                inlet
                    .accept(SandboxEvent::ScreenshotReceived(ScreenshotFrame {
                        seq,
                        jpeg: jpeg.to_vec(),
                    }))
                    .await;
            }
            message_type::ERROR => {
                let error_frame: Result<ErrorFrame, _> = serde_json::from_slice(&payload);
                tracing::warn!(error = ?error_frame.ok(), "user-actor reported an error");
            }
            unknown => {
                tracing::warn!(%unknown, "unknown IPC frame type; disconnecting");
                return Ok(());
            }
        }
    }
}

/// Read exactly `buf.len()` bytes; `Ok(true)` = peer disconnected cleanly or
/// the adapter was stopped (the pending read is abandoned with the handle).
async fn read_exact_or_disconnect(
    server: &mut NamedPipeServer,
    buf: &mut [u8],
    cancel: &CancellationToken,
) -> Result<bool, IpcServerError> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Ok(true),
        read = server.read_exact(buf) => match read {
            Ok(_) => Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(true),
            Err(error) => Err(error.into()),
        },
    }
}

async fn send_frame(
    server: &mut NamedPipeServer,
    message_type: u16,
    payload: &[u8],
) -> Result<(), IpcServerError> {
    let header = FrameHeader {
        payload_len: u32::try_from(payload.len())
            .map_err(|_| IpcServerError::Setup("frame exceeds u32".to_owned()))?,
        message_type,
        flags: 0,
    };
    server.write_all(&header.to_bytes()).await?;
    server.write_all(payload).await?;
    server.flush().await?;
    Ok(())
}

fn build_welcome(state: &SharedScopeState, config: &UserActorConfig) -> Welcome {
    let guard = state.lock();
    Welcome {
        session_id: guard.current_session().map_or(0, |session| session.id),
        config: config.clone(),
    }
}

/// Length-independent comparison for the nonce (defensive habit; the nonce is
/// a fresh per-boot random value, timing is not a realistic side channel).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn client_pid(server: &NamedPipeServer) -> u32 {
    // Best-effort diagnostics; the authoritative PID check lands with the
    // user-actor launcher (the agent knows its child's PID there).
    let mut pid = 0_u32;
    // SAFETY: the raw handle is a valid named-pipe handle owned by `server`.
    let result = unsafe {
        windows::Win32::System::Pipes::GetNamedPipeClientProcessId(
            windows::Win32::Foundation::HANDLE(server.as_raw_handle() as isize),
            &raw mut pid,
        )
    };
    result.map_or(0, |()| pid)
}

fn io_plain(message: String) -> IpcServerError {
    IpcServerError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, message))
}

/// Build the protected DACL once per server lifetime.
fn build_security_attributes(
    sddl: &str,
) -> Result<windows::Win32::Security::SECURITY_ATTRIBUTES, IpcServerError> {
    use windows::{
        Win32::{
            Foundation::BOOL,
            Security::{
                Authorization::{
                    ConvertStringSecurityDescriptorToSecurityDescriptorW,
                    SDDL_REVISION_1,
                },
                PSECURITY_DESCRIPTOR,
                SECURITY_ATTRIBUTES,
            },
        },
        core::PCWSTR,
    };
    let sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    // SAFETY: `sddl` is a NUL-terminated wide string; the out pointer is a
    // local. The descriptor intentionally lives for the adapter's lifetime
    // (one boot); the OS frees nothing here and we drop it with the pipe.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR::from_raw(sddl.as_ptr()),
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
    }
    .map_err(|error| IpcServerError::Setup(format!("SDDL conversion failed: {error}")))?;

    Ok(SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|error| IpcServerError::Setup(error.to_string()))?,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: BOOL(0),
    })
}

/// Create one named-pipe server instance (first call is exclusive) with the
/// restrictive DACL applied via tokio's security-attributes passthrough.
fn create_pipe_instance(
    security: &mut windows::Win32::Security::SECURITY_ATTRIBUTES,
    first_instance: bool,
    pipe_name: &str,
) -> Result<NamedPipeServer, IpcServerError> {
    // tokio's builder is the supported creation path: it selects the access
    // mode, OVERLAPPED flag and pipe modes that raw calls keep getting wrong
    // (a raw `CreateNamedPipeW` with the same flags fails with ERROR 87 here).
    let mut options = tokio::net::windows::named_pipe::ServerOptions::new();
    options
        .first_pipe_instance(first_instance)
        .reject_remote_clients(true)
        .access_inbound(true)
        .access_outbound(true);
    // SAFETY: `security` is initialized by the SDDL conversion, outlives the
    // creation call, and the resulting server owns the configured pipe.
    let server = unsafe {
        options.create_with_security_attributes_raw(
            pipe_name,
            std::ptr::from_mut(security).cast::<std::ffi::c_void>(),
        )
    }
    .map_err(IpcServerError::Io)?;
    Ok(server)
}

/// Build a pipe SDDL that additionally grants the interactive console
/// session's user `GENERIC_ALL` — the user actor runs under that user's
/// token (`CreateProcessAsUser`), so without this ACE it cannot open the
/// pipe. Returns `None` when there is no console session or the SID cannot
/// be resolved (dev boxes, service before logon); the default DACL applies.
#[cfg(windows)]
#[must_use]
pub async fn console_user_pipe_sddl() -> Option<String> {
    tokio::task::spawn_blocking(console_user_pipe_sddl_blocking).await.ok().flatten()
}

/// Blocking SID resolution for [`console_user_pipe_sddl`].
fn console_user_pipe_sddl_blocking() -> Option<String> {
    use windows::{
        Win32::{
            Foundation::{
                HANDLE,
                HLOCAL,
                LocalFree,
            },
            Security::{
                Authorization::ConvertSidToStringSidW,
                GetTokenInformation,
                TOKEN_USER,
                TokenUser,
            },
            System::RemoteDesktop::{
                WTSGetActiveConsoleSessionId,
                WTSQueryUserToken,
            },
        },
        core::PWSTR,
    };

    // SAFETY: no preconditions; returns the current console session id.
    let session_id = unsafe { WTSGetActiveConsoleSessionId() };
    let mut token = HANDLE::default();
    // SAFETY: `token` is a valid, initialized output handle; closed on every
    // path below.
    let queried = unsafe { WTSQueryUserToken(session_id, std::ptr::from_mut(&mut token)) };
    if queried.is_err() {
        return None;
    }

    // Query the token user: first call fails with the needed size.
    let mut needed = 0_u32;
    // SAFETY: the sizing call expects `None` and reports the length.
    let _ =
        unsafe { GetTokenInformation(token, TokenUser, None, 0, std::ptr::from_mut(&mut needed)) };
    if needed == 0 {
        // SAFETY: owned handle, closed exactly once.
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(token) };
        return None;
    }
    let mut buffer = vec![0_u8; usize::try_from(needed).ok()?];
    // SAFETY: `buffer` is `needed` bytes long; the class writes a TOKEN_USER
    // (with embedded SID) into it.
    let filled = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            needed,
            std::ptr::from_mut(&mut needed),
        )
    };
    // SAFETY: owned handle, closed exactly once.
    let _ = unsafe { windows::Win32::Foundation::CloseHandle(token) };
    filled.ok()?;

    // SAFETY: the buffer now holds a TOKEN_USER per the contract above; it
    // is read unaligned because a `Vec<u8>` only guarantees 1-byte alignment.
    let token_user = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let mut sid_string = PWSTR::null();
    // SAFETY: `sid_string` is a valid out-pointer; the returned string is
    // freed with LocalFree below.
    unsafe { ConvertSidToStringSidW(token_user.User.Sid, std::ptr::from_mut(&mut sid_string)) }
        .ok()?;
    if sid_string.is_null() {
        return None;
    }
    // SAFETY: `sid_string` points at a NUL-terminated wide string allocated
    // by ConvertSidToStringSidW above.
    let sid = unsafe { sid_string.to_string() }.ok();
    // SAFETY: the string was allocated by ConvertSidToStringSidW and is
    // freed exactly once.
    unsafe { LocalFree(HLOCAL(sid_string.0.cast())) };
    let sid = sid?;

    Some(format!("{DEFAULT_PIPE_SDDL}(A;;GA;;;<{sid}>)"))
}
