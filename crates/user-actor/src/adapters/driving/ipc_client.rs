//! Named-pipe IPC client (driving + driven halves in one adapter).
//!
//! Driving: the run loop receives `WELCOME` frames and hands them to the
//! kernel inlet as [`ActorEvent::Welcome`]. Driven: [`IpcScreenshotSink`]
//! (cloneable) feeds screenshot frames into the same loop through a bounded
//! channel — backpressure instead of unbounded memory (hostile-input rule).
//! Oversized frames are rejected at the sink, never queued: a >16 MiB frame
//! would be rejected by the peer, and resending it after reconnect would
//! loop forever.
//!
//! Connection lifecycle: retry connecting until the server appears (the agent
//! may start the pipe after us), handshake with the per-boot nonce, and
//! reconnect on any loss (with a small delay so a peer that accepts-then-
//! drops cannot spin the loop hot). A handshake **rejection** is fatal: the
//! nonce is wrong for this boot and retrying cannot fix it. Frame READS run
//! on a dedicated task: `read_exact` consumes pipe bytes even when its future
//! is abandoned, so the read must never be dropped mid-frame (a `select!`
//! over reads desyncs the stream — the historical bug this structure fixes).

use std::{
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use kernel::app::api_ports::EventInletPort;
use protocol::ipc::{
    FrameHeader,
    HEADER_LEN,
    MAX_PAYLOAD_LEN,
    message_type,
    messages::{
        ErrorFrame,
        Hello,
        IPC_PROTOCOL_VERSION,
        Welcome,
    },
};
use tokio::{
    io::{
        AsyncReadExt as _,
        AsyncWriteExt as _,
        ReadHalf,
        WriteHalf,
    },
    net::windows::named_pipe::ClientOptions,
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;

use crate::{
    domain::ActorEvent,
    ports::driven::{
        ScreenshotSinkError,
        ScreenshotSinkPort,
    },
};

/// Delay between connection attempts while the server pipe does not exist.
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(500);

/// Delay after a lost connection before reconnecting — a peer that accepts
/// and immediately drops must not spin the loop hot (each new connection
/// would otherwise get a fresh connect deadline with no backoff).
const RECONNECT_DELAY: Duration = Duration::from_millis(500);

/// Bounded in-flight screenshot frames before the sink applies backpressure.
const SINK_CHANNEL_CAPACITY: usize = 4;

/// Bounded queue of frames read from the pipe, awaiting dispatch. The reader
/// task blocks on send when the loop is busy — pipe backpressure, never data
/// loss (a dropped in-flight read would desync the stream).
const INBOUND_CHANNEL_CAPACITY: usize = 8;

/// Grace period for the reader task to notice teardown (cancel token / pipe
/// close) before it is aborted along with the rest of the connection.
const READER_TEARDOWN_GRACE: Duration = Duration::from_secs(1);

/// IPC client failures.
#[derive(Debug, thiserror::Error)]
pub enum IpcClientError {
    /// The server rejected our `HELLO` — the nonce/protocol is wrong for this
    /// boot; retrying cannot succeed.
    #[error("handshake rejected by the agent")]
    HandshakeRejected,
    /// The pipe could not be opened beyond transient absence.
    #[error("pipe connection failed: {0}")]
    Connect(std::io::Error),
    /// A frame exchange failed.
    #[error("pipe I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A frame violated the protocol.
    #[error("protocol violation: {0}")]
    Protocol(#[from] protocol::ipc::FrameError),
}

/// Assembly options for the client.
#[derive(Debug, Clone)]
pub struct IpcClientOptions {
    /// Full pipe name (IPC v1 fixed name by default).
    pub pipe_name: String,
    /// Per-boot nonce from the command line; echoed in `HELLO`.
    pub nonce: String,
    /// Build version reported in `HELLO`.
    pub module_version: String,
    /// Reconnect while the server is absent (up to this long), then fail.
    pub connect_deadline: Duration,
}

impl IpcClientOptions {
    /// Options for the fixed IPC v1 pipe.
    #[must_use]
    pub fn new(nonce: String, module_version: String) -> Self {
        Self {
            pipe_name: crate::PIPE_NAME.to_owned(),
            nonce,
            module_version,
            connect_deadline: Duration::from_secs(20),
        }
    }
}

/// The receiving half of the screenshot sink channel, shared with the run
/// loop (tokio `Mutex` because the loop holds it across awaits).
type SharedScreenshotQueue = Arc<tokio::sync::Mutex<mpsc::Receiver<(u32, Vec<u8>)>>>;

/// The IPC client adapter. The sink half ([`IpcScreenshotSink`]) is created
/// before assembly ([`channel`](Self::channel)) because plugins receive it at
/// construction; this adapter consumes the queue half and runs the wire loop.
pub struct IpcClientAdapter {
    options: IpcClientOptions,
    sink_rx: SharedScreenshotQueue,
    cancel: CancellationToken,
}

impl IpcClientAdapter {
    /// Create the sink/queue pair. The sink goes into the plugins; the queue
    /// goes into [`IpcClientAdapter::new`].
    #[must_use]
    pub fn channel() -> (IpcScreenshotSink, mpsc::Receiver<(u32, Vec<u8>)>) {
        let (tx, rx) = mpsc::channel(SINK_CHANNEL_CAPACITY);
        (IpcScreenshotSink { tx }, rx)
    }

    /// Assemble the client over an existing sink queue.
    #[must_use]
    pub fn new(
        options: IpcClientOptions,
        sink_rx: mpsc::Receiver<(u32, Vec<u8>)>,
        cancel: CancellationToken,
    ) -> Self {
        Self { options, sink_rx: Arc::new(tokio::sync::Mutex::new(sink_rx)), cancel }
    }

    /// Stop the client (idempotent); `run` returns shortly after.
    pub fn stop(&self) {
        self.cancel.cancel();
    }

    /// Run until cancelled or fatally rejected. On connection loss the client
    /// reconnects and re-handshakes (the server re-pushes `WELCOME`), so the
    /// runtime config self-heals.
    ///
    /// # Errors
    /// [`IpcClientError::HandshakeRejected`] (fatal), connect deadline
    /// exceeded, or I/O/protocol failures on the first connection.
    pub async fn run(
        &self,
        inlet: Arc<dyn EventInletPort<ActorEvent>>,
    ) -> Result<(), IpcClientError> {
        loop {
            let client = self.connect().await?;
            let (reader, mut writer) = tokio::io::split(client);

            self.send_hello(&mut writer).await?;
            // `exchange` owns both halves: it must be able to close the pipe
            // (dropping the writer) to un-teardown the reader task.
            match self.exchange(reader, writer, inlet.as_ref()).await? {
                ExchangeOutcome::Cancelled => return Ok(()),
                ExchangeOutcome::Disconnected => {
                    tracing::warn!("agent IPC connection lost; reconnecting");
                    // Backoff before the next attempt: the loss may be a
                    // hostile accept-then-drop, and each retry would get a
                    // fresh connect deadline.
                    tokio::select! {
                        biased;
                        () = self.cancel.cancelled() => return Ok(()),
                        () = tokio::time::sleep(RECONNECT_DELAY) => {}
                    }
                }
                ExchangeOutcome::Rejected => return Err(IpcClientError::HandshakeRejected),
            }
        }
    }

    /// Open the pipe, waiting out transient absence (the server may not exist
    /// yet). The deadline bounds a wrong-configuration hang.
    async fn connect(
        &self,
    ) -> Result<tokio::net::windows::named_pipe::NamedPipeClient, IpcClientError> {
        let deadline = tokio::time::Instant::now() + self.options.connect_deadline;
        loop {
            if self.cancel.is_cancelled() {
                return Err(IpcClientError::Connect(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled",
                )));
            }
            // ERROR_FILE_NOT_FOUND / ERROR_PIPE_BUSY are the expected
            // "not yet / busy" outcomes; everything else is fatal.
            match ClientOptions::new().open(&self.options.pipe_name) {
                Ok(client) => return Ok(client),
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        // ERROR_PIPE_BUSY (231): all pipe instances are busy —
                        // transient; retry. Kept numeric to avoid a windows
                        // dependency in the `ipc` feature.
                        || error.raw_os_error() == Some(231) =>
                {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(IpcClientError::Connect(error));
                    }
                    tokio::time::sleep(CONNECT_RETRY_DELAY).await;
                }
                Err(error) => return Err(IpcClientError::Connect(error)),
            }
        }
    }

    async fn send_hello(
        &self,
        writer: &mut WriteHalf<tokio::net::windows::named_pipe::NamedPipeClient>,
    ) -> Result<(), IpcClientError> {
        let hello = Hello {
            protocol: IPC_PROTOCOL_VERSION,
            nonce: self.options.nonce.clone(),
            module_version: self.options.module_version.clone(),
        };
        let payload = serde_json::to_vec(&hello).map_err(|error| {
            IpcClientError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
        })?;
        send_frame(writer, message_type::HELLO, &payload).await
    }

    /// Read/write loop: receive frames (Welcome → inlet; Error → judge),
    /// forward queued screenshots. Runs until EOF, error, cancel, or
    /// rejection.
    ///
    /// Frame reads belong to a DEDICATED task: `read_exact` consumes pipe
    /// bytes even when its future is abandoned, so a `select!` over the read
    /// (with screenshots also flowing) would drop a mid-frame read and
    /// permanently desync the stream. The task forwards complete frames (or
    /// the read error) through a bounded channel the loop can safely await.
    async fn exchange(
        &self,
        reader: ReadHalf<tokio::net::windows::named_pipe::NamedPipeClient>,
        mut writer: WriteHalf<tokio::net::windows::named_pipe::NamedPipeClient>,
        inlet: &dyn EventInletPort<ActorEvent>,
    ) -> Result<ExchangeOutcome, IpcClientError> {
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<
            Result<Option<ReceivedFrame>, IpcClientError>,
        >(INBOUND_CHANNEL_CAPACITY);
        // Frame reads belong to a DEDICATED task: `read_exact` consumes pipe
        // bytes even when its future is abandoned, so a `select!` over the
        // read (with screenshots also flowing) would drop a mid-frame read
        // and permanently desync the stream. The task forwards complete
        // frames (or the read error) through a bounded channel the loop can
        // safely await.
        let reader_tx = inbound_tx.clone();
        let cancel = self.cancel.clone();
        let reader_task = tokio::spawn(async move {
            let mut reader = reader;
            loop {
                let frame = tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    read = read_frame(&mut reader) => match read {
                        Ok(frame) => frame,
                        Err(error) => {
                            // Read errors (incl. protocol violations) mean
                            // the stream is unusable: report and reconnect.
                            let _ = reader_tx.send(Err(error)).await;
                            break;
                        }
                    },
                };
                let sent = tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    sent = reader_tx.send(Ok(frame)) => sent,
                };
                if sent.is_err() {
                    break; // exchange loop is gone
                }
            }
        });

        let outcome = self.dispatch_loop(&mut inbound_rx, &mut writer, inlet).await;
        // Release the loop's channel half, then close the pipe (dropping the
        // writer ends the peer's read AND our own blocked read). The reader
        // may still be parked in `read_exact` on a peer that never closes —
        // give it the cancel-aware grace period, then abort: the whole
        // connection is being discarded, so an abandoned partial read is
        // harmless here.
        drop(inbound_tx);
        drop(writer);
        let _ = tokio::time::timeout(READER_TEARDOWN_GRACE, reader_task).await;
        outcome
    }

    /// The dispatch select: all awaited branches are channel receives, which
    /// are safe to abandon — unlike a partial frame read.
    async fn dispatch_loop(
        &self,
        inbound_rx: &mut mpsc::Receiver<Result<Option<ReceivedFrame>, IpcClientError>>,
        writer: &mut WriteHalf<tokio::net::windows::named_pipe::NamedPipeClient>,
        inlet: &dyn EventInletPort<ActorEvent>,
    ) -> Result<ExchangeOutcome, IpcClientError> {
        let mut sink_rx = self.sink_rx.lock().await;
        let mut handshaked = false;
        loop {
            let send_next = sink_rx.recv();
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => return Ok(ExchangeOutcome::Cancelled),
                read = inbound_rx.recv() => {
                    match read {
                        Some(Ok(Some(frame))) => {
                            match frame.message_type {
                                message_type::WELCOME => {
                                    match serde_json::from_slice::<Welcome>(&frame.payload) {
                                        Ok(welcome) => {
                                            handshaked = true;
                                            inlet.accept(ActorEvent::Welcome(welcome)).await;
                                        }
                                        Err(error) => {
                                            tracing::warn!(%error, "malformed WELCOME ignored");
                                        }
                                    }
                                }
                                message_type::ERROR => {
                                    let detail = serde_json::from_slice::<ErrorFrame>(
                                        &frame.payload,
                                    )
                                    .ok()
                                    .map_or_else(String::new, |error_frame| error_frame.error);
                                    if handshaked {
                                        tracing::warn!(detail, "agent reported an IPC error");
                                    } else {
                                        // Pre-WELCOME: our handshake was refused;
                                        // retrying cannot fix a wrong nonce.
                                        tracing::error!(detail, "IPC handshake rejected");
                                        return Ok(ExchangeOutcome::Rejected);
                                    }
                                }
                                unknown => {
                                    tracing::warn!(%unknown, "unexpected IPC frame; reconnecting");
                                    return Ok(ExchangeOutcome::Disconnected);
                                }
                            }
                        }
                        Some(Ok(None)) => return Ok(ExchangeOutcome::Disconnected), // EOF
                        Some(Err(error)) => {
                            tracing::warn!(%error, "IPC read failed; reconnecting");
                            return Ok(ExchangeOutcome::Disconnected);
                        }
                        None => return Ok(ExchangeOutcome::Cancelled), // reader gone
                    }
                }
                shot = send_next => {
                    match shot {
                        Some((seq, jpeg)) => {
                            let payload = protocol::ipc::messages::encode_screenshot(seq, &jpeg);
                            let outcome =
                                send_frame(writer, message_type::SCREENSHOT, &payload).await;
                            if let Err(error) = outcome {
                                tracing::warn!(seq, %error, "screenshot send failed; reconnecting");
                                return Ok(ExchangeOutcome::Disconnected);
                            }
                        }
                        None => return Ok(ExchangeOutcome::Cancelled),
                    }
                }
            }
        }
    }
}

enum ExchangeOutcome {
    Cancelled,
    Disconnected,
    Rejected,
}

/// One received frame; `None` on clean EOF.
struct ReceivedFrame {
    message_type: u16,
    payload: Vec<u8>,
}

/// Read one frame, validating the header before allocating the payload.
/// `Ok(None)` = peer closed.
async fn read_frame(
    reader: &mut ReadHalf<tokio::net::windows::named_pipe::NamedPipeClient>,
) -> Result<Option<ReceivedFrame>, IpcClientError> {
    let mut header = [0_u8; HEADER_LEN];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let parsed = FrameHeader::from_bytes(&header)?;
    let mut payload =
        vec![0_u8; usize::try_from(parsed.payload_len).unwrap_or(MAX_PAYLOAD_LEN + 1)];
    match reader.read_exact(&mut payload).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    Ok(Some(ReceivedFrame { message_type: parsed.message_type, payload }))
}

async fn send_frame(
    writer: &mut WriteHalf<tokio::net::windows::named_pipe::NamedPipeClient>,
    message_type: u16,
    payload: &[u8],
) -> Result<(), IpcClientError> {
    let header = FrameHeader {
        payload_len: u32::try_from(payload.len()).map_err(|_| {
            IpcClientError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "frame exceeds u32",
            ))
        })?,
        message_type,
        flags: 0,
    };
    writer.write_all(&header.to_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Cloneable sink handle; frames queue (bounded) and are flushed by the run
/// loop. `send` NEVER blocks on a saturated queue: an over-capacity frame is
/// dropped at the sink (doctrine: coalesce + loss counter, never block the
/// focus pipeline — the kernel inlet is inline, so a blocking sink would
/// freeze focus tracking and the pump thread). Callers release the capture
/// quota slot on any error.
pub struct IpcScreenshotSink {
    tx: mpsc::Sender<(u32, Vec<u8>)>,
}

#[async_trait]
impl ScreenshotSinkPort for IpcScreenshotSink {
    async fn send(&self, seq: u32, jpeg: Vec<u8>) -> Result<(), ScreenshotSinkError> {
        // Reject at the SOURCE, never queue an unwireable frame: the peer
        // must reject >16 MiB frames, and resending the poisoned frame after
        // every reconnect would loop forever.
        if protocol::ipc::messages::SCREENSHOT_SEQ_LEN + jpeg.len() > MAX_PAYLOAD_LEN {
            return Err(ScreenshotSinkError::Oversize);
        }
        self.tx.try_send((seq, jpeg)).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => ScreenshotSinkError::Full,
            mpsc::error::TrySendError::Closed(_) => ScreenshotSinkError::Closed,
        })
    }
}
