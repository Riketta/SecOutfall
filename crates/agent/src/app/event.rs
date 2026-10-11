//! Inbound event taxonomy of the agent hexagon.
//!
//! [`SandboxEvent`] is what driving adapters normalize into and hand to the
//! kernel's inlet. Source telemetry reuses the `protocol` payload structs
//! verbatim — one schema from source to wire. [`AgentBusEvent`] is the derived,
//! plugin-owned bus taxonomy (never raw inbound events).

use protocol::{
    events::EventType,
    payload::{
        BehaviorCallData,
        FileCreatedData,
        FileDeletedData,
        FileFsctlData,
        FileReleasedData,
        FileRenamedData,
        FileWrittenData,
        ImageLoadedData,
        ImageUnloadedData,
        Payload,
        ProcessStartedData,
        ProcessStoppedData,
        ProtectionStrippedData,
        RegistryKeyData,
        RegistryValueQueriedData,
        RegistryValueSetData,
        TcpConnectionData,
        ThreadStartedData,
        ThreadStoppedData,
    },
};

/// An inbound event of the agent core. Fire-and-forget: outputs happen only via
/// driven ports.
#[derive(Debug, Clone)]
pub enum SandboxEvent {
    /// Source telemetry stamped at consumption (ETW today, scripted feeds in
    /// simulation) — the wire envelope carries the consumption time.
    Source(SourceEvent),
    /// Source telemetry with the SOURCE's own event time, already mapped to
    /// the fake clock's unix-ms (driver records are kernel-stamped; the
    /// adapter applies the real→fake offset at drain). The wire envelope
    /// carries THIS time, not the consumption time — driver events keep
    /// their ground-truth ordering even when a drain batch is late.
    SourceDated(SourceEvent, i64),
    /// The current session's scheduled uptime elapsed.
    SessionDeadline,
    /// The service/console host asked the agent to stop.
    ServiceStop,
    /// A decoded screenshot frame arrived from the user-actor (IPC v1).
    ScreenshotReceived(ScreenshotFrame),
    /// Periodic persistence tick (legacy scope-save cadence).
    PersistTick,
    /// Periodic statistics tick.
    StatsTick,
}

impl SandboxEvent {
    /// The source event, when this is source telemetry of either stamping
    /// kind — membership, drop detection and scoring treat both identically.
    #[must_use]
    pub fn source_event(&self) -> Option<&SourceEvent> {
        match self {
            Self::Source(event) | Self::SourceDated(event, _) => Some(event),
            _ => None,
        }
    }
}

/// One screenshot frame handed over by the user-actor.
///
/// `Default` exists for the `mem::take` swap in the intake plugin; a default
/// frame is never a real frame.
#[derive(Debug, Clone, Default)]
pub struct ScreenshotFrame {
    /// Per-session screenshot sequence number (chosen by the user-actor).
    pub seq: u32,
    /// Raw JPEG bytes.
    pub jpeg: Vec<u8>,
}

/// Source-observable telemetry, variant-for-variant identical to the
/// corresponding `protocol::payload` structs and wire event types.
#[derive(Debug, Clone)]
pub enum SourceEvent {
    /// See [`ProcessStartedData`] / `process.started`.
    ProcessStarted(ProcessStartedData),
    /// See [`ProcessStoppedData`] / `process.stopped`.
    ProcessStopped(ProcessStoppedData),
    /// See [`ThreadStartedData`] / `thread.started`.
    ThreadStarted(ThreadStartedData),
    /// See [`ThreadStoppedData`] / `thread.stopped`.
    ThreadStopped(ThreadStoppedData),
    /// See [`ImageLoadedData`] / `image.loaded`.
    ImageLoaded(ImageLoadedData),
    /// See [`ImageUnloadedData`] / `image.unloaded`.
    ImageUnloaded(ImageUnloadedData),
    /// See [`RegistryKeyData`] / `registry.key_created`.
    RegistryKeyCreated(RegistryKeyData),
    /// See [`RegistryKeyData`] / `registry.key_deleted`.
    RegistryKeyDeleted(RegistryKeyData),
    /// See [`RegistryKeyData`] / `registry.key_opened`.
    RegistryKeyOpened(RegistryKeyData),
    /// See [`RegistryKeyData`] / `registry.key_closed`.
    RegistryKeyClosed(RegistryKeyData),
    /// See [`RegistryKeyData`] / `registry.key_queried`.
    RegistryKeyQueried(RegistryKeyData),
    /// See [`RegistryValueQueriedData`] / `registry.value_queried`.
    RegistryValueQueried(RegistryValueQueriedData),
    /// See [`RegistryValueSetData`] / `registry.value_set`.
    RegistryValueSet(RegistryValueSetData),
    /// See [`FileCreatedData`] / `file.created`.
    FileCreated(FileCreatedData),
    /// See [`FileWrittenData`] / `file.written`.
    FileWritten(FileWrittenData),
    /// See `file.closed` (schema: `FileReleasedData`).
    FileClosed(FileReleasedData),
    /// See `file.cleaned_up` (schema: `FileReleasedData`).
    FileCleanedUp(FileReleasedData),
    /// See [`FileDeletedData`] / `file.deleted`.
    FileDeleted(FileDeletedData),
    /// See [`FileRenamedData`] / `file.renamed`.
    FileRenamed(FileRenamedData),
    /// See [`FileFsctlData`] / `file.fsctl`.
    FileFsctl(FileFsctlData),
    /// See [`TcpConnectionData`] / `net.tcp.connected`.
    NetTcpConnected(TcpConnectionData),
    /// See [`TcpConnectionData`] / `net.tcp.accepted`.
    NetTcpAccepted(TcpConnectionData),
    /// See [`TcpConnectionData`] / `net.tcp.disconnected`.
    NetTcpDisconnected(TcpConnectionData),
    /// Sensor hooked-API call (`behavior.call`, driver track).
    BehaviorCall(BehaviorCallData),
    /// Handle access to a protected process was stripped
    /// (`protection.stripped`, driver track).
    ProtectionStripped(ProtectionStrippedData),
}

/// Generates `event_type()` and `into_payload()` from one variant table —
/// `Payload` variant names match `SourceEvent` variant names 1:1.
macro_rules! source_variants {
    ($( $variant:ident ( $ty:ty ) => $event:path ),* $(,)?) => {
        impl SourceEvent {
            /// The canonical wire event type this source event maps to.
            #[must_use]
            pub fn event_type(&self) -> EventType {
                match self {
                    $( Self::$variant(_) => $event, )*
                }
            }

            /// Convert into the wire payload for reporting.
            #[must_use]
            pub fn into_payload(self) -> Payload {
                match self {
                    $( Self::$variant(data) => Payload::$variant(data), )*
                }
            }
        }
    };
}

source_variants! {
    ProcessStarted(ProcessStartedData) => EventType::ProcessStarted,
    ProcessStopped(ProcessStoppedData) => EventType::ProcessStopped,
    ThreadStarted(ThreadStartedData) => EventType::ThreadStarted,
    ThreadStopped(ThreadStoppedData) => EventType::ThreadStopped,
    ImageLoaded(ImageLoadedData) => EventType::ImageLoaded,
    ImageUnloaded(ImageUnloadedData) => EventType::ImageUnloaded,
    RegistryKeyCreated(RegistryKeyData) => EventType::RegistryKeyCreated,
    RegistryKeyDeleted(RegistryKeyData) => EventType::RegistryKeyDeleted,
    RegistryKeyOpened(RegistryKeyData) => EventType::RegistryKeyOpened,
    RegistryKeyClosed(RegistryKeyData) => EventType::RegistryKeyClosed,
    RegistryKeyQueried(RegistryKeyData) => EventType::RegistryKeyQueried,
    RegistryValueQueried(RegistryValueQueriedData) => EventType::RegistryValueQueried,
    RegistryValueSet(RegistryValueSetData) => EventType::RegistryValueSet,
    FileCreated(FileCreatedData) => EventType::FileCreated,
    FileWritten(FileWrittenData) => EventType::FileWritten,
    FileClosed(FileReleasedData) => EventType::FileClosed,
    FileCleanedUp(FileReleasedData) => EventType::FileCleanedUp,
    FileDeleted(FileDeletedData) => EventType::FileDeleted,
    FileRenamed(FileRenamedData) => EventType::FileRenamed,
    FileFsctl(FileFsctlData) => EventType::FileFsctl,
    NetTcpConnected(TcpConnectionData) => EventType::NetTcpConnected,
    NetTcpAccepted(TcpConnectionData) => EventType::NetTcpAccepted,
    NetTcpDisconnected(TcpConnectionData) => EventType::NetTcpDisconnected,
    BehaviorCall(BehaviorCallData) => EventType::BehaviorCall,
    ProtectionStripped(ProtectionStrippedData) => EventType::ProtectionStripped,
}

/// Derived, plugin-owned domain events carried on the agent bus. Never raw
/// inbound events — the pipeline→bus bridge is plugin behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentBusEvent {
    /// The target sample entered the scope.
    TargetLaunched {
        /// Target image name (with extension).
        name: String,
    },
    /// A process joined the analysis scope.
    ProcessEnteredScope {
        /// OS process id.
        pid: u32,
        /// Image name (with extension).
        name: String,
    },
    /// A scoped process exited.
    ProcessExitedScope {
        /// OS process id.
        pid: u32,
        /// Image name (with extension).
        name: String,
    },
    /// A drop (matching file written by a scoped process) was first observed.
    DropObserved {
        /// File path.
        path: String,
        /// Writing process id, when scoped.
        pid: Option<u32>,
    },
    /// An observed drop's handles closed — safe to copy.
    DropClosed {
        /// File path.
        path: String,
    },
    /// Every scoped process of the current session died (empty scope is NOT dead).
    ScopeDied,
    /// The launcher resolved a target program image whose process name should
    /// seed the scope expectation (non-exe targets launch via interpreters,
    /// so the observed image differs from the configured target name).
    ExtendScopeExpectation {
        /// Image name (with extension) to expect in the scope.
        name: String,
    },
    /// A scoped process made a hooked-API call that is a scoring signal
    /// (`behavior.call` filtered by `domain::score::is_scoring_relevant`).
    /// Bridged by the scope-tracker — bus events are derived, never raw.
    BehaviorObserved {
        /// OS process id (scoped — the tracker checked membership).
        pid: u32,
        /// Behavior api id (see `protocol::driver_wire::behavior_api`).
        api: u32,
    },
    /// The scoring plugin raised the session maximum score.
    SessionScoreRaised {
        /// New session maximum.
        score: u32,
    },
}
