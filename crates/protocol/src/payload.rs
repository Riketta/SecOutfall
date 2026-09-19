//! Typed `data` payload schemas — one schema per canonical [`EventType`].
//!
//! Contract rules:
//! - Every taxonomy member has exactly one payload struct; several variants may
//!   share a struct when their schemas are identical (noted on the struct).
//! - Field names are `snake_case`; unknown fields are rejected on inbound
//!   validation (strict, versioned schema — forward compat is a version bump).
//! - [`Payload`] serializes as the plain payload object (no enum tag): the
//!   envelope's `type` field is the single discriminator. Deserialization goes
//!   through [`Payload::from_raw`], which dispatches on [`EventType`] — never on
//!   shape inference.

use std::collections::BTreeMap;

use serde::{
    Deserialize,
    Serialize,
};

use crate::events::EventType;

/// Why a session is finalizing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalizeReason {
    /// The scheduled uptime elapsed.
    Deadline,
    /// Every scoped process died and autoshutdown enabled early finalization.
    DeadScope,
    /// The Controller requested it (future inbound control).
    InboundRequest,
    /// An unrecoverable agent error.
    Error,
}

/// Which mechanism launched the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Launcher {
    /// `CreateProcessAsUser` with the interactive user's token.
    Token,
    /// Legacy scheduled-task trick (EventID-777 + run-as-system helper).
    SchedTask,
}

/// What caused a clock adjustment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockCause {
    /// Fake timestamp set at study start (session 0).
    StudyStart,
    /// Per-session offset applied at finalization.
    SessionOffset,
}

/// Payload of `process.started`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStartedData {
    /// OS process id.
    pub pid: u32,
    /// OS process id of the parent, when reported by the source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
    /// Process image file name (with extension).
    pub name: String,
    /// Full image path, when resolvable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_path: Option<String>,
    /// Full command line, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    /// OS session id (0 = services, > 0 = interactive); distinct from study sessions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_session_id: Option<u32>,
}

/// Payload of `process.stopped`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStoppedData {
    /// OS process id.
    pub pid: u32,
    /// Process image file name (with extension).
    pub name: String,
}

/// Payload of `thread.started`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadStartedData {
    /// Owning process id.
    pub pid: u32,
    /// OS thread id.
    pub tid: u32,
    /// Creating thread id, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_tid: Option<u32>,
}

/// Payload of `thread.stopped`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadStoppedData {
    /// Owning process id.
    pub pid: u32,
    /// OS thread id.
    pub tid: u32,
}

/// Payload of `image.loaded`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageLoadedData {
    /// Loading process id.
    pub pid: u32,
    /// Image file name.
    pub name: String,
    /// Full image path, when resolvable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_path: Option<String>,
    /// Image size in bytes, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_size: Option<u64>,
    /// Image checksum, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_checksum: Option<u32>,
}

/// Payload of `image.unloaded`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageUnloadedData {
    /// Unloading process id.
    pub pid: u32,
    /// Image file name.
    pub name: String,
}

/// Payload schema shared by `registry.key_created`, `registry.key_deleted`,
/// `registry.key_opened`, `registry.key_closed` and `registry.key_queried`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryKeyData {
    /// Accessing process id.
    pub pid: u32,
    /// Full key path (e.g. `\REGISTRY\MACHINE\SOFTWARE\...`).
    pub key_name: String,
    /// Kernel key handle, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_handle: Option<u64>,
}

/// Payload of `registry.value_queried`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryValueQueriedData {
    /// Accessing process id.
    pub pid: u32,
    /// Full key path.
    pub key_name: String,
    /// Queried value name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_name: Option<String>,
    /// Kernel key handle, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_handle: Option<u64>,
}

/// Payload of `registry.value_set`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryValueSetData {
    /// Writing process id.
    pub pid: u32,
    /// Full key path.
    pub key_name: String,
    /// Written value name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_name: Option<String>,
    /// Kernel key handle, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_handle: Option<u64>,
    /// Registry value type name (e.g. `REG_SZ`), when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
    /// Written data size in bytes, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_size: Option<u32>,
}

/// Payload of `file.created`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileCreatedData {
    /// Creating process id.
    pub pid: u32,
    /// Kernel file object address (file identity before name resolution).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_object: Option<u64>,
    /// File name, when available at creation time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    /// `CreateOptions` flags, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_options: Option<u32>,
    /// `CreateDisposition` code, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_disposition: Option<u32>,
}

/// Payload of `file.written`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileWrittenData {
    /// Writing process id.
    pub pid: u32,
    /// Kernel file object address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_object: Option<u64>,
    /// Kernel file key (stable per file instance).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_key: Option<u64>,
    /// File name, when resolvable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    /// Bytes written by this I/O, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_size: Option<u64>,
    /// Write offset in bytes, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
}

/// Payload schema shared by `file.closed` and `file.cleaned_up`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileReleasedData {
    /// Closing process id.
    pub pid: u32,
    /// Kernel file object address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_object: Option<u64>,
    /// Kernel file key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_key: Option<u64>,
    /// File name, when resolvable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
}

/// Payload of `file.deleted`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileDeletedData {
    /// Deleting process id.
    pub pid: u32,
    /// Kernel file object address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_object: Option<u64>,
    /// Kernel file key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_key: Option<u64>,
    /// File name, when resolvable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
}

/// Payload of `file.renamed`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRenamedData {
    /// Renaming process id.
    pub pid: u32,
    /// Kernel file object address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_object: Option<u64>,
    /// Old file name, when resolvable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    /// New file name, when resolvable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_name: Option<String>,
    /// Kernel file key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_key: Option<u64>,
}

/// Payload of `file.fsctl`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileFsctlData {
    /// Issuing process id.
    pub pid: u32,
    /// Kernel file object address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_object: Option<u64>,
    /// File name, when resolvable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    /// Kernel file key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_key: Option<u64>,
}

/// Payload schema shared by `net.tcp.connected`, `net.tcp.accepted` and
/// `net.tcp.disconnected`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpConnectionData {
    /// Owning process id, when attributable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Source IP address (IPv4 or IPv6, rendered as string).
    pub source_addr: String,
    /// Source port.
    pub source_port: u16,
    /// Destination IP address.
    pub dest_addr: String,
    /// Destination port.
    pub dest_port: u16,
}

/// Payload of `session.started`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionStartedData {
    /// Scheduled session duration in seconds; `None` = dynamic (uptimes exhausted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduled_duration_secs: Option<u64>,
}

/// Payload of `session.finalizing`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionFinalizingData {
    /// What triggered finalization.
    pub reason: FinalizeReason,
}

/// Payload of `session.ended` — empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionEndedData {}

/// Payload of `scope.died` — empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeDiedData {}

/// Payload of `target.launched`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetLaunchedData {
    /// Target process id, when the launcher reported one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Launch path (post file-association resolution).
    pub path: String,
    /// Launch arguments, when any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<String>,
    /// Mechanism used.
    pub launcher: Launcher,
}

/// Payload of `agent.state` (legacy `StateReport`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentStateData {
    /// Agent build version.
    pub agent_version: String,
}

/// Payload of `study.score` (legacy `ScoreReport`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StudyScoreData {
    /// Session score.
    pub score: u32,
    /// What produced the score, when attributed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Payload of `study.drops_summary` (legacy `DropsReport`, now structured).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StudyDropsSummaryData {
    /// Observed drop extensions histogram: extension → count. `""` = extensionless.
    pub extensions: BTreeMap<String, u32>,
}

/// Payload of `study.reboot_requested`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StudyRebootRequestedData {
    /// Why the reboot was requested, when attributed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Payload of `study.shutdown_requested`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StudyShutdownRequestedData {
    /// Why shutdown was requested; carries the abort error, when any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Payload of `drop.observed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DropObservedData {
    /// Observed file path.
    pub path: String,
    /// Writing process id, when scoped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}

/// Payload of `drop.closed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DropClosedData {
    /// File path whose last handle closed — safe to copy.
    pub path: String,
}

/// Payload of `drop.copied`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DropCopiedData {
    /// Original path inside the VM.
    pub source: String,
    /// Copy path in the drops directory.
    pub copy: String,
    /// Copy size in bytes.
    pub size_bytes: u64,
}

/// Payload of `drop.uploaded`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DropUploadedData {
    /// Copy path that was uploaded.
    pub copy: String,
    /// Upload size in bytes.
    pub size_bytes: u64,
}

/// Payload of `screenshot.received`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenshotReceivedData {
    /// Per-session screenshot sequence number.
    pub seq: u32,
    /// JPEG size in bytes.
    pub size_bytes: u64,
}

/// Payload of `screenshot.uploaded`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenshotUploadedData {
    /// Per-session screenshot sequence number.
    pub seq: u32,
}

/// Payload of `user_actor.started`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserActorStartedData {
    /// User-actor build version (from its `HELLO`).
    pub module_version: String,
    /// User-actor process id, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}

/// Payload of `user_actor.stopped`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserActorStoppedData {
    /// Why it stopped, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Payload of `clock.adjusted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockAdjustedData {
    /// New wall clock value, unix milliseconds.
    pub to_ts: i64,
    /// Applied offset in seconds.
    pub offset_secs: i64,
    /// What caused the adjustment.
    pub cause: ClockCause,
}

/// Payload of `control.keepalive` — empty; liveness is carried by the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlKeepaliveData {}

/// Payload of `control.reboot`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRebootData {
    /// Why the reboot was requested, when attributed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Payload of `control.shutdown`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlShutdownData {
    /// Why shutdown was requested, when attributed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Generates the [`Payload`] enum, its `event_type` mapping and the strict
/// `from_raw` validator from a single variant↔event table (one source of truth).
macro_rules! payload_variants {
    ($( $variant:ident ( $ty:ty ) => $event:path ),* $(,)?) => {
        /// Typed payload carried in [`crate::nats::Envelope::data`].
        ///
        /// Serializes untagged (the envelope `type` field is the discriminator);
        /// deserializes only via [`Payload::from_raw`].
        #[allow(missing_docs)]
        #[derive(Debug, Clone, PartialEq, serde::Serialize)]
        #[serde(untagged)]
        pub enum Payload {
            $( $variant($ty) ),*
        }

        impl Payload {
            /// The canonical event type this payload belongs to.
            #[must_use]
            pub fn event_type(&self) -> EventType {
                match self {
                    $( Self::$variant(_) => $event, )*
                }
            }

            /// Validate raw JSON against the schema registered for `event_type`.
            ///
            /// # Errors
            /// [`serde_json::Error`] when `data` does not match the schema.
            pub fn from_raw(
                event_type: EventType,
                data: serde_json::Value,
            ) -> Result<Self, serde_json::Error> {
                match event_type {
                    $( $event => Ok(Self::$variant(serde_json::from_value(data)?)), )*
                }
            }
        }
    };
}

payload_variants! {
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
    SessionStarted(SessionStartedData) => EventType::SessionStarted,
    SessionFinalizing(SessionFinalizingData) => EventType::SessionFinalizing,
    SessionEnded(SessionEndedData) => EventType::SessionEnded,
    ScopeDied(ScopeDiedData) => EventType::ScopeDied,
    TargetLaunched(TargetLaunchedData) => EventType::TargetLaunched,
    AgentState(AgentStateData) => EventType::AgentState,
    StudyScore(StudyScoreData) => EventType::StudyScore,
    StudyDropsSummary(StudyDropsSummaryData) => EventType::StudyDropsSummary,
    StudyRebootRequested(StudyRebootRequestedData) => EventType::StudyRebootRequested,
    StudyShutdownRequested(StudyShutdownRequestedData) => EventType::StudyShutdownRequested,
    DropObserved(DropObservedData) => EventType::DropObserved,
    DropClosed(DropClosedData) => EventType::DropClosed,
    DropCopied(DropCopiedData) => EventType::DropCopied,
    DropUploaded(DropUploadedData) => EventType::DropUploaded,
    ScreenshotReceived(ScreenshotReceivedData) => EventType::ScreenshotReceived,
    ScreenshotUploaded(ScreenshotUploadedData) => EventType::ScreenshotUploaded,
    UserActorStarted(UserActorStartedData) => EventType::UserActorStarted,
    UserActorStopped(UserActorStoppedData) => EventType::UserActorStopped,
    ClockAdjusted(ClockAdjustedData) => EventType::ClockAdjusted,
    ControlKeepalive(ControlKeepaliveData) => EventType::ControlKeepalive,
    ControlReboot(ControlRebootData) => EventType::ControlReboot,
    ControlShutdown(ControlShutdownData) => EventType::ControlShutdown,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::events::ALL;

    /// One representative payload per taxonomy member, so the roundtrip matrix
    /// covers every schema.
    #[allow(clippy::too_many_lines)] // exhaustive fixture table, one arm per event
    fn sample_for(event: EventType) -> Payload {
        match event {
            EventType::ProcessStarted => Payload::ProcessStarted(ProcessStartedData {
                pid: 484,
                parent_pid: Some(1200),
                name: "evil.exe".to_owned(),
                image_path: Some("C:\\Users\\victim\\AppData\\evil.exe".to_owned()),
                command_line: Some("\"C:\\Users\\victim\\AppData\\evil.exe\" -q".to_owned()),
                os_session_id: Some(1),
            }),
            EventType::ProcessStopped => Payload::ProcessStopped(ProcessStoppedData {
                pid: 484,
                name: "evil.exe".to_owned(),
            }),
            EventType::ThreadStarted => Payload::ThreadStarted(ThreadStartedData {
                pid: 484,
                tid: 9001,
                parent_tid: Some(9000),
            }),
            EventType::ThreadStopped => {
                Payload::ThreadStopped(ThreadStoppedData { pid: 484, tid: 9001 })
            }
            EventType::ImageLoaded => Payload::ImageLoaded(ImageLoadedData {
                pid: 484,
                name: "kernel32.dll".to_owned(),
                image_path: Some("C:\\Windows\\System32\\kernel32.dll".to_owned()),
                image_size: Some(738_816),
                image_checksum: Some(0x0017_C0DE),
            }),
            EventType::ImageUnloaded => Payload::ImageUnloaded(ImageUnloadedData {
                pid: 484,
                name: "kernel32.dll".to_owned(),
            }),
            EventType::RegistryKeyCreated
            | EventType::RegistryKeyDeleted
            | EventType::RegistryKeyOpened
            | EventType::RegistryKeyClosed
            | EventType::RegistryKeyQueried => {
                let key = RegistryKeyData {
                    pid: 484,
                    key_name: "\\REGISTRY\\MACHINE\\SOFTWARE\\SOD_1465182366".to_owned(),
                    key_handle: Some(0xFFFF_C000_1234_5678),
                };
                match event {
                    EventType::RegistryKeyCreated => Payload::RegistryKeyCreated(key),
                    EventType::RegistryKeyDeleted => Payload::RegistryKeyDeleted(key),
                    EventType::RegistryKeyOpened => Payload::RegistryKeyOpened(key),
                    EventType::RegistryKeyClosed => Payload::RegistryKeyClosed(key),
                    _ => Payload::RegistryKeyQueried(key),
                }
            }
            EventType::RegistryValueQueried => {
                Payload::RegistryValueQueried(RegistryValueQueriedData {
                    pid: 484,
                    key_name: "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\DirectX".to_owned(),
                    value_name: Some("Version".to_owned()),
                    key_handle: None,
                })
            }
            EventType::RegistryValueSet => Payload::RegistryValueSet(RegistryValueSetData {
                pid: 484,
                key_name: "\\REGISTRY\\MACHINE\\SOFTWARE\\SOD_1465182366".to_owned(),
                value_name: Some("Version".to_owned()),
                key_handle: Some(0xFFFF_C000_1234_5678),
                value_type: Some("REG_SZ".to_owned()),
                data_size: Some(4),
            }),
            EventType::FileCreated => Payload::FileCreated(FileCreatedData {
                pid: 484,
                file_object: Some(0xFFFF_8900_ABCD_0001),
                file_name: Some("C:\\Users\\victim\\Desktop\\notes.txt.enc".to_owned()),
                create_options: Some(0x0000_0020),
                create_disposition: Some(2),
            }),
            EventType::FileWritten => Payload::FileWritten(FileWrittenData {
                pid: 484,
                file_object: Some(0xFFFF_8900_ABCD_0001),
                file_key: Some(0x0000_002A_0000_0001),
                file_name: None,
                io_size: Some(4096),
                offset: Some(0),
            }),
            EventType::FileClosed => Payload::FileClosed(FileReleasedData {
                pid: 484,
                file_object: Some(0xFFFF_8900_ABCD_0001),
                file_key: Some(0x0000_002A_0000_0001),
                file_name: Some("C:\\Users\\victim\\Desktop\\notes.txt.enc".to_owned()),
            }),
            EventType::FileCleanedUp => Payload::FileCleanedUp(FileReleasedData {
                pid: 484,
                file_object: Some(0xFFFF_8900_ABCD_0001),
                file_key: Some(0x0000_002A_0000_0001),
                file_name: None,
            }),
            EventType::FileDeleted => Payload::FileDeleted(FileDeletedData {
                pid: 484,
                file_object: Some(0xFFFF_8900_ABCD_0001),
                file_key: Some(0x0000_002A_0000_0001),
                file_name: Some("C:\\Users\\victim\\Desktop\\notes.txt.enc".to_owned()),
            }),
            EventType::FileRenamed => Payload::FileRenamed(FileRenamedData {
                pid: 484,
                file_object: Some(0xFFFF_8900_ABCD_0001),
                file_name: Some("C:\\drop\\a.tmp".to_owned()),
                new_name: Some("C:\\drop\\a.dll".to_owned()),
                file_key: Some(0x0000_002A_0000_0001),
            }),
            EventType::FileFsctl => Payload::FileFsctl(FileFsctlData {
                pid: 484,
                file_object: Some(0xFFFF_8900_ABCD_0001),
                file_name: None,
                file_key: Some(0x0000_002A_0000_0001),
            }),
            EventType::NetTcpConnected => Payload::NetTcpConnected(TcpConnectionData {
                pid: Some(484),
                source_addr: "192.168.56.10".to_owned(),
                source_port: 49_152,
                dest_addr: "203.0.113.7".to_owned(),
                dest_port: 443,
            }),
            EventType::NetTcpAccepted => Payload::NetTcpAccepted(TcpConnectionData {
                pid: Some(484),
                source_addr: "192.168.56.10".to_owned(),
                source_port: 49_152,
                dest_addr: "203.0.113.7".to_owned(),
                dest_port: 443,
            }),
            EventType::NetTcpDisconnected => Payload::NetTcpDisconnected(TcpConnectionData {
                pid: Some(484),
                source_addr: "192.168.56.10".to_owned(),
                source_port: 49_152,
                dest_addr: "203.0.113.7".to_owned(),
                dest_port: 443,
            }),
            EventType::SessionStarted => {
                Payload::SessionStarted(SessionStartedData { scheduled_duration_secs: Some(6000) })
            }
            EventType::SessionFinalizing => Payload::SessionFinalizing(SessionFinalizingData {
                reason: FinalizeReason::Deadline,
            }),
            EventType::SessionEnded => Payload::SessionEnded(SessionEndedData {}),
            EventType::ScopeDied => Payload::ScopeDied(ScopeDiedData {}),
            EventType::TargetLaunched => Payload::TargetLaunched(TargetLaunchedData {
                pid: Some(484),
                path: "C:\\Targets\\evil.exe".to_owned(),
                args: Some("-q".to_owned()),
                launcher: Launcher::Token,
            }),
            EventType::AgentState => {
                Payload::AgentState(AgentStateData { agent_version: "0.1.0".to_owned() })
            }
            EventType::StudyScore => Payload::StudyScore(StudyScoreData {
                score: 4,
                reason: Some("CliStarted".to_owned()),
            }),
            EventType::StudyDropsSummary => Payload::StudyDropsSummary(StudyDropsSummaryData {
                extensions: BTreeMap::from([(".txt".to_owned(), 3), (String::new(), 1)]),
            }),
            EventType::StudyRebootRequested => {
                Payload::StudyRebootRequested(StudyRebootRequestedData {
                    reason: Some("session 3 of 24 finished".to_owned()),
                })
            }
            EventType::StudyShutdownRequested => {
                Payload::StudyShutdownRequested(StudyShutdownRequestedData {
                    reason: Some("last session finished".to_owned()),
                })
            }
            EventType::DropObserved => Payload::DropObserved(DropObservedData {
                path: "C:\\Users\\victim\\Desktop\\notes.txt.enc".to_owned(),
                pid: Some(484),
            }),
            EventType::DropClosed => Payload::DropClosed(DropClosedData {
                path: "C:\\Users\\victim\\Desktop\\notes.txt.enc".to_owned(),
            }),
            EventType::DropCopied => Payload::DropCopied(DropCopiedData {
                source: "C:\\Users\\victim\\Desktop\\notes.txt.enc".to_owned(),
                copy: "Drops\\4-0007-ab12cd34.txt".to_owned(),
                size_bytes: 4096,
            }),
            EventType::DropUploaded => Payload::DropUploaded(DropUploadedData {
                copy: "Drops\\4-0007-ab12cd34.txt".to_owned(),
                size_bytes: 4096,
            }),
            EventType::ScreenshotReceived => {
                Payload::ScreenshotReceived(ScreenshotReceivedData { seq: 3, size_bytes: 61_440 })
            }
            EventType::ScreenshotUploaded => {
                Payload::ScreenshotUploaded(ScreenshotUploadedData { seq: 3 })
            }
            EventType::UserActorStarted => Payload::UserActorStarted(UserActorStartedData {
                module_version: "0.1.0".to_owned(),
                pid: Some(2400),
            }),
            EventType::UserActorStopped => Payload::UserActorStopped(UserActorStoppedData {
                reason: Some("session finalize".to_owned()),
            }),
            EventType::ClockAdjusted => Payload::ClockAdjusted(ClockAdjustedData {
                to_ts: 1_465_182_366_000,
                offset_secs: 2_680_000,
                cause: ClockCause::SessionOffset,
            }),
            EventType::ControlKeepalive => Payload::ControlKeepalive(ControlKeepaliveData {}),
            EventType::ControlReboot => Payload::ControlReboot(ControlRebootData { reason: None }),
            EventType::ControlShutdown => Payload::ControlShutdown(ControlShutdownData {
                reason: Some("lab cleanup".to_owned()),
            }),
        }
    }

    #[test]
    fn event_type_mapping_is_a_perfect_matching() {
        for &event in ALL {
            let payload = sample_for(event);
            assert_eq!(payload.event_type(), event);
        }
    }

    #[test]
    fn every_schema_validates_its_own_sample() {
        for &event in ALL {
            let payload = sample_for(event);
            let raw = serde_json::to_value(&payload).unwrap();
            let back = Payload::from_raw(event, raw).unwrap();
            assert_eq!(back, payload);
        }
    }

    #[test]
    fn shape_mismatch_is_rejected() {
        let bad = serde_json::json!({ "nope": 1 });
        assert!(Payload::from_raw(EventType::ProcessStarted, bad).is_err());
    }

    #[test]
    fn empty_payloads_serialize_as_empty_objects() {
        let raw = serde_json::to_value(Payload::ControlKeepalive(ControlKeepaliveData {})).unwrap();
        assert_eq!(raw, serde_json::json!({}));
    }
}
