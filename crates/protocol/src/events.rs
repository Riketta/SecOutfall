//! Canonical event taxonomy, shared by internal pipeline events and the wire.
//!
//! Source-agnostic: the ETW adapter maps native Task/Opcode names onto these; a
//! future driver adapter emits the same names directly, enabling mixed feeds.

use serde::{
    Deserialize,
    Serialize,
};

/// Every canonical event name. The wire envelope's `type` field carries
/// [`EventType::as_str`]; the `data` payload schema is keyed by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    /// A new process started.
    #[serde(rename = "process.started")]
    ProcessStarted,
    /// A process stopped.
    #[serde(rename = "process.stopped")]
    ProcessStopped,
    /// A new thread started.
    #[serde(rename = "thread.started")]
    ThreadStarted,
    /// A thread stopped.
    #[serde(rename = "thread.stopped")]
    ThreadStopped,
    /// An image (PE module) was loaded into a process.
    #[serde(rename = "image.loaded")]
    ImageLoaded,
    /// An image was unloaded from a process.
    #[serde(rename = "image.unloaded")]
    ImageUnloaded,
    /// A registry key was created.
    #[serde(rename = "registry.key_created")]
    RegistryKeyCreated,
    /// A registry key was deleted.
    #[serde(rename = "registry.key_deleted")]
    RegistryKeyDeleted,
    /// A registry key was opened (handle acquired).
    #[serde(rename = "registry.key_opened")]
    RegistryKeyOpened,
    /// A registry key handle was closed.
    #[serde(rename = "registry.key_closed")]
    RegistryKeyClosed,
    /// A registry key (metadata) was queried.
    #[serde(rename = "registry.key_queried")]
    RegistryKeyQueried,
    /// A registry value was queried.
    #[serde(rename = "registry.value_queried")]
    RegistryValueQueried,
    /// A registry value was written.
    #[serde(rename = "registry.value_set")]
    RegistryValueSet,
    /// A file was created/opened with create disposition.
    #[serde(rename = "file.created")]
    FileCreated,
    /// A file was written to.
    #[serde(rename = "file.written")]
    FileWritten,
    /// A file handle was closed.
    #[serde(rename = "file.closed")]
    FileClosed,
    /// A file was cleaned up (last handle closed, object teardown).
    #[serde(rename = "file.cleaned_up")]
    FileCleanedUp,
    /// A file was deleted.
    #[serde(rename = "file.deleted")]
    FileDeleted,
    /// A file was renamed.
    #[serde(rename = "file.renamed")]
    FileRenamed,
    /// A filesystem control code was issued against a file.
    #[serde(rename = "file.fsctl")]
    FileFsctl,
    /// An outbound TCP connection was established.
    #[serde(rename = "net.tcp.connected")]
    NetTcpConnected,
    /// An inbound TCP connection was accepted.
    #[serde(rename = "net.tcp.accepted")]
    NetTcpAccepted,
    /// A TCP connection was torn down.
    #[serde(rename = "net.tcp.disconnected")]
    NetTcpDisconnected,
    /// The agent opened a new session.
    #[serde(rename = "session.started")]
    SessionStarted,
    /// The agent began finalizing a session.
    #[serde(rename = "session.finalizing")]
    SessionFinalizing,
    /// The agent ended a session (pre-reboot/shutdown).
    #[serde(rename = "session.ended")]
    SessionEnded,
    /// Every scoped process died — the analysis scope is empty.
    #[serde(rename = "scope.died")]
    ScopeDied,
    /// The malware sample was launched.
    #[serde(rename = "target.launched")]
    TargetLaunched,
    /// A drop (file written by a scoped process) was observed.
    #[serde(rename = "drop.observed")]
    DropObserved,
    /// An observed drop's last handle closed — safe to copy.
    #[serde(rename = "drop.closed")]
    DropClosed,
    /// A drop was copied into the drops directory.
    #[serde(rename = "drop.copied")]
    DropCopied,
    /// A drop was uploaded to the Controller.
    #[serde(rename = "drop.uploaded")]
    DropUploaded,
    /// A screenshot arrived from the user-actor.
    #[serde(rename = "screenshot.received")]
    ScreenshotReceived,
    /// A screenshot was uploaded to the Controller.
    #[serde(rename = "screenshot.uploaded")]
    ScreenshotUploaded,
    /// The user-actor connected and announced itself.
    #[serde(rename = "user_actor.started")]
    UserActorStarted,
    /// The user-actor stopped.
    #[serde(rename = "user_actor.stopped")]
    UserActorStopped,
    /// The system clock was adjusted (study start or per-session offset).
    #[serde(rename = "clock.adjusted")]
    ClockAdjusted,
    /// Agent state report (legacy `StateReport`): protocol/agent versions, session.
    #[serde(rename = "agent.state")]
    AgentState,
    /// Session score report (legacy `ScoreReport`).
    #[serde(rename = "study.score")]
    StudyScore,
    /// Observed drop extension histogram (legacy `DropsReport`).
    #[serde(rename = "study.drops_summary")]
    StudyDropsSummary,
    /// The agent requested a reboot (next session of the study).
    #[serde(rename = "study.reboot_requested")]
    StudyRebootRequested,
    /// The agent requested shutdown (last session of the study).
    #[serde(rename = "study.shutdown_requested")]
    StudyShutdownRequested,
    /// Agent liveness control message (every 15 s).
    #[serde(rename = "control.keepalive")]
    ControlKeepalive,
    /// Inbound control: reboot now (future subscription).
    #[serde(rename = "control.reboot")]
    ControlReboot,
    /// Inbound control: shut down now (future subscription).
    #[serde(rename = "control.shutdown")]
    ControlShutdown,
}

/// All taxonomy members, in taxonomy order.
pub const ALL: &[EventType] = &[
    EventType::ProcessStarted,
    EventType::ProcessStopped,
    EventType::ThreadStarted,
    EventType::ThreadStopped,
    EventType::ImageLoaded,
    EventType::ImageUnloaded,
    EventType::RegistryKeyCreated,
    EventType::RegistryKeyDeleted,
    EventType::RegistryKeyOpened,
    EventType::RegistryKeyClosed,
    EventType::RegistryKeyQueried,
    EventType::RegistryValueQueried,
    EventType::RegistryValueSet,
    EventType::FileCreated,
    EventType::FileWritten,
    EventType::FileClosed,
    EventType::FileCleanedUp,
    EventType::FileDeleted,
    EventType::FileRenamed,
    EventType::FileFsctl,
    EventType::NetTcpConnected,
    EventType::NetTcpAccepted,
    EventType::NetTcpDisconnected,
    EventType::SessionStarted,
    EventType::SessionFinalizing,
    EventType::SessionEnded,
    EventType::ScopeDied,
    EventType::TargetLaunched,
    EventType::DropObserved,
    EventType::DropClosed,
    EventType::DropCopied,
    EventType::DropUploaded,
    EventType::ScreenshotReceived,
    EventType::ScreenshotUploaded,
    EventType::UserActorStarted,
    EventType::UserActorStopped,
    EventType::ClockAdjusted,
    EventType::AgentState,
    EventType::StudyScore,
    EventType::StudyDropsSummary,
    EventType::StudyRebootRequested,
    EventType::StudyShutdownRequested,
    EventType::ControlKeepalive,
    EventType::ControlReboot,
    EventType::ControlShutdown,
];

impl EventType {
    /// The canonical dotted name carried on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessStarted => "process.started",
            Self::ProcessStopped => "process.stopped",
            Self::ThreadStarted => "thread.started",
            Self::ThreadStopped => "thread.stopped",
            Self::ImageLoaded => "image.loaded",
            Self::ImageUnloaded => "image.unloaded",
            Self::RegistryKeyCreated => "registry.key_created",
            Self::RegistryKeyDeleted => "registry.key_deleted",
            Self::RegistryKeyOpened => "registry.key_opened",
            Self::RegistryKeyClosed => "registry.key_closed",
            Self::RegistryKeyQueried => "registry.key_queried",
            Self::RegistryValueQueried => "registry.value_queried",
            Self::RegistryValueSet => "registry.value_set",
            Self::FileCreated => "file.created",
            Self::FileWritten => "file.written",
            Self::FileClosed => "file.closed",
            Self::FileCleanedUp => "file.cleaned_up",
            Self::FileDeleted => "file.deleted",
            Self::FileRenamed => "file.renamed",
            Self::FileFsctl => "file.fsctl",
            Self::NetTcpConnected => "net.tcp.connected",
            Self::NetTcpAccepted => "net.tcp.accepted",
            Self::NetTcpDisconnected => "net.tcp.disconnected",
            Self::SessionStarted => "session.started",
            Self::SessionFinalizing => "session.finalizing",
            Self::SessionEnded => "session.ended",
            Self::ScopeDied => "scope.died",
            Self::TargetLaunched => "target.launched",
            Self::DropObserved => "drop.observed",
            Self::DropClosed => "drop.closed",
            Self::DropCopied => "drop.copied",
            Self::DropUploaded => "drop.uploaded",
            Self::ScreenshotReceived => "screenshot.received",
            Self::ScreenshotUploaded => "screenshot.uploaded",
            Self::UserActorStarted => "user_actor.started",
            Self::UserActorStopped => "user_actor.stopped",
            Self::ClockAdjusted => "clock.adjusted",
            Self::AgentState => "agent.state",
            Self::StudyScore => "study.score",
            Self::StudyDropsSummary => "study.drops_summary",
            Self::StudyRebootRequested => "study.reboot_requested",
            Self::StudyShutdownRequested => "study.shutdown_requested",
            Self::ControlKeepalive => "control.keepalive",
            Self::ControlReboot => "control.reboot",
            Self::ControlShutdown => "control.shutdown",
        }
    }
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn serde_roundtrip_matches_as_str() {
        for event in ALL {
            let json = serde_json::to_string(event).unwrap();
            assert_eq!(json, format!("\"{}\"", event.as_str()));
            let back: EventType = serde_json::from_str(&json).unwrap();
            assert_eq!(back, *event);
        }
    }

    #[test]
    fn unknown_names_are_rejected() {
        assert!(serde_json::from_str::<EventType>("\"process.bogus\"").is_err());
        assert!(serde_json::from_str::<EventType>("\"process.started \"").is_err());
    }
}
