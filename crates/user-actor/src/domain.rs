//! User-actor domain model: the inbound event taxonomy, the derived bus
//! taxonomy, focus tracking, and the shared runtime state the config push
//! fills in.

use std::sync::Arc;

use parking_lot::Mutex;
use protocol::config::UserActorConfig;

/// Foreground-window snapshot emitted by every focus source (polling,
/// `WinEvent` hook, fakes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FocusInfo {
    /// OS process id owning the foreground window (0 when unresolved).
    pub pid: u32,
    /// Foreground window title (may be empty).
    pub title: String,
    /// Foreground process image name, when resolvable.
    pub process: Option<String>,
}

/// Change detector shared by focus sources: suppresses repeats so a 50 ms
/// poll (or repeated `EVENT_OBJECT_FOCUS` per element) yields one event per
/// actual foreground change.
#[derive(Debug, Default)]
pub struct FocusDedup {
    last: Option<FocusInfo>,
}

impl FocusDedup {
    /// Report a candidate; [`Some`] when it differs from the previous one.
    pub fn changed(&mut self, candidate: FocusInfo) -> Option<FocusInfo> {
        if self.last.as_ref() == Some(&candidate) {
            None
        } else {
            self.last = Some(candidate.clone());
            Some(candidate)
        }
    }
}

/// Inbound event of the user-actor core. Fire-and-forget: outputs happen only
/// via driven ports (capture, sink, input synthesis).
#[derive(Debug, Clone)]
pub enum ActorEvent {
    /// The agent pushed the runtime configuration (IPC `WELCOME`, handshake or
    /// re-pull). The user-actor reads no files — this is its whole config.
    Welcome(protocol::ipc::messages::Welcome),
    /// The foreground window changed.
    FocusChanged(FocusInfo),
}

/// Derived, plugin-owned bus events (never raw inbound events — the
/// pipeline→bus bridge is plugin behavior).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActorBusEvent {
    /// The pushed config became active; carries the effective settings.
    ConfigApplied(UserActorConfig),
    /// A (deduplicated) foreground change — consumed by the reactive plugin.
    ForegroundChanged {
        /// The new foreground window.
        focus: FocusInfo,
    },
    /// A screenshot left through the sink.
    ScreenshotTaken {
        /// Per-session capture sequence number.
        seq: u32,
    },
    /// The capture quota ran out; further captures are skipped until reboot.
    CaptureQuotaExhausted,
}

/// Runtime state assembled from the IPC config push (the user-actor's only
/// source of truth).
#[derive(Debug, Default, Clone)]
pub struct RuntimeState {
    /// Study-local session id from the `WELCOME` push.
    pub session_id: u32,
    /// Effective configuration; `None` until the first `WELCOME`.
    pub config: Option<UserActorConfig>,
}

/// Shared handle to the runtime state (pipeline is serial; the mutex guards
/// host and bus accessors).
pub type SharedRuntime = Arc<Mutex<RuntimeState>>;

/// Services bundle injected into every plugin hook (mirrors the agent's
/// `AgentServices`; carries the driven ports the plugins need).
#[derive(Clone)]
pub struct ActorServices {
    /// Runtime state filled by the `WELCOME` push.
    pub runtime: SharedRuntime,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn focus(pid: u32, title: &str) -> FocusInfo {
        FocusInfo { pid, title: title.to_owned(), process: None }
    }

    #[test]
    fn dedup_suppresses_repeats() {
        let mut dedup = FocusDedup::default();
        assert_eq!(dedup.changed(focus(1, "a")), Some(focus(1, "a")));
        assert_eq!(dedup.changed(focus(1, "a")), None);
        assert_eq!(dedup.changed(focus(1, "b")), Some(focus(1, "b")));
        assert_eq!(dedup.changed(focus(2, "b")), Some(focus(2, "b")));
        assert_eq!(dedup.changed(focus(2, "b")), None);
    }

    #[test]
    fn dedup_treats_empty_process_and_none_distinctly() {
        let mut dedup = FocusDedup::default();
        let no_process = FocusInfo { pid: 1, title: "t".to_owned(), process: None };
        let empty_process =
            FocusInfo { pid: 1, title: "t".to_owned(), process: Some(String::new()) };
        assert_eq!(dedup.changed(no_process.clone()), Some(no_process));
        assert_eq!(dedup.changed(empty_process.clone()), Some(empty_process));
    }
}
