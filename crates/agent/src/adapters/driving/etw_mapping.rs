//! Pure ETW → canonical taxonomy mapping.
//!
//! The table below is the single source of truth tying classic Windows Kernel
//! logger providers/opcodes to our own event names. Source-agnostic by design:
//! a driver adapter emits the same canonical names directly, and mixed feeds
//! are possible. Compiled and tested on every platform (no ETW types here).
//!
//! Opcode values are the documented `EVENT_TRACE_TYPE_*` constants of the
//! classic NT kernel logger. Opcodes we deliberately do not subscribe to
//! (e.g. `FileIo` read, TCP send/recv) are unmapped here and filtered by the
//! adapter before they ever reach the pipeline.

use protocol::events::EventType;

/// Classic kernel logger providers we consume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EtwProvider {
    /// `Process` — process lifecycle.
    Process,
    /// `Thread` — thread lifecycle.
    Thread,
    /// `Image` — PE image load/unload.
    Image,
    /// `Registry` — registry operations.
    Registry,
    /// `FileIo` — file operations (read deliberately excluded upstream).
    FileIo,
    /// `TcpIp` — TCP connections (send/recv deliberately excluded upstream).
    TcpIp,
}

impl EtwProvider {
    /// Canonical GUID string (lowercase, no braces).
    #[must_use]
    pub const fn guid(self) -> &'static str {
        match self {
            Self::Process => "3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c",
            Self::Thread => "3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c",
            Self::Image => "2cb15d1d-5fc1-11d2-abe1-00a0c911f518",
            Self::Registry => "ae53722e-c863-11d2-8659-00c04fa321a1",
            Self::FileIo => "90dcb41a-4483-41a8-87b4-735a11b3b0e4",
            Self::TcpIp => "9a280ac0-c8e0-11d1-84e2-00c04fb998a2",
        }
    }

    /// Resolve a provider from a GUID string (case-insensitive, braces and
    /// whitespace tolerated).
    #[must_use]
    pub fn from_guid(guid: &str) -> Option<Self> {
        let normalized = guid.trim().trim_start_matches('{').trim_end_matches('}').to_lowercase();
        Self::ALL.into_iter().find(|provider| provider.guid() == normalized)
    }
}

impl EtwProvider {
    /// All providers, taxonomy order.
    pub const ALL: [Self; 6] =
        [Self::Process, Self::Thread, Self::Image, Self::Registry, Self::FileIo, Self::TcpIp];
}

/// Map `(provider, opcode)` onto the canonical event type.
///
/// DCStart/DCEnd opcodes (3/4) fold into started/stopped: on a fresh boot the
/// kernel replays existing processes/threads through DC events, and the scope
/// tracker treats them identically (legacy did the same).
#[must_use]
pub fn event_type(provider: EtwProvider, opcode: u8) -> Option<EventType> {
    let event = match provider {
        EtwProvider::Process => match opcode {
            1 | 3 => EventType::ProcessStarted,
            2 | 4 => EventType::ProcessStopped,
            _ => return None,
        },
        EtwProvider::Thread => match opcode {
            1 | 3 => EventType::ThreadStarted,
            2 | 4 => EventType::ThreadStopped,
            _ => return None,
        },
        EtwProvider::Image => match opcode {
            10 => EventType::ImageLoaded,
            11 => EventType::ImageUnloaded,
            _ => return None,
        },
        EtwProvider::Registry => match opcode {
            10 => EventType::RegistryKeyCreated,
            11 => EventType::RegistryKeyOpened,
            12 => EventType::RegistryKeyDeleted,
            13 => EventType::RegistryKeyQueried,
            14 => EventType::RegistryValueSet,
            16 | 22 => EventType::RegistryValueQueried,
            27 => EventType::RegistryKeyClosed,
            _ => return None,
        },
        EtwProvider::FileIo => match opcode {
            32 => EventType::FileCreated,
            20 => EventType::FileWritten,
            35 => EventType::FileClosed,
            36 => EventType::FileCleanedUp,
            33 => EventType::FileDeleted,
            34 => EventType::FileRenamed,
            42 => EventType::FileFsctl,
            _ => return None,
        },
        EtwProvider::TcpIp => match opcode {
            12 | 28 => EventType::NetTcpConnected,
            15 | 31 => EventType::NetTcpAccepted,
            13 | 29 => EventType::NetTcpDisconnected,
            _ => return None,
        },
    };
    Some(event)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_roundtrip_is_case_and_brace_tolerant() {
        for provider in EtwProvider::ALL {
            assert_eq!(EtwProvider::from_guid(provider.guid()), Some(provider));
            let braced_upper = format!("{{{}}}", provider.guid().to_uppercase());
            assert_eq!(EtwProvider::from_guid(&braced_upper), Some(provider));
        }
        assert_eq!(EtwProvider::from_guid("not-a-guid"), None);
    }

    #[test]
    fn legacy_subscribed_events_all_map() {
        // The exact set legacy consumed (see root AGENTS.md), nothing less.
        let expected: &[(EtwProvider, u8, EventType)] = &[
            (EtwProvider::Process, 1, EventType::ProcessStarted),
            (EtwProvider::Process, 2, EventType::ProcessStopped),
            (EtwProvider::Process, 3, EventType::ProcessStarted),
            (EtwProvider::Process, 4, EventType::ProcessStopped),
            (EtwProvider::Thread, 1, EventType::ThreadStarted),
            (EtwProvider::Thread, 2, EventType::ThreadStopped),
            (EtwProvider::Thread, 3, EventType::ThreadStarted),
            (EtwProvider::Thread, 4, EventType::ThreadStopped),
            (EtwProvider::Image, 10, EventType::ImageLoaded),
            (EtwProvider::Image, 11, EventType::ImageUnloaded),
            (EtwProvider::Registry, 10, EventType::RegistryKeyCreated),
            (EtwProvider::Registry, 12, EventType::RegistryKeyDeleted),
            (EtwProvider::Registry, 11, EventType::RegistryKeyOpened),
            (EtwProvider::Registry, 27, EventType::RegistryKeyClosed),
            (EtwProvider::Registry, 13, EventType::RegistryKeyQueried),
            (EtwProvider::Registry, 16, EventType::RegistryValueQueried),
            (EtwProvider::Registry, 22, EventType::RegistryValueQueried),
            (EtwProvider::Registry, 14, EventType::RegistryValueSet),
            (EtwProvider::FileIo, 32, EventType::FileCreated),
            (EtwProvider::FileIo, 20, EventType::FileWritten),
            (EtwProvider::FileIo, 35, EventType::FileClosed),
            (EtwProvider::FileIo, 36, EventType::FileCleanedUp),
            (EtwProvider::FileIo, 33, EventType::FileDeleted),
            (EtwProvider::FileIo, 34, EventType::FileRenamed),
            (EtwProvider::FileIo, 42, EventType::FileFsctl),
            (EtwProvider::TcpIp, 12, EventType::NetTcpConnected),
            (EtwProvider::TcpIp, 28, EventType::NetTcpConnected),
            (EtwProvider::TcpIp, 15, EventType::NetTcpAccepted),
            (EtwProvider::TcpIp, 31, EventType::NetTcpAccepted),
            (EtwProvider::TcpIp, 13, EventType::NetTcpDisconnected),
            (EtwProvider::TcpIp, 29, EventType::NetTcpDisconnected),
        ];
        for (provider, opcode, event) in expected {
            assert_eq!(event_type(*provider, *opcode), Some(*event));
        }
    }

    #[test]
    fn deliberately_excluded_events_are_unmapped() {
        // FileIo read (too noisy since legacy) and TCP send/recv/other opcodes.
        assert_eq!(event_type(EtwProvider::FileIo, 15), None);
        assert_eq!(event_type(EtwProvider::FileIo, 0), None);
        assert_eq!(event_type(EtwProvider::TcpIp, 10), None);
        assert_eq!(event_type(EtwProvider::TcpIp, 11), None);
        assert_eq!(event_type(EtwProvider::Process, 99), None);
    }
}
