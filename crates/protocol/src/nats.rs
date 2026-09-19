//! NATS envelope and channel model (protocol v3).
//!
//! Every message on `control_channel` and `event_channel` uses the same envelope.
//! The agent is publish-only today (observe-only); an inbound control subscription
//! is future work behind a driving port.

use serde::{
    Deserialize,
    Serialize,
};
use uuid::Uuid;

use crate::events::EventType;

/// Wire protocol version carried in every envelope.
pub const PROTOCOL_VERSION: u32 = 3;

/// Envelope for every message on both channels.
///
/// `ts` is unix **milliseconds** read from the (deliberately fake) system clock —
/// never use it for absolute correlation; correlate by `study`/`session`.
/// `seq` is monotonic per publisher connection so the Controller can detect loss.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope<D = serde_json::Value> {
    /// Wire protocol version; see [`PROTOCOL_VERSION`].
    pub v: u32,
    /// Canonical event type; the `data` payload schema is keyed by it.
    #[serde(rename = "type")]
    pub event_type: EventType,
    /// Unix milliseconds from the manipulated system clock.
    pub ts: i64,
    /// Study id — generated at session 0, persisted in the scope DB.
    pub study: Uuid,
    /// Session id (one boot-to-reboot interval) within the study.
    pub session: u32,
    /// Monotonic sequence number for Controller-side loss detection.
    pub seq: u64,
    /// Type-specific payload.
    pub data: D,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn golden_envelope_roundtrip() {
        let json = serde_json::json!({
            "v": 3,
            "type": "process.started",
            "ts": 1_699_999_999_999_i64,
            "study": "00000000-0000-0000-0000-000000000001",
            "session": 4,
            "seq": 12_345,
            "data": {"pid": 484},
        });

        let envelope: Envelope<serde_json::Value> = serde_json::from_value(json).unwrap();

        assert_eq!(envelope.v, PROTOCOL_VERSION);
        assert_eq!(envelope.event_type, EventType::ProcessStarted);
        assert_eq!(envelope.ts, 1_699_999_999_999);
        assert_eq!(envelope.session, 4);
        assert_eq!(envelope.seq, 12_345);
        assert_eq!(envelope.data.get("pid"), Some(&serde_json::json!(484)));

        let back = serde_json::to_value(&envelope).unwrap();
        assert_eq!(back.get("type"), Some(&serde_json::json!("process.started")));
    }

    #[test]
    fn unknown_type_is_rejected() {
        let json = serde_json::json!({
            "v": 3,
            "type": "process.bogus",
            "ts": 0,
            "study": "00000000-0000-0000-0000-000000000001",
            "session": 0,
            "seq": 0,
            "data": {},
        });

        assert!(serde_json::from_value::<Envelope>(json).is_err());
    }
}
