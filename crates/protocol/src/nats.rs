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

use crate::{
    events::EventType,
    payload::Payload,
};

/// Wire protocol version carried in every envelope.
pub const PROTOCOL_VERSION: u32 = 3;

/// Errors from typed envelope validation.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// Envelope declares a different protocol version.
    #[error("unsupported protocol version {0}, expected {PROTOCOL_VERSION}")]
    UnsupportedVersion(u32),
    /// Envelope JSON is malformed or has unknown fields.
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(#[from] serde_json::Error),
    /// The `data` payload does not match the schema keyed by `type`.
    #[error("payload for `{event_type}` does not match its schema: {source}")]
    InvalidPayload {
        /// The declared canonical event type.
        event_type: EventType,
        /// The underlying schema validation error.
        #[source]
        source: serde_json::Error,
    },
}

/// Envelope for every message on both channels.
///
/// `ts` is unix **milliseconds** read from the (deliberately fake) system clock —
/// never use it for absolute correlation; correlate by `study`/`session`.
/// `seq` is monotonic per publisher connection so the Controller can detect loss.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

impl Envelope<Payload> {
    /// Deserialize and strictly validate a typed envelope: unknown fields are
    /// rejected, the version must match [`PROTOCOL_VERSION`], and the payload is
    /// validated against the schema registered for its `type`.
    ///
    /// # Errors
    /// [`ProtocolError`] describing exactly which layer rejected the message.
    pub fn from_value(value: serde_json::Value) -> Result<Self, ProtocolError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawEnvelope {
            v: u32,
            #[serde(rename = "type")]
            event_type: EventType,
            ts: i64,
            study: Uuid,
            session: u32,
            seq: u64,
            data: serde_json::Value,
        }

        let raw: RawEnvelope = serde_json::from_value(value)?;
        if raw.v != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(raw.v));
        }
        let data = Payload::from_raw(raw.event_type, raw.data).map_err(|source| {
            ProtocolError::InvalidPayload { event_type: raw.event_type, source }
        })?;
        Ok(Self {
            v: raw.v,
            event_type: raw.event_type,
            ts: raw.ts,
            study: raw.study,
            session: raw.session,
            seq: raw.seq,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::payload::ProcessStartedData;

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

    #[test]
    fn unknown_envelope_field_is_rejected() {
        let json = serde_json::json!({
            "v": 3,
            "type": "control.keepalive",
            "ts": 0,
            "study": "00000000-0000-0000-0000-000000000001",
            "session": 0,
            "seq": 0,
            "data": {},
            "extra": true,
        });

        assert!(
            Envelope::<Payload>::from_value(json)
                .is_err_and(|error| matches!(error, ProtocolError::InvalidEnvelope(_)))
        );
    }

    #[test]
    fn wrong_version_is_rejected() {
        let json = serde_json::json!({
            "v": 2,
            "type": "control.keepalive",
            "ts": 0,
            "study": "00000000-0000-0000-0000-000000000001",
            "session": 0,
            "seq": 0,
            "data": {},
        });

        assert!(matches!(
            Envelope::<Payload>::from_value(json),
            Err(ProtocolError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn payload_schema_mismatch_is_rejected() {
        let json = serde_json::json!({
            "v": 3,
            "type": "process.started",
            "ts": 0,
            "study": "00000000-0000-0000-0000-000000000001",
            "session": 0,
            "seq": 0,
            "data": {"unexpected": "shape"},
        });

        assert!(
            Envelope::<Payload>::from_value(json)
                .is_err_and(|error| matches!(error, ProtocolError::InvalidPayload { .. }))
        );
    }

    #[test]
    fn typed_envelope_serializes_payload_without_enum_tag() {
        let envelope = Envelope {
            v: PROTOCOL_VERSION,
            event_type: EventType::ProcessStarted,
            ts: 0,
            study: Uuid::from_u128(1),
            session: 4,
            seq: 1,
            data: Payload::ProcessStarted(ProcessStartedData {
                pid: 484,
                parent_pid: None,
                name: "evil.exe".to_owned(),
                image_path: None,
                command_line: None,
                os_session_id: None,
            }),
        };

        let json = serde_json::to_value(&envelope).unwrap();
        assert_eq!(json.get("type"), Some(&serde_json::json!("process.started")));
        assert_eq!(json.get("data"), Some(&serde_json::json!({"pid": 484, "name": "evil.exe"})));

        let back = Envelope::<Payload>::from_value(json).unwrap();
        assert_eq!(back, envelope);
    }
}
