//! Shared envelope composition helpers for plugins that publish to the wire.

use std::sync::atomic::{
    AtomicU64,
    Ordering,
};

use protocol::{
    events::EventType,
    nats::{
        Envelope,
        PROTOCOL_VERSION,
        Payload,
    },
};

use crate::app::event::SourceEvent;

/// Monotonic sequence number for one boot's wire output (Controller-side loss
/// detection). Shared by every publisher in the process.
pub fn next_seq(seq: &AtomicU64) -> u64 {
    seq.fetch_add(1, Ordering::SeqCst)
}

/// Compose an envelope from a source event (wire type and payload derived 1:1).
#[must_use]
pub fn envelope_from_source(
    now_ms: i64,
    seq: u64,
    study_id: uuid::Uuid,
    session_id: u32,
    source: &SourceEvent,
) -> Envelope<Payload> {
    Envelope {
        v: PROTOCOL_VERSION,
        event_type: source.event_type(),
        ts: now_ms,
        study: study_id,
        session: session_id,
        seq,
        data: source.clone().into_payload(),
    }
}

/// Compose an envelope from an explicit event type + payload.
#[must_use]
pub fn envelope_raw(
    now_ms: i64,
    seq: u64,
    study_id: uuid::Uuid,
    session_id: u32,
    event_type: EventType,
    data: Payload,
) -> Envelope<Payload> {
    Envelope {
        v: PROTOCOL_VERSION,
        event_type,
        ts: now_ms,
        study: study_id,
        session: session_id,
        seq,
        data,
    }
}
