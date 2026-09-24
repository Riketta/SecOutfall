//! Console-printing broker — the wire output for standalone/local runs.
//!
//! Every published envelope is printed to stdout as one line, so a quick
//! run against a real target shows the full event stream without any broker
//! infrastructure. `control.keepalive` spam is suppressed (counted instead);
//! publishing never fails.

use std::sync::atomic::{
    AtomicU64,
    Ordering,
};

use async_trait::async_trait;
use protocol::{
    events::EventType,
    nats::{
        Envelope,
        Payload,
    },
};

use crate::ports::broker::{
    BrokerError,
    BrokerPort,
    Channel,
};

/// Console broker: prints each envelope (except suppressed keepalives) and
/// counts traffic. Publishing always succeeds — nothing downstream exists to
/// fail.
#[derive(Debug, Default)]
pub struct ConsoleBroker {
    /// Keepalives seen but not printed (they are the heartbeat noise).
    keepalives: AtomicU64,
    /// Total envelopes printed.
    printed: AtomicU64,
}

/// Should this event type be printed? Keepalives are the 15-second
/// heartbeat — they would drown the interesting traffic in a local run.
#[must_use]
fn should_print(event_type: EventType) -> bool {
    event_type != EventType::ControlKeepalive
}

/// Channel name for the log line.
fn label(channel: Channel) -> &'static str {
    match channel {
        Channel::Control => "control",
        Channel::Event => "events",
    }
}

impl ConsoleBroker {
    /// Keepalives suppressed so far.
    #[must_use]
    pub fn suppressed_keepalives(&self) -> u64 {
        self.keepalives.load(Ordering::Relaxed)
    }

    /// Envelopes printed so far.
    #[must_use]
    pub fn printed(&self) -> u64 {
        self.printed.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl BrokerPort for ConsoleBroker {
    async fn publish(
        &self,
        channel: Channel,
        envelope: &Envelope<Payload>,
    ) -> Result<(), BrokerError> {
        if !should_print(envelope.event_type) {
            self.keepalives.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        self.printed.fetch_add(1, Ordering::Relaxed);
        println!(
            "[{:>7}] #{seq} {event_type} session={session} study={study}",
            label(channel),
            seq = envelope.seq,
            event_type = envelope.event_type.as_str(),
            session = envelope.session,
            study = envelope.study.simple().to_string().get(..8).unwrap_or("????????").to_owned(),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn keepalives_are_suppressed_everything_else_prints() {
        assert!(!should_print(EventType::ControlKeepalive));
        for event_type in [
            EventType::ProcessStarted,
            EventType::SessionStarted,
            EventType::DropObserved,
            EventType::StudyShutdownRequested,
        ] {
            assert!(should_print(event_type), "{event_type:?} must print");
        }
    }

    #[tokio::test]
    async fn publish_counts_and_reports_keepalive_suppression() {
        use protocol::payload::{
            ControlKeepaliveData,
            ProcessStartedData,
        };

        let broker = ConsoleBroker::default();
        let keepalive = Envelope {
            v: 3,
            event_type: EventType::ControlKeepalive,
            ts: 0,
            study: uuid::Uuid::from_u128(1),
            session: 0,
            seq: 1,
            data: Payload::ControlKeepalive(ControlKeepaliveData {}),
        };
        let started = Envelope {
            v: 3,
            event_type: EventType::ProcessStarted,
            ts: 0,
            study: uuid::Uuid::from_u128(1),
            session: 0,
            seq: 2,
            data: Payload::ProcessStarted(ProcessStartedData {
                pid: 1,
                parent_pid: None,
                name: "x.exe".to_owned(),
                image_path: None,
                command_line: None,
                os_session_id: None,
            }),
        };

        broker.publish(Channel::Control, &keepalive).await.unwrap();
        broker.publish(Channel::Control, &keepalive).await.unwrap();
        broker.publish(Channel::Event, &started).await.unwrap();

        assert_eq!(broker.suppressed_keepalives(), 2);
        assert_eq!(broker.printed(), 1);
    }
}
