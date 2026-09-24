//! Tee broker — fans one publish out to several sinks (e.g. the console
//! printer AND the JSONL event log in `local` mode). Sink failures are
//! logged and never mask the other sinks: the publish itself reports `Ok`
//! unless every sink failed.

use std::sync::Arc;

use async_trait::async_trait;
use protocol::nats::{
    Envelope,
    Payload,
};

use crate::ports::broker::{
    BrokerError,
    BrokerPort,
    Channel,
};

/// Fan-out broker over ordered sinks.
pub struct TeeBroker {
    sinks: Vec<Arc<dyn BrokerPort>>,
}

impl TeeBroker {
    /// Fan out to `sinks`, in order.
    #[must_use]
    pub fn new(sinks: Vec<Arc<dyn BrokerPort>>) -> Self {
        Self { sinks }
    }
}

#[async_trait]
impl BrokerPort for TeeBroker {
    async fn publish(
        &self,
        channel: Channel,
        envelope: &Envelope<Payload>,
    ) -> Result<(), BrokerError> {
        let mut failures = 0_usize;
        for sink in &self.sinks {
            if let Err(error) = sink.publish(channel, envelope).await {
                failures += 1;
                tracing::warn!(%error, event_type = %envelope.event_type, "tee sink failed");
            }
        }
        // A sink that cannot store/print is a dev-harness annoyance, not a
        // lost message: report failure only when nothing accepted the event.
        if failures == self.sinks.len() {
            return Err(BrokerError::Persistence("all tee sinks failed".to_owned()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::adapters::broker_fake::FakeBroker;

    #[tokio::test]
    async fn every_sink_receives_every_envelope() {
        let left = Arc::new(FakeBroker::default());
        let right = Arc::new(FakeBroker::default());
        let tee = TeeBroker::new(vec![left.clone(), right.clone()]);

        tee.publish(
            Channel::Event,
            &crate::plugins::wire::envelope_raw(
                0,
                1,
                uuid::Uuid::from_u128(1),
                0,
                protocol::events::EventType::SessionStarted,
                protocol::payload::Payload::SessionStarted(protocol::payload::SessionStartedData {
                    scheduled_duration_secs: Some(3),
                }),
            ),
        )
        .await
        .unwrap();

        assert_eq!(left.event_sequence().len(), 1);
        assert_eq!(right.event_sequence().len(), 1);
    }
}
