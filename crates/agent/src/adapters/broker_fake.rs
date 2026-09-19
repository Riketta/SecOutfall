//! Fake broker: captures published envelopes for assertions and prints nothing.
//! The real NATS adapter lands in phase 6.

use std::sync::Arc;

use parking_lot::Mutex;
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

/// In-memory broker. `Clone` shares the capture buffer (per-boot brokers may
/// share one buffer to assert cross-boot sequences).
/// Everything captured so far, in publish order.
type Capture = Arc<Mutex<Vec<(Channel, Envelope<Payload>)>>>;

/// In-memory broker. `Clone` shares the capture buffer (per-boot brokers may
/// share one buffer to assert cross-boot sequences).
#[derive(Debug, Clone, Default)]
pub struct FakeBroker {
    published: Capture,
}

impl FakeBroker {
    /// Snapshot of everything published, in order.
    #[must_use]
    pub fn published(&self) -> Vec<(Channel, Envelope<Payload>)> {
        self.published.lock().clone()
    }

    /// Envelopes published on one channel, in order.
    #[must_use]
    pub fn of_channel(&self, channel: Channel) -> Vec<Envelope<Payload>> {
        self.published
            .lock()
            .iter()
            .filter(|(published_channel, _)| *published_channel == channel)
            .map(|(_, envelope)| envelope.clone())
            .collect()
    }

    /// Event-type sequence of the event channel, in order.
    #[must_use]
    pub fn event_sequence(&self) -> Vec<EventType> {
        self.of_channel(Channel::Event).into_iter().map(|envelope| envelope.event_type).collect()
    }
}

#[async_trait::async_trait]
impl BrokerPort for FakeBroker {
    async fn publish(
        &self,
        channel: Channel,
        envelope: &Envelope<Payload>,
    ) -> Result<(), BrokerError> {
        self.published.lock().push((channel, envelope.clone()));
        Ok(())
    }
}
