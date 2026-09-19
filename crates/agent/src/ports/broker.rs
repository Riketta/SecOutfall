//! Broker publish port — the agent's only channel to the Controller.

use async_trait::async_trait;
use protocol::nats::{
    Envelope,
    Payload,
};

/// Which NATS subject an envelope belongs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// Control subject: keepalive/reboot/shutdown lifecycle.
    Control,
    /// Event subject: reports and sandbox events.
    Event,
}

/// Publish failures. Adapters map transport errors onto this.
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// Connection to the broker is down (message NOT delivered).
    #[error("broker connection is down")]
    ConnectionLost,
}

/// Driven port: publishes typed v3 envelopes. Implementations must serialize
/// and send without altering the envelope.
#[async_trait]
pub trait BrokerPort: Send + Sync + 'static {
    /// Publish one envelope; returns after hand-off to the transport.
    ///
    /// # Errors
    /// [`BrokerError::ConnectionLost`] when the message could not be delivered.
    async fn publish(
        &self,
        channel: Channel,
        envelope: &Envelope<Payload>,
    ) -> Result<(), BrokerError>;
}
