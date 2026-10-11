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
    /// A local persistence sink (e.g. the JSONL event log) failed to store
    /// the envelope.
    #[error("event persistence failed: {0}")]
    Persistence(String),
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

    /// Drain transport buffers: when this resolves, everything published so
    /// far has left the process (or failed loudly). The runtime awaits it
    /// once after finalize, before exit — the review found the final
    /// `session.ended`/reboot request sitting in the client's send queue
    /// while the process tore down. Adapters with synchronous hand-off
    /// (console, tee, fake) inherit the no-op.
    ///
    /// # Errors
    /// [`BrokerError::ConnectionLost`] when the drain fails.
    async fn flush(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}
