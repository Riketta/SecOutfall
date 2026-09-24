//! NATS broker adapter — the production [`BrokerPort`].
//!
//! Publish-only (the agent never subscribes today). The client handles
//! reconnects internally; publish failures surface as
//! [`BrokerError::ConnectionLost`] and are counted for loss accounting.
//!
//! Startup retry budget is legacy parity (18 attempts × 5 s): the broker may
//! come up after the VM boots, and losing the `session.started` /
//! `agent.state` reports would blind the Controller for the whole study.
//!
//! Subjects are validated against the NATS token grammar at construction —
//! the config file is inside the VM and must be treated as hostile input
//! (a malformed subject must fail fast at boot, not corrupt the stream).

use std::{
    sync::{
        Arc,
        atomic::{
            AtomicU64,
            Ordering,
        },
    },
    time::Duration,
};

use async_trait::async_trait;
use protocol::{
    config::BrokerConfig,
    nats::{
        Envelope,
        Payload,
    },
};

use crate::ports::driven::broker::{
    BrokerError,
    BrokerPort,
    Channel,
};

/// Startup retry budget (legacy parity).
pub const CONNECT_ATTEMPTS: u32 = 18;
/// Delay between startup attempts (legacy parity).
pub const CONNECT_RETRY_DELAY: Duration = Duration::from_secs(5);

/// Connection failures after exhausting the retry budget.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// Every attempt failed; the last error is carried for diagnosis.
    #[error("NATS connect failed after {attempts} attempts: {last_error}")]
    RetriesExhausted {
        /// Total attempts made.
        attempts: u32,
        /// Text of the final underlying error.
        last_error: String,
    },
    /// A configured subject violates the NATS token grammar.
    #[error("invalid NATS subject `{subject}`: {detail}")]
    InvalidSubject {
        /// The offending configured subject.
        subject: String,
        /// What is wrong with it.
        detail: String,
    },
}

/// Validate one subject against the NATS token grammar (a conservative
/// subset: alphanumerics, `_`, `-`, and the wildcard tokens).
fn validate_subject(subject: &str) -> Result<(), ConnectError> {
    for token in subject.split('.') {
        if token.is_empty() {
            return Err(ConnectError::InvalidSubject {
                subject: subject.to_owned(),
                detail: "empty token".to_owned(),
            });
        }
        if !token.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '*' | '>')) {
            return Err(ConnectError::InvalidSubject {
                subject: subject.to_owned(),
                detail: format!("illegal character in token `{token}`"),
            });
        }
    }
    Ok(())
}

/// Production broker over `async-nats`.
pub struct NatsBrokerAdapter {
    client: async_nats::Client,
    control_subject: String,
    event_subject: String,
    loss: Arc<AtomicU64>,
}

impl NatsBrokerAdapter {
    /// Connect with the legacy startup retry budget.
    ///
    /// # Errors
    /// [`ConnectError`] after the budget is exhausted or a subject is invalid.
    pub async fn connect(config: &BrokerConfig) -> Result<Self, ConnectError> {
        Self::connect_with(config, CONNECT_ATTEMPTS, CONNECT_RETRY_DELAY).await
    }

    /// Connect with an explicit retry budget (tests and impatient dev modes).
    ///
    /// # Errors
    /// [`ConnectError`] after the budget is exhausted or a subject is invalid.
    pub async fn connect_with(
        config: &BrokerConfig,
        attempts: u32,
        delay: Duration,
    ) -> Result<Self, ConnectError> {
        validate_subject(&config.control_channel)?;
        validate_subject(&config.event_channel)?;

        let mut last_error = String::from("no attempts made");
        for attempt in 1..=attempts {
            match async_nats::connect(&config.uri).await {
                Ok(client) => {
                    return Ok(Self {
                        client,
                        control_subject: config.control_channel.clone(),
                        event_subject: config.event_channel.clone(),
                        loss: Arc::new(AtomicU64::new(0)),
                    });
                }
                Err(error) => {
                    tracing::warn!(
                        attempt,
                        attempts,
                        uri = %config.uri,
                        error = %error,
                        "NATS connect failed; retrying"
                    );
                    last_error = error.to_string();
                    tokio::time::sleep(delay).await;
                }
            }
        }
        Err(ConnectError::RetriesExhausted { attempts, last_error })
    }

    /// Wire messages dropped because the connection was down (diagnostics).
    #[must_use]
    pub fn loss_count(&self) -> u64 {
        self.loss.load(Ordering::Relaxed)
    }

    fn subject(&self, channel: Channel) -> &str {
        match channel {
            Channel::Control => &self.control_subject,
            Channel::Event => &self.event_subject,
        }
    }
}

#[async_trait]
impl BrokerPort for NatsBrokerAdapter {
    async fn publish(
        &self,
        channel: Channel,
        envelope: &Envelope<Payload>,
    ) -> Result<(), BrokerError> {
        let bytes = match serde_json::to_vec(envelope) {
            Ok(bytes) => bytes,
            Err(error) => {
                // Typed envelopes always serialize; reaching here is a bug.
                tracing::error!(%error, "envelope serialization failed");
                return Err(BrokerError::ConnectionLost);
            }
        };
        match self.client.publish(self.subject(channel).to_owned(), bytes.into()).await {
            Ok(()) => Ok(()),
            Err(error) => {
                self.loss.fetch_add(1, Ordering::Relaxed);
                tracing::error!(%error, channel = ?channel, "NATS publish failed");
                Err(BrokerError::ConnectionLost)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn subject_error(subject: &str) -> String {
        match validate_subject(subject) {
            Ok(()) => panic!("subject `{subject}` should be invalid"),
            Err(ConnectError::InvalidSubject { subject, detail }) => format!("{subject}: {detail}"),
            Err(ConnectError::RetriesExhausted { attempts, .. }) => {
                panic!("unexpected RetriesExhausted({attempts}) for subject validation")
            }
        }
    }

    #[test]
    fn subjects_follow_nats_token_grammar() {
        for subject in ["events", "secoutfall.events", "a-b_c1", "*.*", "events.>"] {
            validate_subject(subject).unwrap_or_else(|_| panic!("`{subject}` should be valid"));
        }
        assert!(subject_error("").contains("empty token"));
        assert!(subject_error("events..x").contains("empty token"));
        assert!(subject_error("events sp.ace").contains("illegal character"));
        assert!(subject_error("events\nnewline").contains("illegal character"));
    }

    /// Live roundtrip against a real broker (e.g. `devtools dummy-broker`);
    /// skipped unless `SECOUTFALL_TEST_NATS_URL` is set.
    #[tokio::test]
    async fn publish_roundtrip_against_live_broker() {
        use futures_util::StreamExt as _;

        let Ok(uri) = std::env::var("SECOUTFALL_TEST_NATS_URL") else {
            return;
        };
        let client = async_nats::connect(&uri).await.expect("connect");
        let subject = format!("secoutfall.test.{}", uuid::Uuid::new_v4());
        let mut subscriber = client.subscribe(subject.clone()).await.expect("subscribe");

        let adapter = NatsBrokerAdapter {
            client,
            control_subject: format!("{subject}.control"),
            event_subject: subject.clone(),
            loss: Arc::new(AtomicU64::new(0)),
        };
        let envelope = Envelope {
            v: protocol::nats::PROTOCOL_VERSION,
            event_type: protocol::events::EventType::ControlKeepalive,
            ts: 0,
            study: uuid::Uuid::nil(),
            session: 0,
            seq: 1,
            data: Payload::ControlKeepalive(protocol::payload::ControlKeepaliveData {}),
        };
        adapter.publish(Channel::Event, &envelope).await.expect("publish");

        let received = tokio::time::timeout(Duration::from_secs(5), subscriber.next())
            .await
            .expect("timed out waiting for message")
            .expect("subscription closed");
        assert_eq!(received.payload.to_vec(), serde_json::to_vec(&envelope).unwrap());
        assert_eq!(adapter.loss_count(), 0);
    }
}
