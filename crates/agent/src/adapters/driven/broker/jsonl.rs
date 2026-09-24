//! JSONL event log — a standalone/local-run event database: one wire
//! envelope per line (`events.jsonl`), append-ordered, trivially inspectable
//! with `jq` or `tail -f`.
//!
//! Dev-grade by design (the `local` mode is a sneak-peek harness, not a
//! hardened component): each line is the exact wire JSON the Controller would
//! receive, written with a buffered writer and flushed on drop; write
//! failures surface as typed [`BrokerError`]s and are logged by callers.

use std::{
    io::{
        BufWriter,
        Write,
    },
    path::PathBuf,
};

use async_trait::async_trait;
use parking_lot::Mutex;
use protocol::nats::{
    Envelope,
    Payload,
};

use crate::ports::driven::broker::{
    BrokerError,
    BrokerPort,
    Channel,
};

/// Append-only JSONL sink. One file per run (created/truncated at open).
pub struct JsonlBroker {
    writer: Mutex<BufWriter<std::fs::File>>,
}

impl JsonlBroker {
    /// Create (or truncate) the JSONL log at `path`.
    ///
    /// # Errors
    /// [`std::io::Error`] when the file cannot be opened.
    pub fn create(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let file = std::fs::File::create(path.into())?;
        Ok(Self { writer: Mutex::new(BufWriter::new(file)) })
    }
}

impl Drop for JsonlBroker {
    fn drop(&mut self) {
        // The buffer outlives the run; flush the tail so the file is complete.
        let _ = self.writer.get_mut().flush();
    }
}

#[async_trait]
impl BrokerPort for JsonlBroker {
    async fn publish(
        &self,
        _channel: Channel,
        envelope: &Envelope<Payload>,
    ) -> Result<(), BrokerError> {
        let mut line = serde_json::to_string(envelope)
            .map_err(|error| BrokerError::Persistence(error.to_string()))?;
        line.push('\n');
        let mut writer = self.writer.lock();
        writer
            .write_all(line.as_bytes())
            .and_then(|()| writer.flush())
            .map_err(|error| BrokerError::Persistence(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use protocol::{
        events::EventType,
        payload::ProcessStartedData,
    };

    use super::*;

    fn sample(seq: u64, pid: u32) -> Envelope<Payload> {
        Envelope {
            v: 3,
            event_type: EventType::ProcessStarted,
            ts: 1_000,
            study: uuid::Uuid::from_u128(7),
            session: 0,
            seq,
            data: Payload::ProcessStarted(ProcessStartedData {
                pid,
                parent_pid: None,
                name: "evil.exe".to_owned(),
                image_path: None,
                command_line: None,
                os_session_id: Some(1),
            }),
        }
    }

    #[tokio::test]
    async fn every_published_envelope_lands_as_one_json_line() {
        let path = std::env::temp_dir().join(format!(
            "secoutfall-jsonl-{}-{}.jsonl",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));

        {
            let broker = JsonlBroker::create(&path).unwrap();
            broker.publish(Channel::Event, &sample(1, 10)).await.unwrap();
            broker.publish(Channel::Event, &sample(2, 11)).await.unwrap();
            // Drop flushes the buffered tail.
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "one line per envelope: {content:?}");

        for (line, seq) in lines.iter().zip([1_u64, 2]) {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(value.get("v").and_then(serde_json::Value::as_u64), Some(3));
            assert_eq!(
                value.get("type").and_then(serde_json::Value::as_str),
                Some("process.started")
            );
            assert_eq!(value.get("seq").and_then(serde_json::Value::as_u64), Some(seq));
            // The payload is serialized without the enum tag: the data object
            // is exactly what the Controller would receive.
            let data = value.get("data").expect("payload object present");
            assert!(
                data.get("pid").and_then(serde_json::Value::as_u64).is_some(),
                "payload inline: {line}"
            );
            assert!(data.get("ProcessStarted").is_none());
        }
        let _ = std::fs::remove_file(&path);
    }
}
