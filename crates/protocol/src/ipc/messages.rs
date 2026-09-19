//! JSON control messages and the binary screenshot payload of IPC v1.
//!
//! Control frames carry JSON-serialized structs from this module; the screenshot
//! frame payload is binary: `seq: u32 LE` followed by the raw JPEG bytes.

use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    config::UserActorConfig,
    ipc::FrameError,
};

/// Wire protocol version of the agent↔user-actor pipe.
pub const IPC_PROTOCOL_VERSION: u16 = 1;

/// Length of the screenshot sequence prefix inside a screenshot frame payload.
pub const SCREENSHOT_SEQ_LEN: usize = 4;

/// `HELLO` payload — client handshake (client → agent).
///
/// The `nonce` is the per-boot random value the agent passed to the user-actor at
/// launch; the agent rejects any `HELLO` whose nonce does not match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    /// Must equal [`IPC_PROTOCOL_VERSION`].
    pub protocol: u16,
    /// Per-boot shared secret, echoed back from the launch command line.
    pub nonce: String,
    /// User-actor build version, for the agent's logs and reports.
    pub module_version: String,
}

/// `WELCOME` payload — the config push (agent → client).
///
/// The user-actor reads no files: this is its entire runtime configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Welcome {
    /// Study-local session id (one boot-to-reboot interval).
    pub session_id: u32,
    /// Full runtime configuration for the user-actor.
    pub config: UserActorConfig,
}

/// `GET_CONFIG` payload — client config re-pull; the agent answers with `WELCOME`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetConfig {}

/// `ERROR` payload — either side reports an IPC-level failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorFrame {
    /// Human-readable error description.
    pub error: String,
}

/// Encode a `SCREENSHOT` frame payload: `seq: u32 LE` followed by raw JPEG bytes.
#[must_use]
pub fn encode_screenshot(seq: u32, jpeg: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(SCREENSHOT_SEQ_LEN + jpeg.len());
    payload.extend_from_slice(&seq.to_le_bytes());
    payload.extend_from_slice(jpeg);
    payload
}

/// Decode a `SCREENSHOT` frame payload into `(seq, jpeg_bytes)`.
///
/// # Errors
/// [`FrameError::MalformedScreenshot`] when the payload has no 4-byte sequence
/// prefix.
pub fn decode_screenshot(payload: &[u8]) -> Result<(u32, &[u8]), FrameError> {
    if payload.len() < SCREENSHOT_SEQ_LEN {
        return Err(FrameError::MalformedScreenshot(SCREENSHOT_SEQ_LEN, payload.len()));
    }
    let (seq_bytes, jpeg) = payload.split_at(SCREENSHOT_SEQ_LEN);
    let seq = u32::from_le_bytes(
        seq_bytes
            .try_into()
            .map_err(|_| FrameError::MalformedScreenshot(SCREENSHOT_SEQ_LEN, payload.len()))?,
    );
    Ok((seq, jpeg))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn hello_json_roundtrip() {
        let hello = Hello {
            protocol: IPC_PROTOCOL_VERSION,
            nonce: "d4f1a0b2c3e4f5a6b7c8d9e0f1a2b3c4".to_owned(),
            module_version: "0.1.0".to_owned(),
        };
        let json = serde_json::to_value(&hello).unwrap();
        assert_eq!(json.get("protocol"), Some(&serde_json::json!(1)));
        assert_eq!(serde_json::from_value::<Hello>(json).unwrap(), hello);
    }

    #[test]
    fn welcome_json_roundtrip() {
        let welcome = Welcome { session_id: 4, config: UserActorConfig::default() };
        let json = serde_json::to_value(&welcome).unwrap();
        assert_eq!(json.get("session_id"), Some(&serde_json::json!(4)));
        assert_eq!(serde_json::from_value::<Welcome>(json).unwrap(), welcome);
    }

    #[test]
    fn get_config_serializes_as_empty_object() {
        let json = serde_json::to_value(GetConfig {}).unwrap();
        assert_eq!(json, serde_json::json!({}));
        assert_eq!(serde_json::from_value::<GetConfig>(json).unwrap(), GetConfig {});
    }

    #[test]
    fn error_frame_json_roundtrip() {
        let frame = ErrorFrame { error: "handshake nonce mismatch".to_owned() };
        let json = serde_json::to_value(&frame).unwrap();
        assert_eq!(serde_json::from_value::<ErrorFrame>(json).unwrap(), frame);
    }

    #[test]
    fn screenshot_payload_roundtrip() {
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x1A, 0x02];
        let payload = encode_screenshot(7, &jpeg);
        let (seq, decoded) = decode_screenshot(&payload).unwrap();
        assert_eq!(seq, 7);
        assert_eq!(decoded, jpeg);
    }

    #[test]
    fn screenshot_without_seq_prefix_is_rejected() {
        assert_eq!(decode_screenshot(&[0x01, 0x02]), Err(FrameError::MalformedScreenshot(4, 2)));
    }
}
