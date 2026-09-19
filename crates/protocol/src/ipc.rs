//! Agent↔user-actor named-pipe frame schema (IPC v1).
//!
//! Wire format per frame: 8-byte little-endian [`FrameHeader`] followed by
//! `payload_len` bytes of payload (JSON for control messages, raw JPEG for
//! screenshots). Peers MUST reject frames exceeding [`MAX_PAYLOAD_LEN`] — never
//! allocate attacker-chosen sizes.

use serde::{
    Deserialize,
    Serialize,
};

/// Header size in bytes: `{payload_len: u32 LE, message_type: u16 LE, flags: u16 LE}`.
pub const HEADER_LEN: usize = 8;
/// Hard payload cap (16 MiB). Screenshot frames are the largest expected.
pub const MAX_PAYLOAD_LEN: usize = 16 * 1024 * 1024;

/// Frame message types (IPC v1).
pub mod message_type {
    /// Client handshake: `{protocol, nonce, module_version}`.
    pub const HELLO: u16 = 0x0001;
    /// Server answer to Hello: `{session_id, config}` — the config push.
    pub const WELCOME: u16 = 0x0002;
    /// Client config re-pull; the server answers with `WELCOME`.
    pub const GET_CONFIG: u16 = 0x0003;
    /// Client push: `{seq, jpeg}` — payload is the raw JPEG.
    pub const SCREENSHOT: u16 = 0x0010;
    /// Either side: `{"error": "..."}` text payload.
    pub const ERROR: u16 = 0x007F;

    /// Is this message type defined in IPC v1?
    #[must_use]
    pub const fn is_known(value: u16) -> bool {
        matches!(value, HELLO | WELCOME | GET_CONFIG | SCREENSHOT | ERROR)
    }
}

/// Frame header, 8 bytes little-endian on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameHeader {
    /// Payload length in bytes; MUST NOT exceed [`MAX_PAYLOAD_LEN`].
    pub payload_len: u32,
    /// One of [`message_type`].
    pub message_type: u16,
    /// Reserved; must be 0 in IPC v1.
    pub flags: u16,
}

/// Header parse/serialize errors.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// Fewer than [`HEADER_LEN`] bytes provided.
    #[error("header needs {HEADER_LEN} bytes, got {0}")]
    Truncated(usize),
    /// Payload length exceeds [`MAX_PAYLOAD_LEN`].
    #[error("payload length {0} exceeds {MAX_PAYLOAD_LEN}")]
    PayloadTooLong(u32),
    /// Unknown message type — IPC v1 is strict; forward compat is a version bump.
    #[error("unknown message type {0:#06x}")]
    UnknownType(u16),
}

impl FrameHeader {
    /// Encode to the 8-byte little-endian wire form.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; HEADER_LEN] {
        let [l0, l1, l2, l3] = self.payload_len.to_le_bytes();
        let [m0, m1] = self.message_type.to_le_bytes();
        let [f0, f1] = self.flags.to_le_bytes();
        [l0, l1, l2, l3, m0, m1, f0, f1]
    }

    /// Decode from the wire; validates the payload cap and known message types.
    ///
    /// # Errors
    /// - [`FrameError::Truncated`] when fewer than [`HEADER_LEN`] bytes are given.
    /// - [`FrameError::PayloadTooLong`] when `payload_len` exceeds the cap.
    /// - [`FrameError::UnknownType`] when `message_type` is not defined in IPC v1.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < HEADER_LEN {
            return Err(FrameError::Truncated(bytes.len()));
        }
        let (len_bytes, rest) = bytes.split_at(4);
        let (mt_bytes, fl_bytes) = rest.split_at(2);
        let payload_len = u32::from_le_bytes(
            len_bytes.try_into().map_err(|_| FrameError::Truncated(bytes.len()))?,
        );
        let message_type = u16::from_le_bytes(
            mt_bytes.try_into().map_err(|_| FrameError::Truncated(bytes.len()))?,
        );
        let flags = u16::from_le_bytes(
            fl_bytes.try_into().map_err(|_| FrameError::Truncated(bytes.len()))?,
        );

        if usize::try_from(payload_len).is_ok_and(|payload_len| payload_len > MAX_PAYLOAD_LEN) {
            return Err(FrameError::PayloadTooLong(payload_len));
        }
        if !message_type::is_known(message_type) {
            return Err(FrameError::UnknownType(message_type));
        }
        Ok(Self { payload_len, message_type, flags })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn header_wire_form_is_little_endian() {
        let header =
            FrameHeader { payload_len: 5, message_type: message_type::SCREENSHOT, flags: 0 };
        assert_eq!(header.to_bytes(), [0x05, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn header_roundtrips() {
        let header =
            FrameHeader { payload_len: 0x00AA_BBCC, message_type: message_type::WELCOME, flags: 0 };
        assert_eq!(FrameHeader::from_bytes(&header.to_bytes()), Ok(header));
    }

    #[test]
    fn truncated_header_is_rejected() {
        assert_eq!(FrameHeader::from_bytes(&[0x01, 0x02, 0x03]), Err(FrameError::Truncated(3)));
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let bytes =
            FrameHeader { payload_len: u32::MAX, message_type: message_type::HELLO, flags: 0 }
                .to_bytes();
        assert_eq!(FrameHeader::from_bytes(&bytes), Err(FrameError::PayloadTooLong(u32::MAX)));
    }

    #[test]
    fn unknown_message_type_is_rejected() {
        let bytes = FrameHeader { payload_len: 0, message_type: 0x9999, flags: 0 }.to_bytes();
        assert_eq!(FrameHeader::from_bytes(&bytes), Err(FrameError::UnknownType(0x9999)));
    }
}
