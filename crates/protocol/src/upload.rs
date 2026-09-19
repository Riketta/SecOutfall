//! HTTP collector upload schemas (protocol v3).
//!
//! Uploads are multipart requests with exactly two parts:
//! - `meta` — `application/json`, serialized [`UploadMeta`].
//! - `blob` — `application/octet-stream`, the artifact bytes.
//!
//! `path` is a wire pseudo-name minted by the publisher (e.g.
//! `screenshot-{session}-{seq}.jpeg`); local filesystem paths never cross the
//! wire — the Controller must not learn the VM's directory layout.

use serde::{
    Deserialize,
    Serialize,
};
use uuid::Uuid;

/// `meta` multipart part: identifying metadata for one uploaded artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadMeta {
    /// Artifact pseudo-name (see module docs).
    pub path: String,
    /// Study id.
    pub study: Uuid,
    /// Session id.
    pub session: u32,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn serializes_exactly_three_fields() {
        let meta = UploadMeta {
            path: "screenshot-2-7.jpeg".to_owned(),
            study: Uuid::from_u128(0xA),
            session: 2,
        };
        let raw = serde_json::to_value(&meta).unwrap();
        assert_eq!(
            raw,
            serde_json::json!({
                "path": "screenshot-2-7.jpeg",
                "study": "00000000-0000-0000-0000-00000000000a",
                "session": 2,
            })
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let raw = serde_json::json!({
            "path": "x.txt",
            "study": "00000000-0000-0000-0000-00000000000a",
            "session": 1,
            "local_path": "C:\\Windows\\evil.txt",
        });
        assert!(serde_json::from_value::<UploadMeta>(raw).is_err());
    }
}
