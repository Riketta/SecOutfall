//! File upload port — drops and screenshots reach the Controller over HTTP.
//!
//! Wire shape (protocol v3): a multipart request with a `meta` part
//! (`application/json`, [`UploadMeta`]) and a `blob` part
//! (`application/octet-stream`). No auth — the lab network is trusted egress.
//!
//! Security posture: the blob is the analyzed malware's output, so it is
//! streamed, never buffered whole, and size-capped — a hostile drop must not
//! OOM the agent (root-cause fix for legacy bug: `drops_maxsize` parsed but
//! never enforced, whole file read into memory).

use std::path::PathBuf;

use async_trait::async_trait;
#[doc(inline)]
pub use protocol::upload::UploadMeta;

/// One file upload request.
#[derive(Debug, Clone)]
pub struct UploadRequest {
    /// Controller collector URL (e.g. `drops.upload_uri` / `screenshots.upload_uri`
    /// from config — the caller owns the endpoint selection).
    pub endpoint: String,
    /// Artifact metadata (wire `meta` part).
    pub meta: UploadMeta,
    /// Local file to stream as the `blob` part.
    pub file_path: PathBuf,
    /// Hard cap on accepted blob size, bytes; larger files are rejected
    /// without being read or sent.
    pub max_blob_bytes: u64,
}

/// Upload failures.
#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    /// The local artifact does not exist (already deleted, quarantined...).
    #[error("upload source missing: {0}")]
    NotFound(PathBuf),
    /// The blob exceeded the size cap — rejected before and during streaming
    /// (the file may grow between the pre-check and the transfer).
    #[error("upload rejected: blob exceeds cap {limit} bytes (read {read})")]
    TooLarge {
        /// Configured cap.
        limit: u64,
        /// Bytes read before the cap tripped.
        read: u64,
    },
    /// Local read failed mid-stream.
    #[error("upload read failed: {0}")]
    Io(#[from] std::io::Error),
    /// The transport failed; the Controller did not receive a complete blob.
    #[error("upload transport failed: {0}")]
    Transport(String),
}

/// Driven port: streams one local file to the Controller's collector endpoint.
#[async_trait]
pub trait FileUploadPort: Send + Sync + 'static {
    /// Upload one artifact. Implementations stream the blob and enforce
    /// [`UploadRequest::max_blob_bytes`].
    ///
    /// # Errors
    /// [`UploadError`] — see variants for the failure taxonomy.
    async fn upload(&self, request: UploadRequest) -> Result<(), UploadError>;
}
