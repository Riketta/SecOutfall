//! HTTP multipart uploader — the production [`FileUploadPort`] (reqwest).
//!
//! Contract honored (protocol v3): `meta` part (`application/json`) + `blob`
//! part (`application/octet-stream`), streamed and size-capped. The blob is
//! never buffered whole: chunks flow from `tokio::fs::File` through a
//! counting stream straight into the request body, so a multi-gigabyte
//! hostile drop costs 64 KiB of RAM, not the file size.
//!
//! The cap is enforced twice, because the analyzed malware is an adversarial
//! user:
//! 1. pre-flight — `metadata().len()` over the cap is rejected before any
//!    bytes move;
//! 2. in-stream — a file that grows (or lies about its size) between the
//!    pre-check and the transfer trips the cap mid-stream and aborts the
//!    request with [`UploadError::TooLarge`].

use std::{
    pin::Pin,
    sync::Arc,
    task::{
        Context,
        Poll,
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use futures_core::Stream;
use parking_lot::Mutex;
use tokio::fs::File;
use tokio_util::io::ReaderStream;

use crate::ports::uploader::{
    FileUploadPort,
    UploadError,
    UploadRequest,
};

/// Upload chunk size fed into the request body.
const CHUNK_BYTES: usize = 64 * 1024;
/// Connect timeout; no total timeout — large drops may legitimately take a
/// while on slow lab links and aborting mid-transfer would corrupt artifacts.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Streaming uploader over a shared reqwest client.
pub struct HttpUploadAdapter {
    client: reqwest::Client,
}

impl HttpUploadAdapter {
    /// Build the adapter.
    ///
    /// # Errors
    /// [`UploadError::Transport`] if the HTTP client cannot be constructed
    /// (TLS backend init failure).
    pub fn new() -> Result<Self, UploadError> {
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|error| UploadError::Transport(error.to_string()))?;
        Ok(Self { client })
    }
}

/// Cap-enforcing wrapper over a file reader stream.
///
/// Counts every chunk handed to the transport; once the total exceeds the
/// cap it yields an error, records [`UploadError::TooLarge`] in the shared
/// slot, and the in-flight request aborts. The slot lets `upload` return the
/// precise cap error instead of a generic transport failure.
struct CappedStream {
    inner: ReaderStream<File>,
    limit: u64,
    total_read: u64,
    overflow: Arc<Mutex<Option<UploadError>>>,
}

impl Stream for CappedStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                this.total_read += u64::try_from(chunk.len()).unwrap_or(u64::MAX);
                if this.total_read > this.limit {
                    *this.overflow.lock() =
                        Some(UploadError::TooLarge { limit: this.limit, read: this.total_read });
                    Poll::Ready(Some(Err(std::io::Error::other("blob exceeds upload cap"))))
                } else {
                    Poll::Ready(Some(Ok(chunk)))
                }
            }
            other => other,
        }
    }
}

#[async_trait]
impl FileUploadPort for HttpUploadAdapter {
    async fn upload(&self, request: UploadRequest) -> Result<(), UploadError> {
        let UploadRequest { endpoint, meta, file_path, max_blob_bytes } = request;

        let file = match File::open(&file_path).await {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(UploadError::NotFound(file_path));
            }
            Err(error) => return Err(UploadError::Io(error)),
        };

        // Pre-flight cap (files may lie later; the in-stream cap catches that).
        let preflight_len = file.metadata().await?.len();
        if preflight_len > max_blob_bytes {
            return Err(UploadError::TooLarge { limit: max_blob_bytes, read: preflight_len });
        }

        let overflow: Arc<Mutex<Option<UploadError>>> = Arc::new(Mutex::new(None));
        let stream = CappedStream {
            inner: ReaderStream::with_capacity(file, CHUNK_BYTES),
            limit: max_blob_bytes,
            total_read: 0,
            overflow: Arc::clone(&overflow),
        };

        let meta_json = serde_json::to_string(&meta)
            .map_err(|error| UploadError::Transport(error.to_string()))?;

        let form = reqwest::multipart::Form::new()
            .part(
                "meta",
                reqwest::multipart::Part::text(meta_json)
                    .mime_str("application/json")
                    .map_err(|error| UploadError::Transport(error.to_string()))?,
            )
            .part(
                "blob",
                reqwest::multipart::Part::stream(reqwest::Body::wrap_stream(stream))
                    .file_name(meta.path)
                    .mime_str("application/octet-stream")
                    .map_err(|error| UploadError::Transport(error.to_string()))?,
            );

        match self.client.post(endpoint).multipart(form).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(())
                } else {
                    Err(UploadError::Transport(format!(
                        "controller rejected upload: {}",
                        response.status()
                    )))
                }
            }
            Err(error) => {
                // Prefer the precise cap error over the aborted-request noise.
                if let Some(overflowed) = overflow.lock().take() {
                    return Err(overflowed);
                }
                Err(UploadError::Transport(error.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::{
        future::poll_fn,
        path::PathBuf,
        pin::pin,
        sync::Arc,
    };

    use axum::{
        Router,
        extract::{
            Multipart,
            State,
        },
        routing::post,
    };
    use protocol::upload::UploadMeta;
    use tokio::{
        io::AsyncWriteExt,
        net::TcpListener,
        sync::mpsc,
    };
    use uuid::Uuid;

    use super::*;

    const STUDY: Uuid = Uuid::from_u128(0xBEEF);

    type CapturedParts = Vec<(String, Vec<u8>, String)>;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("secoutfall-upload-{}-{name}", std::process::id()))
    }

    /// Capture `(part name, bytes, content type)` triples for one request.
    async fn collect_parts(
        State(parts_tx): State<mpsc::Sender<CapturedParts>>,
        mut multipart: Multipart,
    ) {
        let mut parts = Vec::new();
        while let Some(field) = multipart.next_field().await.unwrap() {
            let name = field.name().unwrap_or("").to_owned();
            let content_type = field.content_type().unwrap_or("").to_owned();
            let bytes = field.bytes().await.unwrap().to_vec();
            parts.push((name, bytes, content_type));
        }
        let _ = parts_tx.send(parts).await;
    }

    /// Collector harness: boots an axum server capturing one request's parts,
    /// returns the endpoint URL plus the capture receiver.
    async fn spawn_collector() -> (String, mpsc::Receiver<CapturedParts>) {
        let (parts_tx, parts_rx) = mpsc::channel(4);
        let app = Router::new().route("/collect", post(collect_parts)).with_state(parts_tx);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/collect"), parts_rx)
    }

    async fn write_temp(name: &str, contents: &[u8]) -> PathBuf {
        let path = temp_path(name);
        let mut file = File::create(&path).await.unwrap();
        file.write_all(contents).await.unwrap();
        file.flush().await.unwrap();
        path
    }

    fn sample_request(endpoint: &str, file_path: PathBuf, max: u64) -> UploadRequest {
        UploadRequest {
            endpoint: endpoint.to_owned(),
            meta: UploadMeta { path: "3-42-ab12cd34.txt".to_owned(), study: STUDY, session: 3 },
            file_path,
            max_blob_bytes: max,
        }
    }

    #[tokio::test]
    async fn uploads_meta_and_blob_parts() {
        let (endpoint, mut parts_rx) = spawn_collector().await;
        let contents: Vec<u8> = (0..=255u8).cycle().take(300_000).collect();
        let path = write_temp("ok.bin", &contents).await;
        let adapter = HttpUploadAdapter::new().unwrap();

        adapter
            .upload(sample_request(&endpoint, path.clone(), 1024 * 1024))
            .await
            .expect("upload should succeed");

        let parts = parts_rx.recv().await.unwrap();
        assert_eq!(parts.len(), 2);

        let (name, bytes, content_type) = parts.first().expect("meta part");
        assert_eq!(name, "meta");
        assert_eq!(content_type, "application/json");
        let meta: UploadMeta = serde_json::from_slice(bytes).unwrap();
        assert_eq!(meta.path, "3-42-ab12cd34.txt");
        assert_eq!(meta.study, STUDY);
        assert_eq!(meta.session, 3);

        let (name, bytes, content_type) = parts.get(1).expect("blob part");
        assert_eq!(name, "blob");
        assert_eq!(content_type, "application/octet-stream");
        assert_eq!(bytes, &contents);

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn oversized_file_is_rejected_preflight() {
        let (endpoint, _parts_rx) = spawn_collector().await;
        let path = write_temp("big.bin", &vec![0u8; 64 * 1024]).await;
        let adapter = HttpUploadAdapter::new().unwrap();

        let error = adapter
            .upload(sample_request(&endpoint, path.clone(), 1024))
            .await
            .expect_err("upload over cap must fail");
        assert!(matches!(error, UploadError::TooLarge { limit: 1024, read: 65_536 }));

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn missing_file_maps_to_not_found() {
        let (endpoint, _parts_rx) = spawn_collector().await;
        let adapter = HttpUploadAdapter::new().unwrap();

        let error = adapter
            .upload(sample_request(&endpoint, temp_path("nope.bin"), 1024))
            .await
            .expect_err("missing file must fail");
        assert!(matches!(error, UploadError::NotFound(_)));
    }

    #[tokio::test]
    async fn capped_stream_trips_mid_stream_on_growth() {
        // 4 KiB file, cap 1 KiB: the pre-flight uses `limit` 16 KiB (passes),
        // but the stream itself is capped at 1 KiB — simulating a file that
        // grows (or lies) between pre-check and transfer.
        let contents = vec![7u8; 4 * 1024];
        let path = write_temp("grow.bin", &contents).await;
        let file = File::open(&path).await.unwrap();
        let overflow: Arc<Mutex<Option<UploadError>>> = Arc::new(Mutex::new(None));
        let mut stream = pin!(CappedStream {
            inner: ReaderStream::with_capacity(file, 512),
            limit: 1024,
            total_read: 0,
            overflow: Arc::clone(&overflow),
        });

        let mut delivered = 0_u64;
        loop {
            match poll_fn(|cx| stream.as_mut().poll_next(cx)).await {
                Some(Ok(chunk)) => delivered += u64::try_from(chunk.len()).unwrap(),
                Some(Err(_)) => break,
                None => panic!("stream must end with the cap error, not clean EOF"),
            }
        }
        assert!(delivered <= 1024, "cap must bound delivered bytes, got {delivered}");
        let recorded = overflow.lock().take();
        assert!(matches!(recorded, Some(UploadError::TooLarge { limit: 1024, .. })));
        let _ = std::fs::remove_file(path);
    }
}
