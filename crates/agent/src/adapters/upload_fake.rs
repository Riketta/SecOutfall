//! Fake uploader: records upload requests for assertions and simulates the
//! Controller collector. Reads the source file only for its size (like the
//! real transport's pre-flight), never copies content.

use std::sync::atomic::{
    AtomicBool,
    Ordering,
};

use parking_lot::Mutex;

use crate::ports::uploader::{
    FileUploadPort,
    UploadError,
    UploadMeta,
    UploadRequest,
};

/// One recorded upload request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedUpload {
    /// The endpoint the request went to.
    pub endpoint: String,
    /// The wire metadata.
    pub meta: UploadMeta,
    /// Source file size (bytes) as the pre-flight saw it.
    pub size_bytes: u64,
}

/// Records every upload. `fail(true)` flips it into a failing collector.
#[derive(Debug, Default)]
pub struct FakeUploader {
    uploads: Mutex<Vec<RecordedUpload>>,
    fail: AtomicBool,
}

impl FakeUploader {
    /// All recorded uploads, in order.
    #[must_use]
    pub fn uploads(&self) -> Vec<RecordedUpload> {
        self.uploads.lock().clone()
    }

    /// Make subsequent uploads fail with [`UploadError::Transport`].
    pub fn fail(&self, fail: bool) {
        self.fail.store(fail, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl FileUploadPort for FakeUploader {
    async fn upload(&self, request: UploadRequest) -> Result<(), UploadError> {
        let size = tokio::fs::metadata(&request.file_path).await.map_or(0, |meta| meta.len());
        if self.fail.load(Ordering::SeqCst) {
            return Err(UploadError::Transport("forced failure".to_owned()));
        }
        self.uploads.lock().push(RecordedUpload {
            endpoint: request.endpoint,
            meta: request.meta,
            size_bytes: size,
        });
        Ok(())
    }
}
