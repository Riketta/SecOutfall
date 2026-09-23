//! `drops-collector` — copies matching dropped files out of harm's way and
//! uploads them to the Controller.
//!
//! Bus-only plugin: the `scope-tracker` publishes `DropObserved` /
//! `DropClosed`; the collector acts on closes (the file is handle-free then —
//! root-cause fix for legacy bug #5, which copied on both write AND close and
//! raced the still-open file).
//!
//! Fixes vs legacy, in one place:
//! - de-dup by **content hash** (SHA-256 prefix), not file length (bug #2);
//! - `drops.max_size` enforced twice — pre-flight and during the copy, because
//!   the file can grow between stat and read (bug #3);
//! - copy runs on a bounded job queue (never blocks the pipeline, never OOM;
//!   overflow drops and counts).
//!
//! The copy name is generated (`{session}-{seq}-{hash8}.{ext}`) with the
//! malware-chosen extension sanitized ([`crate::domain::drop_copy`]) — hostile
//! names cannot mint alternate data streams or reserved devices in the drops
//! directory.

use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{
            AtomicU32,
            AtomicU64,
            Ordering,
        },
    },
};

use async_trait::async_trait;
use kernel::{
    app::plugin_ports::{
        event_bus_port::EventBusPort as _,
        plugin_port::PluginPort,
    },
    bus::InMemoryEventBus,
};
use parking_lot::Mutex;
use protocol::{
    config::DropsConfig,
    events::EventType,
    nats::Envelope,
    payload::{
        DropCopiedData,
        DropUploadedData,
        Payload,
    },
};
use sha2::{
    Digest,
    Sha256,
};
use tokio::io::{
    AsyncReadExt,
    AsyncWriteExt,
};
use tokio_util::sync::CancellationToken;

use crate::{
    app::{
        event::AgentBusEvent,
        worker::{
            JobQueue,
            SubmitHandle,
        },
    },
    domain::{
        drop_copy,
        scope::SharedScopeState,
    },
    plugins::wire,
    ports::{
        broker::{
            BrokerPort,
            Channel,
        },
        clock::SystemClockPort,
        uploader::{
            FileUploadPort,
            UploadMeta,
            UploadRequest,
        },
    },
};

/// Copy chunk size while streaming a drop out of the VM filesystem.
const COPY_CHUNK_BYTES: usize = 64 * 1024;
/// Collection queue capacity: the `limit_per_session` budget dwarfs this.
const QUEUE_CAPACITY: usize = 256;

/// Constructor dependencies.
pub struct DropsCollectorDeps {
    /// Shared scope state (study/session identity on the wire).
    pub state: SharedScopeState,
    /// Drop collection policy.
    pub config: Arc<DropsConfig>,
    /// Controller upload transport.
    pub uploader: Arc<dyn FileUploadPort>,
    /// Wire output.
    pub broker: Arc<dyn BrokerPort>,
    /// Time source.
    pub clock: Arc<dyn SystemClockPort>,
    /// Shared per-boot wire sequence counter.
    pub seq: Arc<AtomicU64>,
    /// Derived-event bus.
    pub bus: InMemoryEventBus<AgentBusEvent>,
}

/// Shared collection state (owned by the worker and the plugin alike).
struct Inner {
    deps: DropsCollectorDeps,
    /// Content hashes already collected this boot (dedup across sessions too —
    /// strictly stronger than legacy's per-session length dedup).
    seen_hashes: Mutex<BTreeSet<String>>,
    /// Drops collected this session (vs `limit_per_session`).
    collected: AtomicU32,
    /// Per-boot copy-name sequence.
    name_seq: AtomicU64,
}

/// Drop collection plugin (bus-only).
pub struct DropsCollectorPlugin {
    inner: Arc<Inner>,
    workers: Mutex<Option<OwnedWorkers>>,
}

impl DropsCollectorPlugin {
    /// Assemble the plugin.
    #[must_use]
    pub fn new(deps: DropsCollectorDeps) -> Self {
        Self {
            inner: Arc::new(Inner {
                deps,
                seen_hashes: Mutex::new(BTreeSet::new()),
                collected: AtomicU32::new(0),
                name_seq: AtomicU64::new(0),
            }),
            workers: Mutex::new(None),
        }
    }

    /// The copy-and-upload job, run off the pipeline by the worker.
    async fn collect_drop(inner: &Inner, source: String) {
        // Cheap gate only: the counter increments AFTER a successful copy (see
        // below), so vanished, over-cap, failed and duplicate drops never burn
        // a `limit_per_session` slot (legacy: malware writing+deleting `limit`
        // temp files disabled collection for the whole session). Race-free by
        // construction — the collection job queue is single-consumer, so jobs
        // run one at a time and check-then-increment cannot interleave.
        if inner.collected.load(Ordering::SeqCst) >= inner.deps.config.limit_per_session {
            tracing::warn!(
                limit = inner.deps.config.limit_per_session,
                %source,
                "drop limit reached; not collected"
            );
            return;
        }

        let (study_id, session_id) = {
            let state = inner.deps.state.lock();
            let session_id = state.current_session().map_or(0, |session| session.id);
            (state.study_id, session_id)
        };

        // Pre-flight size check (the file may still grow; the copy caps too).
        let size = match tokio::fs::metadata(&source).await {
            Ok(meta) => meta.len(),
            Err(error) => {
                // Malware deletes drops as fast as it writes them — a debug
                // line, not an error.
                tracing::debug!(%error, %source, "drop vanished before collection");
                return;
            }
        };
        if size > inner.deps.config.max_size {
            tracing::info!(size, limit = inner.deps.config.max_size, %source, "drop over cap");
            return;
        }

        let Some((copy_name, copied_bytes)) = persist_copy(inner, &source, session_id).await else {
            return;
        };
        // Counted only now: the copy is durable on the drops volume, so the
        // session budget is spent on real collections, not failed attempts.
        inner.collected.fetch_add(1, Ordering::SeqCst);
        report_and_upload(inner, &source, &copy_name, copied_bytes, study_id, session_id).await;
    }
}

/// Copy the source out (capped), dedup by content, finalize the copy name.
/// Returns `(copy_name, size_bytes)` on success; failures are logged here.
async fn persist_copy(inner: &Inner, source: &str, session_id: u32) -> Option<(String, u64)> {
    let seq = inner.name_seq.fetch_add(1, Ordering::SeqCst);
    let drops_dir = PathBuf::from(&inner.deps.config.path);
    if let Err(error) = tokio::fs::create_dir_all(&drops_dir).await {
        tracing::error!(%error, dir = %drops_dir.display(), "drops directory unavailable");
        return None;
    }
    let part_path = drops_dir.join(format!("{session_id}-{seq}.part"));

    let digest = match copy_capped(source, &part_path, inner.deps.config.max_size).await {
        Ok(digest) => digest,
        Err(error) => {
            tracing::warn!(%error, %source, "drop copy aborted");
            let _ = tokio::fs::remove_file(&part_path).await;
            return None;
        }
    };

    let hash8 = drop_copy::hash8(&digest);
    // Single-consumer invariant (one collection worker): contains-then-insert
    // here cannot race. The hash is inserted only AFTER a successful rename —
    // a failed finalize must not burn it, or an identical later drop would be
    // silently treated as a duplicate forever.
    if inner.seen_hashes.lock().contains(&hash8) {
        // Same content as an already-collected drop — drop the part.
        let _ = tokio::fs::remove_file(&part_path).await;
        return None;
    }
    let extension = std::path::Path::new(source)
        .extension()
        .map(|ext| ext.to_string_lossy().to_string())
        .unwrap_or_default();
    let copy_name = drop_copy::copy_file_name(
        session_id,
        seq,
        &hash8,
        &drop_copy::sanitize_extension(&extension),
    );
    let copy_path = drops_dir.join(&copy_name);
    if let Err(error) = tokio::fs::rename(&part_path, &copy_path).await {
        tracing::error!(%error, from = %part_path.display(), "drop rename failed");
        // Same cleanup as a failed copy: no `.part` litter, no burned hash.
        let _ = tokio::fs::remove_file(&part_path).await;
        return None;
    }
    inner.seen_hashes.lock().insert(hash8);
    let copied_bytes = tokio::fs::metadata(&copy_path).await.map_or(0, |meta| meta.len());
    Some((copy_name, copied_bytes))
}

/// `drop.copied` wire event, then the upload + `drop.uploaded` when an
/// endpoint is configured.
async fn report_and_upload(
    inner: &Inner,
    source: &str,
    copy_name: &str,
    copied_bytes: u64,
    study_id: uuid::Uuid,
    session_id: u32,
) {
    let copied = wire::envelope_raw(
        inner.deps.clock.now_ms(),
        wire::next_seq(&inner.deps.seq),
        study_id,
        session_id,
        EventType::DropCopied,
        Payload::DropCopied(DropCopiedData {
            source: source.to_owned(),
            copy: copy_name.to_owned(),
            size_bytes: copied_bytes,
        }),
    );
    publish(&inner.deps.broker, copied).await;

    let Some(endpoint) = inner.deps.config.upload_uri.clone() else {
        return;
    };
    let request = UploadRequest {
        endpoint,
        meta: UploadMeta { path: copy_name.to_owned(), study: study_id, session: session_id },
        file_path: PathBuf::from(&inner.deps.config.path).join(copy_name),
        max_blob_bytes: inner.deps.config.max_size,
    };
    match inner.deps.uploader.upload(request).await {
        Ok(()) => {
            let uploaded = wire::envelope_raw(
                inner.deps.clock.now_ms(),
                wire::next_seq(&inner.deps.seq),
                study_id,
                session_id,
                EventType::DropUploaded,
                Payload::DropUploaded(DropUploadedData {
                    copy: copy_name.to_owned(),
                    size_bytes: copied_bytes,
                }),
            );
            publish(&inner.deps.broker, uploaded).await;
        }
        Err(error) => {
            tracing::error!(%error, copy = %copy_name, "drop upload failed");
        }
    }
}

/// Stream `source` into `destination` with a hard cap; returns the SHA-256
/// digest of the bytes copied. The cap is enforced during the read because a
/// drop can grow between the pre-flight stat and the transfer.
async fn copy_capped(
    source: &str,
    destination: &std::path::Path,
    max_bytes: u64,
) -> Result<[u8; 32], std::io::Error> {
    let mut input = tokio::fs::File::open(source).await?;
    let mut output = tokio::fs::File::create(destination).await?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    // Truncate-after-read keeps the full-capacity allocation: no slicing, no
    // reallocation per chunk.
    let mut chunk = vec![0_u8; COPY_CHUNK_BYTES];
    loop {
        let read = input.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        total += u64::try_from(read).unwrap_or(u64::MAX);
        if total > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                format!("drop grew past cap {max_bytes} while copying"),
            ));
        }
        chunk.truncate(read);
        hasher.update(&chunk);
        output.write_all(&chunk).await?;
        chunk.resize(COPY_CHUNK_BYTES, 0);
    }
    output.flush().await?;
    Ok(hasher.finalize().into())
}

async fn publish(broker: &Arc<dyn BrokerPort>, envelope: Envelope<Payload>) {
    if let Err(error) = broker.publish(Channel::Event, &envelope).await {
        tracing::error!(%error, event = %envelope.event_type, "drop event publish failed");
    }
}

/// Everything `stop` must tear down, owned by the plugin.
struct OwnedWorkers {
    queue: JobQueue<String>,
    consumer: tokio::task::JoinHandle<()>,
    cancel: CancellationToken,
}

#[async_trait]
impl PluginPort for DropsCollectorPlugin {
    fn name(&self) -> &'static str {
        "drops-collector"
    }

    async fn start(&self) -> Result<(), kernel::models::PluginError> {
        let inner = Arc::clone(&self.inner);
        let queue: JobQueue<String> = JobQueue::spawn(QUEUE_CAPACITY, move |source| {
            let inner = Arc::clone(&inner);
            async move { Self::collect_drop(&inner, source).await }
        });

        let handle: SubmitHandle<String> = queue.handle();
        let mut receiver = self.inner.deps.bus.subscribe();
        let cancel = CancellationToken::new();
        let cancel_consumer = cancel.clone();
        let consumer = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    () = cancel_consumer.cancelled() => break,
                    event = receiver.recv() => match event {
                        Ok(AgentBusEvent::DropClosed { path }) => {
                            if !handle.submit(path) {
                                tracing::warn!("drop collection queue refused a drop");
                            }
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                            tracing::warn!(lost = count, "drops-collector bus lag");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        });

        *self.workers.lock() = Some(OwnedWorkers { queue, consumer, cancel });
        Ok(())
    }

    async fn stop(&self) -> Result<(), kernel::models::PluginError> {
        let workers = self.workers.lock().take();
        if let Some(workers) = workers {
            workers.cancel.cancel();
            workers.queue.stop().await;
            let _ = workers.consumer.await;
        }
        Ok(())
    }
}
