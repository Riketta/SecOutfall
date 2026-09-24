//! `screenshot-intake` — receives decoded screenshot frames from the
//! user-actor (inbound [`SandboxEvent::ScreenshotReceived`]), saves them when
//! configured, uploads them to the Controller, and reports both wire events.
//!
//! Fixes vs legacy:
//! - when `user_actor.screencapture` is disabled, frames are refused here too
//!   (bug #4: legacy created the manager unconditionally and sent anyway) —
//!   the user-actor must not send, but the agent does not trust that;
//! - the per-session quota (`screenshots.max_per_session`) is enforced on the
//!   receiving side, not just pushed to the user-actor;
//! - save + upload run on a bounded job queue — a screenshot storm cannot
//!   wedge the pipeline or OOM the agent.

use std::{
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
        middleware_plugin_port::{
            MiddlewarePluginPort,
            Next,
        },
        plugin_port::PluginPort,
    },
    bus::InMemoryEventBus,
};
use parking_lot::Mutex;
use protocol::{
    config::ScreenshotsConfig,
    events::EventType,
    nats::Envelope,
    payload::{
        Payload,
        ScreenshotReceivedData,
        ScreenshotUploadedData,
    },
};

use crate::{
    app::{
        builder::AgentServices,
        event::{
            AgentBusEvent,
            SandboxEvent,
            ScreenshotFrame,
        },
        worker::JobQueue,
    },
    domain::scope::SharedScopeState,
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

/// Intake queue capacity; the per-session quota dwarfs it.
const QUEUE_CAPACITY: usize = 64;

/// Constructor dependencies.
pub struct ScreenshotIntakeDeps {
    /// Shared scope state (study/session identity on the wire).
    pub state: SharedScopeState,
    /// Screenshot policy (path/save/quota/endpoint).
    pub config: Arc<ScreenshotsConfig>,
    /// Master gate (`user_actor.screencapture`) — refused when off (bug #4).
    pub capture_enabled: bool,
    /// Controller upload transport.
    pub uploader: Arc<dyn FileUploadPort>,
    /// Wire output.
    pub broker: Arc<dyn BrokerPort>,
    /// Time source.
    pub clock: Arc<dyn SystemClockPort>,
    /// Shared per-boot wire sequence counter.
    pub seq: Arc<AtomicU64>,
    /// Derived-event bus (kept for uniform plugin construction).
    pub bus: InMemoryEventBus<AgentBusEvent>,
}

/// Shared intake state.
struct Inner {
    deps: ScreenshotIntakeDeps,
    /// Screenshots accepted this session (vs `max_per_session`).
    accepted: AtomicU32,
}

/// Screenshot intake plugin (pipeline middleware).
pub struct ScreenshotIntakePlugin {
    inner: Arc<Inner>,
    workers: Mutex<Option<OwnedWorkers>>,
}

/// A job: one frame to persist and/or upload.
struct FrameJob {
    study_id: uuid::Uuid,
    session_id: u32,
    frame: ScreenshotFrame,
}

impl ScreenshotIntakePlugin {
    /// Assemble the plugin.
    #[must_use]
    pub fn new(deps: ScreenshotIntakeDeps) -> Self {
        Self {
            inner: Arc::new(Inner { deps, accepted: AtomicU32::new(0) }),
            workers: Mutex::new(None),
        }
    }

    /// Persist + upload job, run off the pipeline by the worker.
    async fn process_frame(inner: &Inner, job: FrameJob) {
        let FrameJob { study_id, session_id, frame } = job;
        let wire_name = format!("screenshot-{session_id}-{}.jpeg", frame.seq);

        // Where the bytes live for the upload: the save location, or a temp
        // file when saving is off but uploading is on.
        let local_path = if inner.deps.config.save {
            let dir = PathBuf::from(&inner.deps.config.path);
            let path = dir.join(&wire_name);
            if let Err(error) = tokio::fs::create_dir_all(&dir).await {
                tracing::error!(%error, dir = %dir.display(), "screenshots directory unavailable");
                return;
            }
            // Unique name per (session, seq) — direct write is safe; this is
            // telemetry, not persistent state.
            if let Err(error) = tokio::fs::write(&path, &frame.jpeg).await {
                tracing::error!(%error, path = %path.display(), "screenshot save failed");
                return;
            }
            path
        } else if inner.deps.config.upload_uri.is_some() {
            let path = std::env::temp_dir().join(&wire_name);
            if let Err(error) = tokio::fs::write(&path, &frame.jpeg).await {
                tracing::error!(%error, path = %path.display(), "screenshot staging failed");
                return;
            }
            path
        } else {
            // Neither saved nor uploaded: the wire `received` event was the
            // product; done.
            return;
        };

        if let Some(endpoint) = inner.deps.config.upload_uri.clone() {
            let request = UploadRequest {
                endpoint,
                meta: UploadMeta { path: wire_name.clone(), study: study_id, session: session_id },
                file_path: local_path.clone(),
                max_blob_bytes: u64::try_from(frame.jpeg.len()).unwrap_or(u64::MAX),
            };
            match inner.deps.uploader.upload(request).await {
                Ok(()) => {
                    let uploaded = wire::envelope_raw(
                        inner.deps.clock.now_ms(),
                        wire::next_seq(&inner.deps.seq),
                        study_id,
                        session_id,
                        EventType::ScreenshotUploaded,
                        Payload::ScreenshotUploaded(ScreenshotUploadedData { seq: frame.seq }),
                    );
                    publish(&inner.deps.broker, uploaded).await;
                }
                Err(error) => {
                    tracing::error!(%error, screenshot = %wire_name, "screenshot upload failed");
                }
            }
        }

        // Staged-only files (save off) are transient — clean up.
        if !inner.deps.config.save {
            let _ = tokio::fs::remove_file(&local_path).await;
        }
    }
}

async fn publish(broker: &Arc<dyn BrokerPort>, envelope: Envelope<Payload>) {
    if let Err(error) = broker.publish(Channel::Event, &envelope).await {
        tracing::error!(%error, event = %envelope.event_type, "screenshot publish failed");
    }
}

/// Everything `stop` must tear down, owned by the plugin.
struct OwnedWorkers {
    queue: JobQueue<FrameJob>,
}

#[async_trait]
impl PluginPort for ScreenshotIntakePlugin {
    fn name(&self) -> &'static str {
        "screenshot-intake"
    }

    async fn start(&self) -> Result<(), kernel::models::PluginError> {
        let inner = Arc::clone(&self.inner);
        let queue: JobQueue<FrameJob> = JobQueue::spawn(QUEUE_CAPACITY, move |job| {
            let inner = Arc::clone(&inner);
            async move { Self::process_frame(&inner, job).await }
        });
        *self.workers.lock() = Some(OwnedWorkers { queue });
        Ok(())
    }

    async fn stop(&self) -> Result<(), kernel::models::PluginError> {
        let workers = self.workers.lock().take();
        if let Some(workers) = workers {
            workers.queue.stop().await;
        }
        Ok(())
    }
}

#[async_trait]
impl MiddlewarePluginPort<SandboxEvent, AgentServices> for ScreenshotIntakePlugin {
    async fn pre(&self, event: &mut SandboxEvent, _services: &AgentServices) -> Next {
        let SandboxEvent::ScreenshotReceived(frame) = event else {
            return Next::Continue;
        };

        if !self.inner.deps.capture_enabled {
            // Bug #4: never touch or send screenshots when capture is off.
            tracing::warn!(seq = frame.seq, "screenshot received while capture disabled; refused");
            return Next::Continue;
        }
        let accepted = self.inner.accepted.fetch_add(1, Ordering::SeqCst) + 1;
        if accepted > self.inner.deps.config.max_per_session {
            tracing::warn!(
                seq = frame.seq,
                quota = self.inner.deps.config.max_per_session,
                "screenshot quota exhausted; frame dropped"
            );
            return Next::Continue;
        }

        let (study_id, session_id) = {
            let state = self.inner.deps.state.lock();
            let session_id = state.current_session().map_or(0, |session| session.id);
            (state.study_id, session_id)
        };

        let received = wire::envelope_raw(
            self.inner.deps.clock.now_ms(),
            wire::next_seq(&self.inner.deps.seq),
            study_id,
            session_id,
            EventType::ScreenshotReceived,
            Payload::ScreenshotReceived(ScreenshotReceivedData {
                seq: frame.seq,
                size_bytes: u64::try_from(frame.jpeg.len()).unwrap_or(u64::MAX),
            }),
        );
        publish(&self.inner.deps.broker, received).await;

        // Take the frame out of the event: intake is its only consumer, and
        // megabyte-scale JPEGs must not be cloned per hop.
        let frame = std::mem::take(frame);
        let handle = {
            let workers = self.workers.lock();
            workers.as_ref().map(|workers| workers.queue.handle())
        };
        if let Some(handle) = handle
            && !handle.submit(FrameJob { study_id, session_id, frame })
        {
            tracing::warn!("screenshot queue refused a frame");
        }
        Next::Continue
    }
}
