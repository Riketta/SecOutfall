//! `focus-watch` — screenshots on foreground changes.
//!
//! Every deduplicated change is announced on the bus (the reactive plugin
//! listens there). When capture is enabled and quota remains, the plugin
//! captures the desktop and ships the frame through the sink; the sequence
//! number is this session's capture counter. Capture is gated strictly on
//! the pushed config (legacy bug #4: screenshots were produced even when
//! `screencapture` was disabled).

use std::sync::atomic::{
    AtomicU32,
    Ordering,
};

use async_trait::async_trait;
use kernel::{
    app::plugin_ports::{
        event_bus_port::EventBusPort,
        middleware_plugin_port::{
            MiddlewarePluginPort,
            Next,
        },
        plugin_port::PluginPort,
    },
    bus::InMemoryEventBus,
};

use crate::{
    domain::{
        ActorBusEvent,
        ActorEvent,
        ActorServices,
    },
    ports::{
        ScreenCapturePort,
        ScreenshotSinkPort,
    },
};

/// Focus watching plugin.
pub struct FocusWatchPlugin {
    bus: InMemoryEventBus<ActorBusEvent>,
    capture: std::sync::Arc<dyn ScreenCapturePort>,
    sink: std::sync::Arc<dyn ScreenshotSinkPort>,
    /// This session's capture counter (sequence numbers start at 0).
    captured: AtomicU32,
    /// Set when the quota ran out (one bus event, ever).
    quota_exhausted: std::sync::atomic::AtomicBool,
}

impl FocusWatchPlugin {
    /// Assemble the plugin.
    #[must_use]
    pub const fn new(
        bus: InMemoryEventBus<ActorBusEvent>,
        capture: std::sync::Arc<dyn ScreenCapturePort>,
        sink: std::sync::Arc<dyn ScreenshotSinkPort>,
    ) -> Self {
        Self {
            bus,
            capture,
            sink,
            captured: AtomicU32::new(0),
            quota_exhausted: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Captures successfully shipped this session (diagnostics/tests).
    #[must_use]
    pub fn captured_count(&self) -> u32 {
        self.captured.load(Ordering::SeqCst)
    }

    /// The whole capture flow for one focus change. Returns when the frame is
    /// handed to the sink (or skipped) — capture is rare enough that blocking
    /// the sparse pipeline briefly is fine, and it keeps sequence ordering.
    async fn handle_focus(&self, services: &ActorServices, focus: &crate::domain::FocusInfo) {
        let Some(config) = services.runtime.lock().config.clone() else {
            tracing::debug!("focus change ignored: no config push yet");
            return;
        };

        self.bus.publish(ActorBusEvent::ForegroundChanged { focus: focus.clone() });

        if !config.screencapture {
            return;
        }
        let quota = config.max_screenshots_per_session;
        // Reserve the sequence slot atomically: the inlet accepts from several
        // adapters concurrently, so check-then-act could over-run the quota.
        let seq = self.captured.load(Ordering::SeqCst);
        if seq >= quota {
            if !self.quota_exhausted.swap(true, Ordering::SeqCst) {
                tracing::info!(quota, "screenshot quota exhausted for this session");
                self.bus.publish(ActorBusEvent::CaptureQuotaExhausted);
            }
            return;
        }
        let reserved =
            self.captured.compare_exchange(seq, seq + 1, Ordering::SeqCst, Ordering::SeqCst);
        let Ok(seq) = reserved else {
            // Another inlet took the slot; the next focus change re-checks.
            return;
        };

        match self.capture.capture().await {
            Ok(jpeg) => match self.sink.send(seq, jpeg).await {
                Ok(()) => {
                    tracing::debug!(seq, "screenshot captured and queued");
                    self.bus.publish(ActorBusEvent::ScreenshotTaken { seq });
                }
                Err(error) => {
                    // Release the slot: the transport may heal and reuse it.
                    self.captured.fetch_sub(1, Ordering::SeqCst);
                    tracing::warn!(seq, %error, "screenshot sink rejected the frame");
                }
            },
            Err(error) => {
                self.captured.fetch_sub(1, Ordering::SeqCst);
                tracing::warn!(%error, "screen capture failed");
            }
        }
    }
}

#[async_trait]
impl PluginPort for FocusWatchPlugin {
    fn name(&self) -> &'static str {
        "focus-watch"
    }
}

#[async_trait]
impl MiddlewarePluginPort<ActorEvent, ActorServices> for FocusWatchPlugin {
    async fn pre(&self, event: &mut ActorEvent, services: &ActorServices) -> Next {
        if let ActorEvent::FocusChanged(focus) = event {
            self.handle_focus(services, focus).await;
        }
        Next::Continue
    }
}
