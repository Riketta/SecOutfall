//! The kernel: plugin registries, event bus wiring, and the pipeline runner.

use std::{
    marker::PhantomData,
    sync::Arc,
};

use async_trait::async_trait;

use crate::{
    app::{
        api_ports::EventInletPort,
        plugin_ports::{
            event_bus_port::EventBusPort,
            middleware_plugin_port::MiddlewarePluginPort,
            plugin_port::PluginPort,
        },
    },
    models::{
        KernelError,
        Next,
    },
};

/// The inner hexagon. Assembles the chain, but never knows what is in it.
///
/// `D` is the derived bus event type — a different taxonomy from inbound `E`
/// (doctrine: the bus never carries raw inbound events). Defaults to `E` for
/// simple deployments and tests.
#[allow(clippy::module_name_repetitions)]
pub struct KernelService<E, S, B, D = E> {
    plugins: Vec<Arc<dyn PluginPort>>,
    middleware: Vec<Arc<dyn MiddlewarePluginPort<E, S>>>,
    event_bus: B,
    services: S,
    // `fn() -> D` marker: always Send + Sync, unlike plain PhantomData<D>.
    _bus_events: PhantomData<fn() -> D>,
}

impl<E, S, B, D> KernelService<E, S, B, D>
where
    B: EventBusPort<D>,
    D: Clone + Send,
    E: Send + 'static,
{
    /// Assemble the kernel from plugin registries and injected services.
    #[must_use]
    pub fn new(
        plugins: Vec<Arc<dyn PluginPort>>,
        middleware: Vec<Arc<dyn MiddlewarePluginPort<E, S>>>,
        event_bus: B,
        services: S,
    ) -> Self {
        Self { plugins, middleware, event_bus, services, _bus_events: PhantomData }
    }

    /// Boot: `init` all plugins first, then `start` all — a plugin's start may
    /// rely on others being ready.
    ///
    /// On a failed hook, every already-processed plugin is rolled back in
    /// reverse (`stop`), so a failed boot never leaves half-live plugins
    /// behind. `stop` is contractually idempotent and must tolerate plugins
    /// that are initialized-but-not-started (or whose start failed midway).
    ///
    /// # Errors
    /// [`KernelError::Lifecycle`] naming the first failed plugin, after the
    /// rollback completed.
    pub async fn boot(&self) -> Result<(), KernelError> {
        for (index, plugin) in self.plugins.iter().enumerate() {
            if let Err(source) = plugin.init().await {
                self.rollback(index).await;
                return Err(KernelError::Lifecycle { plugin: plugin.name(), source });
            }
        }
        for (index, plugin) in self.plugins.iter().enumerate() {
            if let Err(source) = plugin.start().await {
                // Include the failing plugin: its partial start may hold
                // resources only `stop` can release.
                self.rollback(index + 1).await;
                return Err(KernelError::Lifecycle { plugin: plugin.name(), source });
            }
        }
        Ok(())
    }

    /// Best-effort reverse-order `stop` of the first `count` plugins.
    async fn rollback(&self, count: usize) {
        for plugin in self.plugins.iter().take(count).rev() {
            if let Err(error) = plugin.stop().await {
                tracing::warn!(plugin = plugin.name(), %error, "boot rollback stop failed");
            }
        }
    }

    /// Shutdown: `stop` all plugins in reverse registration order. Best-effort:
    /// failures are logged, remaining plugins are still stopped.
    pub async fn shutdown(&self) {
        for plugin in self.plugins.iter().rev() {
            if let Err(error) = plugin.stop().await {
                tracing::error!(plugin = plugin.name(), %error, "plugin stop failed");
            }
        }
    }

    /// The kernel-owned event bus, shared with plugins via injection.
    #[must_use]
    pub const fn event_bus(&self) -> &B {
        &self.event_bus
    }

    /// The services bundle driven ports are carried in, injected into every hook.
    #[must_use]
    pub const fn services(&self) -> &S {
        &self.services
    }
}

#[async_trait]
impl<E, S, B, D> EventInletPort<E> for KernelService<E, S, B, D>
where
    B: EventBusPort<D>,
    D: Clone + Send + 'static,
    E: Send + 'static,
    S: Send + Sync + 'static,
{
    async fn accept(&self, mut event: E) {
        let mut ran: usize = 0;
        let mut aborted = false;

        for step in &self.middleware {
            match step.pre(&mut event, &self.services).await {
                Next::Continue => ran += 1,
                Next::Stop => {
                    ran += 1;
                    break;
                }
                Next::Abort => {
                    aborted = true;
                    break;
                }
            }
        }

        if aborted {
            return;
        }

        for step in self.middleware.iter().take(ran).rev() {
            step.post(&mut event, &self.services).await;
        }
    }
}
