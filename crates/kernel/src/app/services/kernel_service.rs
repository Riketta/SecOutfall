//! The kernel: plugin registries, event bus wiring, and the pipeline runner.

use std::sync::Arc;

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
#[allow(clippy::module_name_repetitions)]
pub struct KernelService<E, S, B> {
    plugins: Vec<Arc<dyn PluginPort>>,
    middleware: Vec<Arc<dyn MiddlewarePluginPort<E, S>>>,
    event_bus: B,
    services: S,
}

impl<E, S, B> KernelService<E, S, B>
where
    B: EventBusPort<E>,
    E: Clone + Send,
{
    /// Assemble the kernel from plugin registries and injected services.
    #[must_use]
    pub fn new(
        plugins: Vec<Arc<dyn PluginPort>>,
        middleware: Vec<Arc<dyn MiddlewarePluginPort<E, S>>>,
        event_bus: B,
        services: S,
    ) -> Self {
        Self { plugins, middleware, event_bus, services }
    }

    /// Boot: `init` all plugins first, then `start` all — a plugin's start may
    /// rely on others being ready.
    ///
    /// # Errors
    /// Aborts on the first failed lifecycle hook.
    pub async fn boot(&self) -> Result<(), KernelError> {
        for plugin in &self.plugins {
            plugin
                .init()
                .await
                .map_err(|source| KernelError::Lifecycle { plugin: plugin.name(), source })?;
        }
        for plugin in &self.plugins {
            plugin
                .start()
                .await
                .map_err(|source| KernelError::Lifecycle { plugin: plugin.name(), source })?;
        }
        Ok(())
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
impl<E, S, B> EventInletPort<E> for KernelService<E, S, B>
where
    B: EventBusPort<E>,
    E: Clone + Send + 'static,
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
