//! Base plugin contract: identity + lifecycle.

use async_trait::async_trait;

use crate::models::PluginError;

/// Base contract every plugin implements.
///
/// Lifecycle: `boot()` runs [`init`](Self::init) on all plugins, then
/// [`start`](Self::start) on all; `shutdown()` runs [`stop`](Self::stop) in
/// reverse registration order. A plugin that also intercepts inbound events
/// additionally implements
/// [`MiddlewarePluginPort`](crate::app::plugin_ports::middleware_plugin_port::MiddlewarePluginPort);
/// the same `Arc` is registered in both registries.
#[allow(clippy::module_name_repetitions)]
#[async_trait]
pub trait PluginPort: Send + Sync + 'static {
    /// Unique plugin name, used in logs and error reporting.
    fn name(&self) -> &'static str;

    /// Prepare the plugin. All plugins are initialized before any starts.
    async fn init(&self) -> Result<(), PluginError> {
        Ok(())
    }

    /// Activate the plugin. All other plugins are initialized by now.
    async fn start(&self) -> Result<(), PluginError> {
        Ok(())
    }

    /// Deactivate the plugin. Must be idempotent and best-effort.
    async fn stop(&self) -> Result<(), PluginError> {
        Ok(())
    }
}
