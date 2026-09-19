//! Kernel domain models — deliberately minimal.
//!
//! If logic needs a plugin to exist, it does not belong in the kernel.

use std::error::Error as StdError;

/// Pure control signal returned by `pre` hooks. Carries NO payload — the core is
/// fire-and-forget; outputs happen only via driven ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// Pass the event to the next middleware plugin.
    Continue,
    /// Skip remaining `pre` hooks; `post` hooks still run for plugins that ran.
    Stop,
    /// Skip remaining `pre` hooks AND all `post` hooks.
    Abort,
}

/// Error produced by a plugin lifecycle hook.
#[derive(Debug, thiserror::Error)]
#[error("plugin `{plugin}` failed")]
pub struct PluginError {
    plugin: &'static str,
    #[source]
    source: Box<dyn StdError + Send + Sync>,
}

impl PluginError {
    /// Wrap a lower-level error with the plugin identity.
    #[must_use]
    pub fn new(plugin: &'static str, source: impl Into<Box<dyn StdError + Send + Sync>>) -> Self {
        Self { plugin, source: source.into() }
    }
}

/// Fatal kernel lifecycle error; boot aborts on the first failure.
#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    /// A lifecycle hook failed during boot.
    #[error("boot failed at plugin `{plugin}`")]
    Lifecycle {
        /// Name of the plugin whose hook failed.
        plugin: &'static str,
        /// The underlying hook error.
        #[source]
        source: PluginError,
    },
}
