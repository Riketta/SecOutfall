//! Per-plugin pipeline step contract (NOT the pipeline itself — the kernel runs it).

use async_trait::async_trait;

use crate::app::plugin_ports::plugin_port::PluginPort;
#[doc(inline)]
pub use crate::models::Next;

/// A plugin that intercepts inbound events implements this in addition to
/// [`PluginPort`]. Steps run forward through `pre`, backward through `post`.
#[allow(clippy::module_name_repetitions)]
#[async_trait]
pub trait MiddlewarePluginPort<E, S>: PluginPort {
    /// Forward hook. May short-circuit the chain via [`Next`].
    async fn pre(&self, _event: &mut E, _services: &S) -> Next {
        Next::Continue
    }

    /// Backward hook. Always runs for plugins whose `pre` ran, unless the chain
    /// was aborted. Cannot short-circuit.
    async fn post(&self, _event: &mut E, _services: &S) {}
}
