//! Driving ports — the pipeline entry points that driving adapters call.
//!
//! Implemented by the kernel itself; adapters normalize their native events into
//! the application's event type and hand them in.

use async_trait::async_trait;

/// Fire-and-forget inbound entry. No response is returned; outputs happen only
/// via driven ports carried in the services bundle.
#[async_trait]
pub trait EventInletPort<E>: Send + Sync + 'static {
    /// Accept one normalized inbound event into the middleware pipeline.
    async fn accept(&self, event: E);
}
