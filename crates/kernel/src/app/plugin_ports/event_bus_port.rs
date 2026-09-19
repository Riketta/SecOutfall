//! Kernel-owned pub/sub for derived plugin-owned domain events.

/// The kernel routes events but never defines their meaning; plugins own their
/// events and publish/subscribe them as `E`.
///
/// Best-effort by design (fire-and-forget core): publishing to zero subscribers is
/// legal and reported via the returned count so callers can account for loss.
/// Slow subscribers observe
/// [`tokio::sync::broadcast::error::RecvError::Lagged`] and must count the loss.
#[allow(clippy::module_name_repetitions)]
pub trait EventBusPort<E>: Send + Sync + 'static
where
    E: Clone + Send,
{
    /// Publish one event. Returns the number of subscribers it was delivered to.
    fn publish(&self, event: E) -> usize;

    /// Subscribe to all events of type `E`.
    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<E>;
}
