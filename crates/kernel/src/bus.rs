//! Default in-memory event bus adapter (bounded tokio broadcast).
//!
//! Cardinality doctrine: one bus adapter per kernel, single instance, owned by the
//! composition root and injected into plugins.

use tokio::sync::broadcast;

use crate::app::plugin_ports::event_bus_port::EventBusPort;

/// Bounded in-memory bus. Overflow policy: the publisher never blocks; slow
/// subscribers lose events and see `RecvError::Lagged` — they must count the loss
/// and report it.
#[derive(Clone)]
pub struct InMemoryEventBus<E> {
    sender: broadcast::Sender<E>,
}

impl<E> InMemoryEventBus<E>
where
    E: Clone + Send,
{
    /// Create a bus with a bounded queue of `capacity` events per lag window.
    /// A `capacity` of 0 is clamped to 1 (tokio's broadcast channel panics on
    /// zero; a config-derived zero must degrade to "lag on the second event",
    /// never panic the kernel).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(1));
        Self { sender }
    }
}

impl<E> EventBusPort<E> for InMemoryEventBus<E>
where
    E: Clone + Send + 'static,
{
    fn publish(&self, event: E) -> usize {
        self.sender.send(event).unwrap_or(0)
    }

    fn subscribe(&self) -> broadcast::Receiver<E> {
        self.sender.subscribe()
    }
}
