//! `config-apply` — applies the agent's `WELCOME` push.
//!
//! The user-actor reads no files: the pushed config is its whole runtime
//! configuration. This plugin stores it in the shared runtime state (session
//! id + effective settings) and announces it on the bus so late-starting
//! observers can react.

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

use crate::domain::{
    ActorBusEvent,
    ActorEvent,
    ActorServices,
};

/// Config application plugin.
pub struct ConfigApplyPlugin {
    bus: InMemoryEventBus<ActorBusEvent>,
}

impl ConfigApplyPlugin {
    /// Assemble the plugin.
    #[must_use]
    pub const fn new(bus: InMemoryEventBus<ActorBusEvent>) -> Self {
        Self { bus }
    }
}

#[async_trait]
impl PluginPort for ConfigApplyPlugin {
    fn name(&self) -> &'static str {
        "config-apply"
    }
}

#[async_trait]
impl MiddlewarePluginPort<ActorEvent, ActorServices> for ConfigApplyPlugin {
    async fn pre(&self, event: &mut ActorEvent, services: &ActorServices) -> Next {
        if let ActorEvent::Welcome(welcome) = event {
            {
                let mut state = services.runtime.lock();
                state.session_id = welcome.session_id;
                state.config = Some(welcome.config.clone());
            }
            self.bus.publish(ActorBusEvent::ConfigApplied(welcome.config.clone()));
            tracing::info!(
                session_id = welcome.session_id,
                screencapture = welcome.config.screencapture,
                reactive = welcome.config.reactive,
                focus_method = ?welcome.config.focus_method,
                "runtime config applied"
            );
        }
        Next::Continue
    }
}
