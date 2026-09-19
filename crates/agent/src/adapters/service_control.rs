//! SCM service-control adapter (feature `service`, Windows only).
//!
//! Registers the control handler that turns SCM Stop/Shutdown into
//! [`SandboxEvent::ServiceStop`], forwarded into the runtime through a plain
//! mpsc channel (SCM callbacks must return fast; they never touch the pipeline
//! directly).

use std::time::Duration;

use windows_service::{
    service::{
        ServiceControl,
        ServiceControlAccept,
        ServiceExitCode,
        ServiceState,
        ServiceStatus,
        ServiceType,
    },
    service_control_handler::{
        self,
        ServiceControlHandlerResult,
    },
};

use crate::app::event::SandboxEvent;

/// Display/service name of the agent.
pub const SERVICE_NAME: &str = "SecOutfallAgent";

/// Handle used by the service main to report state transitions.
#[derive(Debug, Clone)]
pub struct StatusHandle {
    inner: windows_service::service_control_handler::ServiceStatusHandle,
    service_type: ServiceType,
}

impl StatusHandle {
    /// Transition to `Running` (STOP/SHUTDOWN accepted).
    ///
    /// # Errors
    /// [`windows_service::Error`] when SCM rejects the status update.
    pub fn running(&self) -> Result<(), windows_service::Error> {
        self.set(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN)
    }

    /// Transition to `Stopped`.
    ///
    /// # Errors
    /// [`windows_service::Error`] when SCM rejects the status update.
    pub fn stopped(&self) -> Result<(), windows_service::Error> {
        self.set(ServiceState::Stopped, ServiceControlAccept::empty())
    }

    fn set(
        &self,
        current_state: ServiceState,
        controls_accepted: ServiceControlAccept,
    ) -> Result<(), windows_service::Error> {
        self.inner.set_service_status(ServiceStatus {
            service_type: self.service_type,
            current_state,
            controls_accepted,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        })
    }
}

/// Register the SCM control handler. Control events are forwarded as
/// [`SandboxEvent::ServiceStop`] through `stop_tx`; everything else answers
/// `NotImplemented`.
///
/// # Errors
/// [`windows_service::Error`] when the handler cannot be registered.
pub fn register_control_handler(
    stop_tx: std::sync::mpsc::Sender<SandboxEvent>,
) -> Result<StatusHandle, windows_service::Error> {
    let inner = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            // Only ONE stop is needed; a send failure means the runtime is
            // already gone, which is fine.
            let _ = stop_tx.send(SandboxEvent::ServiceStop);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        // Legacy handled power events (SessionEnding); wiring them to the
        // finalizer is future work — answer honestly instead of guessing.
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    Ok(StatusHandle { inner, service_type: ServiceType::OWN_PROCESS })
}
