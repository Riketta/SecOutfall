//! SCM service-control adapter (feature `service`, Windows only).
//!
//! Two responsibilities:
//! - the control handler that turns SCM Stop/Shutdown into
//!   [`SandboxEvent::ServiceStop`], forwarded into the runtime through a plain
//!   mpsc channel (SCM callbacks must return fast; they never touch the
//!   pipeline directly);
//! - the `install`/`uninstall` ops backing the bin's subcommands (create the
//!   SCM entry pointing at this exe with `--config <path>`, stop + delete it).

use std::time::Duration;

use windows_service::{
    service::{
        ServiceAccess,
        ServiceControl,
        ServiceControlAccept,
        ServiceErrorControl,
        ServiceExitCode,
        ServiceInfo,
        ServiceStartType,
        ServiceState,
        ServiceStatus,
        ServiceType,
    },
    service_control_handler::{
        self,
        ServiceControlHandlerResult,
    },
    service_manager::{
        ServiceManager,
        ServiceManagerAccess,
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

// ---- Installation ops (the bin's `install`/`uninstall` subcommands) ----

/// Display name shown in `services.msc`.
pub const SERVICE_DISPLAY_NAME: &str = "SecOutfall Agent";

/// Description shown in `services.msc`.
pub const SERVICE_DESCRIPTION: &str =
    "Malware analysis sandbox agent (session 0). Runs in an isolated analysis VM only.";

/// Seconds to wait for a clean stop before deleting a running service anyway.
const STOP_WAIT: Duration = Duration::from_secs(10);

const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;
const ERROR_SERVICE_MARKED_FOR_DELETE: i32 = 1072;

/// Failures of the `install`/`uninstall` ops.
#[derive(Debug, thiserror::Error)]
pub enum ServiceOpError {
    /// The SCM entry already exists; install refuses to clobber it.
    #[error("service `{name}` is already installed (uninstall first)")]
    AlreadyInstalled {
        /// Offending service name.
        name: &'static str,
    },
    /// No SCM entry to uninstall.
    #[error("service `{name}` is not installed")]
    NotInstalled {
        /// Missing service name.
        name: &'static str,
    },
    /// The config file failed to load or validate (checked before install so
    /// the service never crash-loops on a broken config).
    #[error("config check failed: {0}")]
    Config(#[from] crate::adapters::config_toml::ConfigLoadError),
    /// Filesystem error (e.g. resolving the current executable).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Any other SCM failure.
    #[error("SCM operation failed: {0}")]
    Scm(#[from] windows_service::Error),
}

/// Extra actions for [`install`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallOptions {
    /// Start the service right after creating it (otherwise it starts at the
    /// next boot, per `AutoStart`).
    pub start_after_install: bool,
}

/// Create the SCM entry for this executable with `--config <path>` arguments.
/// `LocalSystem`, automatic start. Refuses to double-install; validates the
/// config first so a broken file never produces a crash-looping service.
///
/// # Errors
/// [`ServiceOpError`] for config, filesystem, or SCM failures.
pub fn install(
    config_path: &std::path::Path,
    options: InstallOptions,
) -> Result<(), ServiceOpError> {
    // Fail fast: a service that cannot read its config is useless and the
    // operator gets a precise error here instead of in the event log.
    let _validated = crate::adapters::config_toml::load(config_path)?;
    let executable_path = std::env::current_exe()?;

    let manager = ServiceManager::local_computer(
        None::<&std::ffi::OsStr>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    if manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS).is_ok() {
        return Err(ServiceOpError::AlreadyInstalled { name: SERVICE_NAME });
    }

    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: SERVICE_DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path,
        launch_arguments: vec![
            std::ffi::OsString::from("--config"),
            config_path.as_os_str().to_owned(),
        ],
        dependencies: Vec::new(),
        account_name: None, // None = LocalSystem
        account_password: None,
    };
    let mut access = ServiceAccess::QUERY_STATUS;
    if options.start_after_install {
        access |= ServiceAccess::START;
    }
    let service = manager.create_service(&info, access)?;
    // Cosmetic; a rejected description must not fail the install.
    let _ = service.set_description(SERVICE_DESCRIPTION);
    if options.start_after_install {
        service.start(&[] as &[&std::ffi::OsStr])?;
    }
    Ok(())
}

/// Stop (best effort, bounded wait) and delete the SCM entry. Windows marks
/// the service for deletion; the entry disappears once the process exits.
///
/// # Errors
/// [`ServiceOpError::NotInstalled`] or an SCM failure.
pub fn uninstall() -> Result<(), ServiceOpError> {
    let manager =
        ServiceManager::local_computer(None::<&std::ffi::OsStr>, ServiceManagerAccess::CONNECT)?;
    let service = match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        Ok(service) => service,
        Err(error) if raw_is(&error, ERROR_SERVICE_DOES_NOT_EXIST) => {
            return Err(ServiceOpError::NotInstalled { name: SERVICE_NAME });
        }
        Err(error) => return Err(error.into()),
    };

    // Stop first so deletion completes immediately; a still-running service
    // is deleted anyway (SCM defers to process exit).
    match service.query_status() {
        Ok(status) if status.current_state == ServiceState::Stopped => {}
        Ok(_) => {
            if let Err(error) = service.stop()
                && !raw_is(&error, ERROR_SERVICE_NOT_ACTIVE)
            {
                return Err(error.into());
            }
            wait_until_stopped(&service, STOP_WAIT);
        }
        Err(error) if raw_is(&error, ERROR_SERVICE_MARKED_FOR_DELETE) => {
            // Already on its way out; nothing to do.
        }
        Err(error) => return Err(error.into()),
    }

    service.delete()?;
    Ok(())
}

/// Poll the service state up to `deadline`; gives up silently so the caller
/// can proceed with deletion (SCM completes it at process exit).
fn wait_until_stopped(service: &windows_service::service::Service, deadline: Duration) {
    let started = std::time::Instant::now();
    while started.elapsed() < deadline {
        match service.query_status() {
            Ok(status) if status.current_state == ServiceState::Stopped => return,
            Ok(_) => {}
            // Deleted out from under us while stopping — done either way.
            Err(error) if raw_is(&error, ERROR_SERVICE_MARKED_FOR_DELETE) => return,
            Err(_) => return,
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Match a Win32 error code carried in [`windows_service::Error::Winapi`].
fn raw_is(error: &windows_service::Error, code: i32) -> bool {
    matches!(error, windows_service::Error::Winapi(io) if io.raw_os_error() == Some(code))
}
