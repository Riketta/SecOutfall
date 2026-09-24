//! Live Windows Kernel ETW trace adapter (ferrisetw), feature `etw`.
//!
//! Design notes:
//! - ferrisetw callbacks run on the trace processing thread and `EventRecord`
//!   is `!Send` — payloads are parsed **inside** the callback and only our
//!   `Send` `SourceEvent` values cross into the async runtime via a **bounded**
//!   channel. Overflow policy: drop the event, count the loss, keep going
//!   (malware WILL flood the trace; doctrine forbids OOM or blocking the pump).
//! - The mapping table lives in [`crate::adapters::driving::etw_mapping`]; property
//!   parsing is defensive (candidate name lists) because classic kernel event
//!   schemas vary by Windows version — the `etw-probe` bin mode exists to
//!   verify names against a real session.

use std::sync::{
    Arc,
    atomic::{
        AtomicU64,
        Ordering,
    },
};

use async_trait::async_trait;
use ferrisetw::{
    parser::Parser,
    provider::{
        Provider,
        kernel_providers::{
            DISK_FILE_IO_PROVIDER,
            FILE_INIT_IO_PROVIDER,
            FILE_IO_PROVIDER,
            IMAGE_LOAD_PROVIDER,
            KernelProvider,
            PROCESS_PROVIDER,
            REGISTRY_PROVIDER,
            TCP_IP_PROVIDER,
            THREAD_PROVIDER,
        },
    },
    schema_locator::SchemaLocator,
    trace::KernelTrace,
};
use kernel::app::api_ports::EventInletPort;
use protocol::{
    events::EventType,
    payload::{
        FileCreatedData,
        FileDeletedData,
        FileFsctlData,
        FileReleasedData,
        FileRenamedData,
        FileWrittenData,
        ImageLoadedData,
        ImageUnloadedData,
        ProcessStartedData,
        ProcessStoppedData,
        RegistryKeyData,
        RegistryValueQueriedData,
        RegistryValueSetData,
        TcpConnectionData,
        ThreadStartedData,
        ThreadStoppedData,
    },
};
use tokio::sync::{
    Mutex,
    mpsc,
};
use tokio_util::sync::CancellationToken;

use crate::{
    adapters::driving::etw_mapping::{
        EtwProvider,
        event_type,
    },
    app::event::{
        SandboxEvent,
        SourceEvent,
    },
    ports::driving::event_source::{
        EventSourcePort,
        SourceError,
    },
};

/// Default ETW session name (kept close to the legacy `SecOutfall_Session`).
pub const SESSION_NAME: &str = "SecOutfall";

/// Live kernel trace adapter.
pub struct EtwKernelTraceAdapter {
    capacity: usize,
    session_name: String,
    loss: Arc<AtomicU64>,
    cancel: CancellationToken,
    trace: Mutex<Option<KernelTrace>>,
}

impl EtwKernelTraceAdapter {
    /// Bounded queue of `capacity` events between the ETW pump and the runtime.
    #[must_use]
    pub fn new(capacity: usize, session_name: impl Into<String>) -> Self {
        Self {
            capacity,
            session_name: session_name.into(),
            loss: Arc::new(AtomicU64::new(0)),
            cancel: CancellationToken::new(),
            trace: Mutex::new(None),
        }
    }

    /// Events dropped due to a full inbound queue (never blocks the pump).
    #[must_use]
    pub fn loss_count(&self) -> u64 {
        self.loss.load(Ordering::SeqCst)
    }

    /// Stop the live trace (idempotent).
    pub async fn stop(&self) {
        self.cancel.cancel();
        let mut guard = self.trace.lock().await;
        if let Some(trace) = guard.take() {
            let stopped = trace.stop();
            if let Err(error) = stopped {
                tracing::warn!(?error, "trace stop reported an error");
            }
        }
    }
}

#[async_trait]
impl EventSourcePort for EtwKernelTraceAdapter {
    async fn run(&self, inlet: Arc<dyn EventInletPort<SandboxEvent>>) -> Result<(), SourceError> {
        let loss = Arc::clone(&self.loss);
        let (tx, mut rx) = mpsc::channel::<SourceEvent>(self.capacity);

        let handler = move |record: &ferrisetw::EventRecord, locator: &SchemaLocator| {
            let Some(source_event) = parse_event(record, locator) else {
                return;
            };
            // Bounded hand-off: on overflow drop + count (never block the pump).
            if tx.try_send(source_event).is_err() {
                loss.fetch_add(1, Ordering::SeqCst);
            }
        };
        let build = |kernel_provider: &'static KernelProvider| {
            Provider::kernel(kernel_provider).add_callback(handler.clone()).build()
        };

        let trace = KernelTrace::new()
            .named(self.session_name.clone())
            .enable(build(&PROCESS_PROVIDER))
            .enable(build(&THREAD_PROVIDER))
            .enable(build(&IMAGE_LOAD_PROVIDER))
            .enable(build(&REGISTRY_PROVIDER))
            .enable(build(&FILE_IO_PROVIDER))
            .enable(build(&FILE_INIT_IO_PROVIDER))
            .enable(build(&DISK_FILE_IO_PROVIDER))
            .enable(build(&TCP_IP_PROVIDER))
            .start_and_process()
            .map_err(|error| SourceError::Stopped(format!("{error:?}")))?;
        *self.trace.lock().await = Some(trace);

        // Forward parsed events into the pipeline until stopped or closed.
        let forward = async {
            while let Some(event) = rx.recv().await {
                inlet.accept(SandboxEvent::Source(event)).await;
            }
        };
        tokio::select! {
            () = forward => {}
            () = self.cancel.cancelled() => {}
        }
        let dropped = self.loss_count();
        if dropped > 0 {
            tracing::warn!(lost = dropped, "ETW inbound queue overflow (events dropped)");
        }
        Ok(())
    }
}

/// Provider GUID → our [`EtwProvider`] key.
fn provider_of(record: &ferrisetw::EventRecord) -> Option<EtwProvider> {
    EtwProvider::from_guid(&format!("{:?}", record.provider_id()))
}

/// Defensive property lookup: classic kernel schemas changed property names
/// across Windows versions; try candidates in order.
fn opt_u32(parser: &Parser<'_, '_>, names: &[&str]) -> Option<u32> {
    names.iter().find_map(|name| parser.try_parse::<u32>(name).ok())
}

fn opt_u64(parser: &Parser<'_, '_>, names: &[&str]) -> Option<u64> {
    names.iter().find_map(|name| parser.try_parse::<u64>(name).ok())
}

fn opt_string(parser: &Parser<'_, '_>, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| parser.try_parse::<String>(name).ok())
}

fn opt_checksum(parser: &Parser<'_, '_>, names: &[&str]) -> Option<u32> {
    opt_u32(parser, names)
}

/// Map one raw ETW record onto a [`SourceEvent`] (None = unmapped/unparseable).
#[allow(clippy::too_many_lines)] // one arm per provider family, each trivial
fn parse_event(record: &ferrisetw::EventRecord, locator: &SchemaLocator) -> Option<SourceEvent> {
    let provider = provider_of(record)?;
    let opcode = record.opcode();
    let event = event_type(provider, opcode)?;
    let schema = locator.event_schema(record).ok()?;
    let parser = Parser::create(record, &schema);

    let parsed = match (provider, event) {
        (EtwProvider::Process, EventType::ProcessStarted) => {
            SourceEvent::ProcessStarted(ProcessStartedData {
                pid: record.process_id(),
                parent_pid: opt_u32(&parser, &["ParentId", "ParentProcessID"]),
                name: opt_string(&parser, &["ImageFileName", "ImageName"]).unwrap_or_default(),
                image_path: opt_string(&parser, &["ImagePath"]),
                command_line: opt_string(&parser, &["CommandLine"]),
                os_session_id: opt_u32(&parser, &["SessionId", "SessionID"]),
            })
        }
        (EtwProvider::Process, EventType::ProcessStopped) => {
            SourceEvent::ProcessStopped(ProcessStoppedData {
                pid: record.process_id(),
                name: opt_string(&parser, &["ImageFileName", "ImageName"]).unwrap_or_default(),
            })
        }
        (EtwProvider::Thread, EventType::ThreadStarted) => {
            SourceEvent::ThreadStarted(ThreadStartedData {
                pid: opt_u32(&parser, &["ProcessId", "TProcessId"]).unwrap_or(record.process_id()),
                tid: record.thread_id(),
                parent_tid: None,
            })
        }
        (EtwProvider::Thread, EventType::ThreadStopped) => {
            SourceEvent::ThreadStopped(ThreadStoppedData {
                pid: opt_u32(&parser, &["ProcessId"]).unwrap_or(record.process_id()),
                tid: record.thread_id(),
            })
        }
        (EtwProvider::Image, EventType::ImageLoaded) => SourceEvent::ImageLoaded(ImageLoadedData {
            pid: record.process_id(),
            name: opt_string(&parser, &["FileName"])
                .map(|path| file_name_of(&path))
                .unwrap_or_default(),
            image_path: opt_string(&parser, &["FileName"]),
            image_size: opt_u64(&parser, &["ImageSize"]),
            image_checksum: opt_checksum(&parser, &["ImageCheckSum", "ImageChecksum"]),
        }),
        (EtwProvider::Image, EventType::ImageUnloaded) => {
            SourceEvent::ImageUnloaded(ImageUnloadedData {
                pid: record.process_id(),
                name: opt_string(&parser, &["FileName"])
                    .map(|path| file_name_of(&path))
                    .unwrap_or_default(),
            })
        }
        (EtwProvider::Registry, event) => parse_registry(&parser, event)?,
        (EtwProvider::FileIo, event) => parse_file_io(&parser, event)?,
        (EtwProvider::TcpIp, event) => parse_tcp_ip(&parser, event)?,
        _ => return None,
    };
    Some(parsed)
}

/// The shared payload of the registry key-operation events; `None` when the
/// mandatory fields are missing from the schema (defensive: classic kernel
/// registry schemas vary by Windows version).
fn registry_key_data(
    pid: Option<u32>,
    key_name: Option<String>,
    key_handle: Option<u64>,
) -> Option<RegistryKeyData> {
    Some(RegistryKeyData { pid: pid?, key_name: key_name?, key_handle })
}

/// Map one registry event, variant for variant. A fallthrough here must never
/// fabricate a different event kind (legacy mislabeled everything as
/// `key_created`) — unexpected types are logged and dropped.
fn parse_registry(parser: &Parser<'_, '_>, event: EventType) -> Option<SourceEvent> {
    let key_name = opt_string(parser, &["KeyName"]);
    let key_handle = opt_u64(parser, &["KeyHandle"]);
    let pid = opt_u32(parser, &["PID", "ProcessId"]);
    match event {
        EventType::RegistryKeyCreated => {
            Some(SourceEvent::RegistryKeyCreated(registry_key_data(pid, key_name, key_handle)?))
        }
        EventType::RegistryKeyOpened => {
            Some(SourceEvent::RegistryKeyOpened(registry_key_data(pid, key_name, key_handle)?))
        }
        EventType::RegistryKeyDeleted => {
            Some(SourceEvent::RegistryKeyDeleted(registry_key_data(pid, key_name, key_handle)?))
        }
        EventType::RegistryKeyQueried => {
            Some(SourceEvent::RegistryKeyQueried(registry_key_data(pid, key_name, key_handle)?))
        }
        EventType::RegistryKeyClosed => {
            Some(SourceEvent::RegistryKeyClosed(registry_key_data(pid, key_name, key_handle)?))
        }
        EventType::RegistryValueQueried => {
            Some(SourceEvent::RegistryValueQueried(RegistryValueQueriedData {
                pid: pid?,
                key_name: key_name?,
                value_name: opt_string(parser, &["ValueName"]),
                key_handle,
            }))
        }
        EventType::RegistryValueSet => Some(SourceEvent::RegistryValueSet(RegistryValueSetData {
            pid: pid?,
            key_name: key_name?,
            value_name: opt_string(parser, &["ValueName"]),
            key_handle,
            value_type: opt_string(parser, &["ValueType"]),
            data_size: opt_u32(parser, &["DataSize"]),
        })),
        unexpected => {
            tracing::debug!(?unexpected, "unmapped registry event ignored");
            None
        }
    }
}

fn parse_file_io(parser: &Parser<'_, '_>, event: EventType) -> Option<SourceEvent> {
    let pid = opt_u32(parser, &["PID", "ProcessId"]);
    let file_object = opt_u64(parser, &["FileObject"]);
    let file_key = opt_u64(parser, &["FileKey"]);
    let file_name = opt_string(parser, &["FileName"]);
    match event {
        EventType::FileCreated => Some(SourceEvent::FileCreated(FileCreatedData {
            pid: pid?,
            file_object,
            file_name: file_name.clone(),
            create_options: opt_u32(parser, &["CreateOptions"]),
            create_disposition: opt_u32(parser, &["CreateDisposition"]),
        })),
        EventType::FileWritten => Some(SourceEvent::FileWritten(FileWrittenData {
            pid: pid?,
            file_object,
            file_key,
            file_name: file_name.clone(),
            io_size: opt_u64(parser, &["IoSize"]),
            offset: opt_u64(parser, &["Offset"]),
        })),
        EventType::FileClosed => Some(SourceEvent::FileClosed(FileReleasedData {
            pid: pid?,
            file_object,
            file_key,
            file_name: file_name.clone(),
        })),
        EventType::FileCleanedUp => Some(SourceEvent::FileCleanedUp(FileReleasedData {
            pid: pid?,
            file_object,
            file_key,
            file_name: file_name.clone(),
        })),
        EventType::FileDeleted => Some(SourceEvent::FileDeleted(FileDeletedData {
            pid: pid?,
            file_object,
            file_key,
            file_name: file_name.clone(),
        })),
        EventType::FileRenamed => Some(SourceEvent::FileRenamed(FileRenamedData {
            pid: pid?,
            file_object,
            file_name: file_name.clone(),
            new_name: opt_string(parser, &["NewPath", "NewFileName"]),
            file_key,
        })),
        EventType::FileFsctl => Some(SourceEvent::FileFsctl(FileFsctlData {
            pid: pid?,
            file_object,
            file_name: file_name.clone(),
            file_key,
        })),
        _ => None,
    }
}

fn parse_tcp_ip(parser: &Parser<'_, '_>, event: EventType) -> Option<SourceEvent> {
    let source_addr = opt_string(parser, &["saddr", "SourceAddress", "SrcAddr"])?;
    let dest_addr = opt_string(parser, &["daddr", "DestinationAddress", "DestAddr"])?;
    let connection = TcpConnectionData {
        pid: parser.try_parse::<u32>("PID").ok(),
        source_addr,
        source_port: u16::try_from(opt_u32(parser, &["sport", "SourcePort"]).unwrap_or(0))
            .unwrap_or(0),
        dest_addr,
        dest_port: u16::try_from(opt_u32(parser, &["dport", "DestPort"]).unwrap_or(0)).unwrap_or(0),
    };
    let source = match event {
        EventType::NetTcpConnected => SourceEvent::NetTcpConnected(connection),
        EventType::NetTcpAccepted => SourceEvent::NetTcpAccepted(connection),
        EventType::NetTcpDisconnected => SourceEvent::NetTcpDisconnected(connection),
        _ => return None,
    };
    Some(source)
}

/// Last path segment, for image `name` fields.
fn file_name_of(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_owned()
}
