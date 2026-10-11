//! Driver event source adapter (feature `driver`): drains the kernel
//! driver's control device (`GET_DATA`) and promotes wire-v2 records into
//! [`SandboxEvent`]s.
//!
//! Design notes:
//! - One `GET_DATA` batch per tick; records are decoded with
//!   [`protocol::driver_wire`] (the same golden-pinned decoder the fixture
//!   tests use), so a hostile/garbled ring or queue can only cost records,
//!   never corrupt the pipeline.
//! - Clock mapping: the driver stamps real kernel time; the agent lives on
//!   the fake clock. The adapter lazily captures `fake_now - kernel_now` on
//!   the first drained record and applies that offset to every record —
//!   events pre-dating the clock manipulation map to their true pre-fake
//!   moment (correlate by session id, never by SDK timestamps).
//! - Process-exit name resolution: the wire `ProcessExited` record carries no
//!   name, so the adapter keeps a bounded pid→name cache fed by
//!   `ProcessCreated` (same pattern as every ETW consumer).
//! - Overflow policy: bounded channel, drop + count (doctrine).
//! - `DropCaptured` records are logged, not yet routed to the
//!   drops-collector (the driver has already preserved the content).

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{
            AtomicI64,
            Ordering,
        },
    },
    time::Duration,
};

use async_trait::async_trait;
use kernel::app::api_ports::EventInletPort;
use protocol::{
    driver_wire,
    payload::{
        BehaviorCallData,
        FileCreatedData,
        FileDeletedData,
        FileReleasedData,
        FileRenamedData,
        FileWrittenData,
        ImageLoadedData,
        ProcessStartedData,
        ProcessStoppedData,
        ProtectionStrippedData,
        RegistryKeyData,
        RegistryValueSetData,
        ThreadStartedData,
        ThreadStoppedData,
    },
};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle,
            HANDLE,
        },
        Storage::FileSystem::{
            CreateFileW,
            FILE_FLAGS_AND_ATTRIBUTES,
            FILE_SHARE_MODE,
            FILE_SHARE_READ,
            FILE_SHARE_WRITE,
            OPEN_EXISTING,
        },
    },
    core::PCWSTR,
};
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
use windows::Win32::System::IO::DeviceIoControl;

use crate::{
    app::event::{
        SandboxEvent,
        SourceEvent,
    },
    ports::driving::event_source::SourceError,
};

const DRIVER_PATH: PCWSTR = windows::core::w!(r"\\.\secoutfall");
// Pinned in the port module (fixture vs the C compiler's macros) — the old
// hand-derived constant here used method 1 (IN_DIRECT) where the driver
// expects OUT_DIRECT, so every drain call failed against the real device.
use crate::ports::driven::driver_control::codes;
const IOCTL_GET_DATA: u32 = codes::GET_DATA;

const DRAIN_BUFFER_SIZE: usize = 1 << 20; // 1 MiB
const DRAIN_INTERVAL: Duration = Duration::from_millis(100);
const NAME_CACHE_CAP: usize = 4096;

/// Driver event source: one open control device, one drain loop.
pub struct DriverEventSourceAdapter {
    clock: Arc<dyn crate::ports::driven::clock::SystemClockPort>,
    clock_offset_ms: AtomicI64,
    cancel: tokio_util::sync::CancellationToken,
}

impl DriverEventSourceAdapter {
    /// Builds the adapter over the agent's (fake) clock port; the real→fake
    /// offset is captured lazily from the first drained record.
    pub fn new(clock: Arc<dyn crate::ports::driven::clock::SystemClockPort>) -> Self {
        Self {
            clock,
            clock_offset_ms: AtomicI64::new(0),
            cancel: tokio_util::sync::CancellationToken::new(),
        }
    }

    /// Stops the drain loop (idempotent). [`run`](Self::run) returns shortly
    /// after — the per-iteration sleep is cancel-aware; a blocking
    /// `GET_DATA` never waits (the driver answers with whatever is queued).
    pub fn stop(&self) {
        self.cancel.cancel();
    }
}

// The per-drain context: device handle, name cache, offset flag. The async
// run loop owns it.
struct DrainContext {
    device: HANDLE,
    names: HashMap<u32, String>,
    offset_captured: bool,
}

impl DrainContext {
    fn open() -> Result<Self, SourceError> {
        // SAFETY: plain device open; the driver validates all input.
        let device = unsafe {
            CreateFileW(
                DRIVER_PATH,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0),
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        }
        .map_err(|_| {
            SourceError::Stopped(
                r"driver device \\.\secoutfall not found — is the driver started?".to_owned(),
            )
        })?;
        if device.is_invalid() {
            return Err(SourceError::Stopped(
                r"driver device \\.\secoutfall not found — is the driver started?".to_owned(),
            ));
        }
        Ok(Self { device, names: HashMap::new(), offset_captured: false })
    }

    // Resolves a process name from the cache; unknown pids get a placeholder
    // (the scope tracker treats unknown names conservatively).
    fn name_for(&self, pid: u32) -> String {
        self.names.get(&pid).cloned().unwrap_or_else(|| "<unknown>".to_owned())
    }

    fn remember_name(&mut self, pid: u32, name: Option<String>) {
        if self.names.len() >= NAME_CACHE_CAP {
            self.names.clear(); // bounded: cheap reset, entries re-seed on create
        }
        self.names.insert(pid, name.unwrap_or_else(|| "<unnamed>".to_owned()));
    }
}

impl Drop for DrainContext {
    fn drop(&mut self) {
        // SAFETY: closing a kernel handle; no invariants beyond ownership.
        unsafe {
            let _ = CloseHandle(self.device);
        }
    }
}

// Maps one decoded record into zero or one SandboxEvent (always the
// `Source` shape; the drain loop re-wraps it as `SourceDated` with the
// record's kernel time). Records without a taxonomy home (DropCaptured for
// now) are logged, not dropped silently. Exhaustive mapping table, one arm
// per wire record — the too-many-lines exception matches the pattern used by
// `sample_for` in the payload crate.
#[allow(clippy::too_many_lines)]
fn map_record(record: &driver_wire::Record, context: &mut DrainContext) -> Option<SandboxEvent> {
    let pid = record.pid();
    let name_from = |value: Option<&String>| {
        value.map_or_else(
            || "<unknown>".to_owned(),
            |p| p.rsplit(['\\', '/']).next().unwrap_or(p).to_owned(),
        )
    };
    match record.payload() {
        driver_wire::Payload::ProcessCreated { parent_pid, command_line, image_name } => {
            let name = name_from(image_name.as_ref());
            context.remember_name(pid, Some(name.clone()));
            Some(SandboxEvent::Source(SourceEvent::ProcessStarted(ProcessStartedData {
                pid,
                parent_pid: Some(*parent_pid),
                name,
                image_path: image_name.clone(),
                command_line: command_line.clone(),
                os_session_id: None,
            })))
        }
        driver_wire::Payload::ProcessExited => {
            let name = context.name_for(pid);
            Some(SandboxEvent::Source(SourceEvent::ProcessStopped(ProcessStoppedData {
                pid,
                name,
            })))
        }
        driver_wire::Payload::Thread { thread_id } => {
            // The decoder collapses both thread kinds into one payload; the
            // record's kind carries the direction. Mapping unconditionally to
            // `ThreadStarted` published a `thread.started` for every thread
            // DEATH — the review found it.
            if record.kind() == driver_wire::RecordKind::ThreadExited {
                Some(SandboxEvent::Source(SourceEvent::ThreadStopped(ThreadStoppedData {
                    pid,
                    tid: *thread_id,
                })))
            } else {
                Some(SandboxEvent::Source(SourceEvent::ThreadStarted(ThreadStartedData {
                    pid,
                    tid: *thread_id,
                    parent_tid: None,
                })))
            }
        }
        driver_wire::Payload::ImageLoaded { name, .. } => {
            let resolved = name_from(name.as_ref());
            Some(SandboxEvent::Source(SourceEvent::ImageLoaded(ImageLoadedData {
                pid,
                name: resolved,
                image_path: name.clone(),
                image_size: None,
                image_checksum: None,
            })))
        }
        driver_wire::Payload::RegistryKeyCreated { path } => {
            Some(SandboxEvent::Source(SourceEvent::RegistryKeyCreated(RegistryKeyData {
                pid,
                key_name: path.clone(),
                key_handle: None,
            })))
        }
        driver_wire::Payload::RegistryKeyDeleted { path } => {
            Some(SandboxEvent::Source(SourceEvent::RegistryKeyDeleted(RegistryKeyData {
                pid,
                key_name: path.clone(),
                key_handle: None,
            })))
        }
        driver_wire::Payload::RegistrySetValue { key_path, value_name, data_type, data } => {
            Some(SandboxEvent::Source(SourceEvent::RegistryValueSet(RegistryValueSetData {
                pid,
                key_name: key_path.clone(),
                value_name: Some(value_name.clone()),
                key_handle: None,
                value_type: Some(registry_type_name(*data_type)),
                data_size: Some(u32::try_from(data.len()).unwrap_or(0)),
            })))
        }
        driver_wire::Payload::FileCreated { path } => {
            Some(SandboxEvent::Source(SourceEvent::FileCreated(FileCreatedData {
                pid,
                file_name: Some(path.clone()),
                file_object: None,
                create_options: None,
                create_disposition: None,
            })))
        }
        driver_wire::Payload::FileWritten { offset, bytes, path } => {
            Some(SandboxEvent::Source(SourceEvent::FileWritten(FileWrittenData {
                pid,
                file_object: None,
                file_key: None,
                file_name: Some(path.clone()),
                io_size: Some(u64::from(*bytes)),
                offset: Some(*offset),
            })))
        }
        driver_wire::Payload::FileCleanedUp { path } => {
            Some(SandboxEvent::Source(SourceEvent::FileCleanedUp(FileReleasedData {
                pid,
                file_object: None,
                file_key: None,
                file_name: Some(path.clone()),
            })))
        }
        driver_wire::Payload::FileDeleted { path } => {
            Some(SandboxEvent::Source(SourceEvent::FileDeleted(FileDeletedData {
                pid,
                file_object: None,
                file_key: None,
                file_name: Some(path.clone()),
            })))
        }
        driver_wire::Payload::FileRenamed { old_path, new_path } => {
            Some(SandboxEvent::Source(SourceEvent::FileRenamed(FileRenamedData {
                pid,
                file_object: None,
                file_name: Some(old_path.clone()),
                new_name: Some(new_path.clone()),
                file_key: None,
            })))
        }
        driver_wire::Payload::BehaviorCall { thread_id, api, arg0, arg1, arg2, arg3 } => {
            Some(SandboxEvent::Source(SourceEvent::BehaviorCall(BehaviorCallData {
                pid,
                tid: *thread_id,
                api: *api,
                arg0: *arg0,
                arg1: *arg1,
                arg2: *arg2,
                arg3: *arg3,
            })))
        }
        driver_wire::Payload::ProtectionEvent {
            protected_pid,
            target_is_thread,
            original_access,
            stripped_access,
            ..
        } => Some(SandboxEvent::Source(SourceEvent::ProtectionStripped(ProtectionStrippedData {
            opener_pid: pid,
            protected_pid: *protected_pid,
            target_is_thread: *target_is_thread,
            original_access: *original_access,
            stripped_access: *stripped_access,
        }))),
        driver_wire::Payload::DropCaptured { path, stored_name, method } => {
            // The driver has already preserved the content; routing these
            // into the drops-collector is not wired yet — log for now.
            tracing::info!(
                pid,
                path = %path,
                stored = %stored_name,
                method,
                "driver captured drop"
            );
            None
        }
    }
}

/// FILETIME (100 ns ticks since 1601-01-01 — what the kernel stamps in
/// `RecordHeader.Time`) to unix milliseconds, saturating. Ticks before the
/// unix epoch clamp to 0 (a pre-1970 kernel clock is garbage, not history).
#[must_use]
fn filetime_to_unix_ms(ticks: u64) -> i64 {
    const EPOCH_DIFF_100NS: u64 = 11_644_473_600_000_000_000; // 1601→1970
    const TICKS_PER_MS: u64 = 10_000;
    ticks
        .checked_sub(EPOCH_DIFF_100NS)
        .map_or(0, |unix_ticks| i64::try_from(unix_ticks / TICKS_PER_MS).unwrap_or(i64::MAX))
}

/// Registry value type names (REG_* from the winreg ABI) — formatting the
/// raw number put "REG_4"-style strings on the wire.
#[must_use]
fn registry_type_name(data_type: u32) -> String {
    match data_type {
        1 => "REG_SZ".to_owned(),
        2 => "REG_EXPAND_SZ".to_owned(),
        3 => "REG_BINARY".to_owned(),
        4 => "REG_DWORD".to_owned(),
        5 => "REG_DWORD_BIG_ENDIAN".to_owned(),
        6 => "REG_LINK".to_owned(),
        7 => "REG_MULTI_SZ".to_owned(),
        8 => "REG_RESOURCE_LIST".to_owned(),
        9 => "REG_FULL_RESOURCE_DESCRIPTOR".to_owned(),
        10 => "REG_RESOURCE_REQUIREMENTS_LIST".to_owned(),
        11 => "REG_QWORD".to_owned(),
        other => format!("REG_{other}"),
    }
}

#[async_trait]
impl crate::ports::driving::event_source::EventSourcePort for DriverEventSourceAdapter {
    async fn run(&self, inlet: Arc<dyn EventInletPort<SandboxEvent>>) -> Result<(), SourceError> {
        let mut context = DrainContext::open()?;
        let mut buffer = vec![0u8; DRAIN_BUFFER_SIZE];
        loop {
            let mut returned = 0u32;
            // SAFETY: OUT_DIRECT read; output size checked below.
            let ok = unsafe {
                DeviceIoControl(
                    context.device,
                    IOCTL_GET_DATA,
                    None,
                    0,
                    Some(buffer.as_mut_ptr().cast()),
                    u32::try_from(buffer.len()).unwrap_or(0),
                    Some(std::ptr::from_mut(&mut returned)),
                    None,
                )
            };
            if ok.is_err() {
                return Err(SourceError::Stopped("GET_DATA failed".to_owned()));
            }
            // The decoder is golden-pinned and panic-free on hostile bytes.
            // Per-record walk with drop+count: one malformed record costs
            // ITSELF (plus, when its size header is unusable, the rest of
            // the batch — there is no trustworthy boundary to resume from).
            // Never the whole 1 MiB drain, and never the run. The old
            // all-or-nothing `decode_all` turned one degenerate record into
            // mass telemetry loss.
            // `min` clamps a hostile/oversized `returned` to the buffer —
            // the API contract says it fits, but the lint cannot see that.
            let mut rest: &[u8] =
                buffer.get(..(returned as usize).min(buffer.len())).unwrap_or(&[]);
            let mut decoded: usize = 0;
            let mut skipped: usize = 0;
            while !rest.is_empty() {
                let size = driver_wire::record_size(rest);
                match (driver_wire::decode(rest), size) {
                    (Ok(record), Ok(size)) => {
                        // Lazy clock offset: the first drained record anchors
                        // real→fake; constant for the boot.
                        if !context.offset_captured {
                            let offset = self
                                .clock
                                .now_ms()
                                .saturating_sub(filetime_to_unix_ms(record.time()));
                            self.clock_offset_ms.store(offset, Ordering::Relaxed);
                            context.offset_captured = true;
                        }
                        let event_ts = filetime_to_unix_ms(record.time())
                            .saturating_add(self.clock_offset_ms.load(Ordering::Relaxed));
                        if let Some(SandboxEvent::Source(source_event)) =
                            map_record(&record, &mut context)
                        {
                            inlet.accept(SandboxEvent::SourceDated(source_event, event_ts)).await;
                        }
                        rest = rest.get(size..).unwrap_or_default();
                        decoded += 1;
                    }
                    // Unusable size: no trustworthy boundary to the next
                    // record — drop the rest of the batch.
                    (_, Err(_)) => {
                        skipped += 1;
                        tracing::warn!(
                            decoded,
                            skipped,
                            rest = rest.len(),
                            "driver drain: unusable record header, dropping batch remainder"
                        );
                        break;
                    }
                    // Decodable size but rejected payload: skip exactly this
                    // record (the size header still describes a trustworthy
                    // boundary) and keep going.
                    (Err(error), Ok(size)) => {
                        skipped += 1;
                        tracing::warn!(?error, size, "driver drain: record skipped");
                        rest = rest.get(size..).unwrap_or_default();
                    }
                }
            }
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => return Ok(()),
                () = tokio::time::sleep(DRAIN_INTERVAL) => {}
            }
        }
    }
}
