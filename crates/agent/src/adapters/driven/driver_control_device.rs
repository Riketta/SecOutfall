//! Real driver control adapter (feature `driver`): `DeviceIoControl` against
//! `\\.\secoutfall`. Serializes the structured policies into the driver's
//! input blobs and parses the stats reply (field offsets mirror
//! `DriverStats` in `secoutfallCommon.h` — natural x64 alignment:
//! 4-byte header trio, six ULONGs, then 8-aligned ULONG64s).

use std::collections::HashMap;

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
        System::IO::DeviceIoControl,
    },
    core::PCWSTR,
};

use crate::ports::driven::driver_control::{
    DriverControlError,
    DriverControlPort,
    DriverPolicies,
    DriverStatsSnapshot,
};

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

// CTL_CODE(DeviceType, Function, Method, Access) =
//   (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
const fn ctl_code(device: u32, function: u32, method: u32, access: u32) -> u32 {
    (device << 16) | (access << 14) | (function << 2) | method
}

const METHOD_OUT_DIRECT: u32 = 1;
const METHOD_BUFFERED: u32 = 0;
const FILE_READ_ACCESS: u32 = 1;
const FILE_WRITE_ACCESS: u32 = 2;

const IOCTL_GET_STATS: u32 = ctl_code(0x8000, 0x801, METHOD_OUT_DIRECT, FILE_READ_ACCESS);
const IOCTL_SET_DROP_POLICY: u32 = ctl_code(0x8000, 0x804, METHOD_BUFFERED, FILE_WRITE_ACCESS);
const IOCTL_SET_INJECTION_POLICY: u32 = ctl_code(0x8000, 0x805, METHOD_BUFFERED, FILE_WRITE_ACCESS);
const IOCTL_SET_PROTECTED: u32 = ctl_code(0x8000, 0x808, METHOD_BUFFERED, FILE_WRITE_ACCESS);
const IOCTL_SET_DEVICE_SECURITY: u32 = ctl_code(0x8000, 0x809, METHOD_BUFFERED, FILE_WRITE_ACCESS);

const DRIVER_PATH: PCWSTR = windows::core::w!(r"\\.\secoutfall");

/// Real adapter: one open device handle per instance; policies are
/// stateless sends.
pub struct DriverControlDevice {
    device: HANDLE,
}

impl DriverControlDevice {
    /// Opens the control device.
    ///
    /// # Errors
    /// [`DriverControlError::DeviceMissing`] when the device cannot be
    /// opened (driver not started, or access denied for non-elevated
    /// callers).
    pub fn open() -> Result<Self, DriverControlError> {
        // SAFETY: no unusual invariants — the driver validates all input.
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
        .map_err(|_| DriverControlError::DeviceMissing)?;
        Ok(Self { device })
    }

    fn send(&self, code: u32, payload: &[u8]) -> Result<(), DriverControlError> {
        let mut returned = 0u32;
        // SAFETY: buffered method; the driver validates all lengths.
        let ok = unsafe {
            DeviceIoControl(
                self.device,
                code,
                Some(payload.as_ptr().cast()),
                u32::try_from(payload.len()).unwrap_or(0),
                None,
                0,
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )
        };
        if ok.is_err() {
            Err(DriverControlError::Rejected(format!("ioctl {code:#x} failed")))
        } else {
            Ok(())
        }
    }
}

impl Drop for DriverControlDevice {
    fn drop(&mut self) {
        // SAFETY: closing a kernel handle; no invariants beyond ownership.
        unsafe {
            let _ = CloseHandle(self.device);
        }
    }
}

// NUL-terminated UTF-16 blob from a comma-separated list.
fn wide_list(names: &[String]) -> Vec<u8> {
    let mut blob = Vec::new();
    for name in names {
        for unit in name.encode_utf16() {
            blob.extend_from_slice(&unit.to_le_bytes());
        }
        blob.extend_from_slice(&0u16.to_le_bytes());
    }
    blob
}

fn wide_nul(s: &str) -> Vec<u8> {
    let mut blob: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob
}

// `DriverStats` field offsets (natural x64 alignment; see
// secoutfallCommon.h). Magic/Version/Reserved occupy 0..4.
const OFF_QUEUE_DEPTH: usize = 4;
const OFF_QUEUE_CAPACITY: usize = 8;
const OFF_FILE_QUEUE_DEPTH: usize = 12;
const OFF_FILE_QUEUE_CAPACITY: usize = 16;
const OFF_DROPS_QUEUE_DEPTH: usize = 20;
const OFF_DROPS_QUEUE_CAPACITY: usize = 24;
const OFF_SEQUENCE: usize = 32;
const OFF_QUEUE_OVERWRITTEN: usize = 40;
const OFF_ALLOC_FAILURES: usize = 48;
const OFF_OVERSIZED_SKIPPED: usize = 56;
const OFF_IDENTITY_MISSES: usize = 64;
const OFF_FILES_OVERWRITTEN: usize = 72;
const OFF_NAME_QUERIES_FAILED: usize = 80;
const OFF_NOISE_WRITES_SKIPPED: usize = 88;
const OFF_DROPS_STOPPED: usize = 96;
const OFF_DROPS_MISSED_BUSY: usize = 104;
const OFF_DROPS_LINK_FAILED: usize = 112;
const OFF_DROPS_COPY_FAILED: usize = 120;
const OFF_INJECTIONS_QUEUED: usize = 128;
const OFF_INJECTIONS_FAILED: usize = 136;
const OFF_SENSORS_REGISTERED: usize = 144;
const OFF_SENSORS_REJECTED: usize = 152;
const OFF_SENSOR_EVENTS_DRAINED: usize = 160;
const OFF_SENSOR_EVENTS_DROPPED: usize = 168;
const OFF_SENSOR_RINGS_ACTIVE: usize = 176;
const OFF_PROTECTIONS_STRIPPED: usize = 184;
const OFF_PROTECTION_TRUSTED: usize = 192;
const STATS_MIN_SIZE: usize = 200;

impl DriverControlPort for DriverControlDevice {
    fn apply_device_security(&self, sddl: &str) -> Result<(), DriverControlError> {
        use windows::Win32::{
            Foundation::{
                HLOCAL,
                LocalFree,
            },
            Security::{
                Authorization::{
                    ConvertStringSecurityDescriptorToSecurityDescriptorW,
                    SDDL_REVISION_1,
                },
                GetSecurityDescriptorLength,
                PSECURITY_DESCRIPTOR,
            },
        };

        // SDDL → self-relative SD (user-mode facility; the kernel blob takes
        // raw bytes). Converted fresh per call — the port may be called with
        // different SDDLs over a device's lifetime.
        let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        // SAFETY: out-pointers initialized by the API on success.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &windows::core::HSTRING::from(sddl),
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
        };
        if converted.is_err() || descriptor.0.is_null() {
            return Err(DriverControlError::Rejected(format!("bad device SDDL: {converted:?}")));
        }
        // SAFETY: the pointer is a valid descriptor allocated above.
        let sd_len = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
        // SAFETY: the descriptor memory is valid until LocalFree below;
        // slice it for the blob.
        let sd_bytes = unsafe { std::slice::from_raw_parts(descriptor.0.cast::<u8>(), sd_len) };

        let mut blob: Vec<u8> = Vec::with_capacity(8 + sd_bytes.len());
        blob.push(1); // Enabled (the driver rejects disable — it would
        // re-apply the compiled SDDL; the agent never disables).
        blob.extend_from_slice(&[0; 3]);
        blob.extend_from_slice(&u32::to_le_bytes(u32::try_from(sd_bytes.len()).unwrap_or(0)));
        blob.extend_from_slice(sd_bytes);
        // SAFETY: single free of the descriptor allocated above.
        unsafe { LocalFree(HLOCAL(descriptor.0.cast())) };

        self.send(IOCTL_SET_DEVICE_SECURITY, &blob)
    }

    fn apply_policies(&self, policies: &DriverPolicies) -> Result<(), DriverControlError> {
        // 1. Injection policy (armed when a sensor path is configured).
        if let Some(injection) = &policies.injection
            && !injection.sensor_path.is_empty()
        {
            let path = wide_nul(&injection.sensor_path);
            let exclusions = wide_list(&injection.exclusions);
            let mut blob: Vec<u8> = Vec::new();
            blob.push(1); // Enabled
            blob.extend_from_slice(&[0; 3]);
            blob.extend_from_slice(&u32::to_le_bytes(u32::try_from(path.len()).unwrap_or(0)));
            blob.extend_from_slice(&u32::to_le_bytes(u32::try_from(exclusions.len()).unwrap_or(0)));
            blob.extend_from_slice(&path);
            blob.extend_from_slice(&exclusions);
            self.send(IOCTL_SET_INJECTION_POLICY, &blob)?;
        }

        // 2. Drop policy (armed when a directory is configured).
        if let Some(drops) = &policies.drops
            && !drops.dir.is_empty()
        {
            let extensions = wide_list(&drops.extensions);
            let dir = wide_nul(&drops.dir);
            let mut blob: Vec<u8> = Vec::new();
            blob.push(1);
            blob.extend_from_slice(&[0; 3]);
            blob.extend_from_slice(&u32::to_le_bytes(u32::try_from(extensions.len()).unwrap_or(0)));
            blob.extend_from_slice(&u32::to_le_bytes(u32::try_from(dir.len()).unwrap_or(0)));
            blob.extend_from_slice(&extensions);
            blob.extend_from_slice(&dir);
            self.send(IOCTL_SET_DROP_POLICY, &blob)?;
        }

        // 3. Protection policy (armed when names are configured; an empty
        // list disarms).
        if let Some(protection) = &policies.protection {
            let names = wide_list(&protection.names);
            let mut blob: Vec<u8> = Vec::new();
            blob.push(u8::from(!protection.names.is_empty()));
            blob.extend_from_slice(&[0; 3]);
            blob.extend_from_slice(&u32::to_le_bytes(
                u32::try_from(protection.names.len()).unwrap_or(0),
            ));
            blob.extend_from_slice(&u32::to_le_bytes(u32::try_from(names.len()).unwrap_or(0)));
            blob.extend_from_slice(&names);
            self.send(IOCTL_SET_PROTECTED, &blob)?;
        }
        Ok(())
    }

    fn query_stats(&self) -> Result<DriverStatsSnapshot, DriverControlError> {
        let mut out = vec![0u8; 256];
        let mut returned = 0u32;
        // SAFETY: buffered method; output size validated below.
        let ok = unsafe {
            DeviceIoControl(
                self.device,
                IOCTL_GET_STATS,
                None,
                0,
                Some(std::ptr::from_mut(out.as_mut_slice()).cast()),
                u32::try_from(out.len()).unwrap_or(0),
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )
        };
        if ok.is_err() || (returned as usize) < STATS_MIN_SIZE {
            return Err(DriverControlError::Io("GET_STATS failed".to_owned()));
        }
        let u32_at = |at: usize| {
            let mut b = [0u8; 4];
            for (i, slot) in b.iter_mut().enumerate() {
                *slot = *out.get(at + i).unwrap_or(&0);
            }
            u32::from_le_bytes(b)
        };
        let u64_at = |at: usize| {
            let mut b = [0u8; 8];
            for (i, slot) in b.iter_mut().enumerate() {
                *slot = *out.get(at + i).unwrap_or(&0);
            }
            u64::from_le_bytes(b)
        };
        Ok(DriverStatsSnapshot {
            queue_depth: u32_at(OFF_QUEUE_DEPTH),
            queue_capacity: u32_at(OFF_QUEUE_CAPACITY),
            file_queue_depth: u32_at(OFF_FILE_QUEUE_DEPTH),
            file_queue_capacity: u32_at(OFF_FILE_QUEUE_CAPACITY),
            drops_queue_depth: u32_at(OFF_DROPS_QUEUE_DEPTH),
            drops_queue_capacity: u32_at(OFF_DROPS_QUEUE_CAPACITY),
            sequence: u64_at(OFF_SEQUENCE),
            queue_overwritten: u64_at(OFF_QUEUE_OVERWRITTEN),
            alloc_failures: u64_at(OFF_ALLOC_FAILURES),
            oversized_skipped: u64_at(OFF_OVERSIZED_SKIPPED),
            identity_misses: u64_at(OFF_IDENTITY_MISSES),
            files_overwritten: u64_at(OFF_FILES_OVERWRITTEN),
            file_name_queries_failed: u64_at(OFF_NAME_QUERIES_FAILED),
            noise_writes_skipped: u64_at(OFF_NOISE_WRITES_SKIPPED),
            drops_stopped: u64_at(OFF_DROPS_STOPPED),
            drops_missed_busy: u64_at(OFF_DROPS_MISSED_BUSY),
            drops_link_failed: u64_at(OFF_DROPS_LINK_FAILED),
            drops_copy_failed: u64_at(OFF_DROPS_COPY_FAILED),
            injections_queued: u64_at(OFF_INJECTIONS_QUEUED),
            injections_failed: u64_at(OFF_INJECTIONS_FAILED),
            sensors_registered: u64_at(OFF_SENSORS_REGISTERED),
            sensors_rejected: u64_at(OFF_SENSORS_REJECTED),
            sensor_events_drained: u64_at(OFF_SENSOR_EVENTS_DRAINED),
            sensor_events_dropped: u64_at(OFF_SENSOR_EVENTS_DROPPED),
            sensor_rings_active: u32_at(OFF_SENSOR_RINGS_ACTIVE),
            protections_stripped: u64_at(OFF_PROTECTIONS_STRIPPED),
            protection_trusted: u64_at(OFF_PROTECTION_TRUSTED),
        })
    }

    fn loss_counters(&self) -> Result<HashMap<String, u64>, DriverControlError> {
        let stats = self.query_stats()?;
        let mut map = HashMap::new();
        map.insert("queue_overwritten".to_owned(), stats.queue_overwritten);
        map.insert("alloc_failures".to_owned(), stats.alloc_failures);
        map.insert("oversized_skipped".to_owned(), stats.oversized_skipped);
        map.insert("identity_misses".to_owned(), stats.identity_misses);
        map.insert("files_overwritten".to_owned(), stats.files_overwritten);
        map.insert("file_name_queries_failed".to_owned(), stats.file_name_queries_failed);
        map.insert("noise_writes_skipped".to_owned(), stats.noise_writes_skipped);
        map.insert("drops_stopped".to_owned(), stats.drops_stopped);
        map.insert("drops_missed_busy".to_owned(), stats.drops_missed_busy);
        map.insert("drops_link_failed".to_owned(), stats.drops_link_failed);
        map.insert("drops_copy_failed".to_owned(), stats.drops_copy_failed);
        map.insert("injections_queued".to_owned(), stats.injections_queued);
        map.insert("injections_failed".to_owned(), stats.injections_failed);
        map.insert("sensors_registered".to_owned(), stats.sensors_registered);
        map.insert("sensors_rejected".to_owned(), stats.sensors_rejected);
        map.insert("sensor_events_drained".to_owned(), stats.sensor_events_drained);
        map.insert("sensor_events_dropped".to_owned(), stats.sensor_events_dropped);
        map.insert("protections_stripped".to_owned(), stats.protections_stripped);
        map.insert("protection_trusted".to_owned(), stats.protection_trusted);
        Ok(map)
    }
}
