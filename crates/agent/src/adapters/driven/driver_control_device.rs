//! Real driver control adapter (feature `driver`): `DeviceIoControl` against
//! `\\.\secoutfall`. The wire blobs and codes are PINNED in the port module
//! (fixture-tested against the C compiler's output) — this adapter only
//! opens the device, sends the pinned bytes and dispatches results.

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
    codes,
    decode_driver_stats,
    encode_device_security,
    encode_drop_policy,
    encode_injection_policy,
    encode_protection_policy,
};

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
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

// Blob serialization and the stats layout live in the PORT module
// (`ports::driven::driver_control`), pinned byte-exact against the C
// compiler's own fixtures — this adapter only opens the device, sends the
// pinned bytes and dispatches results.

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
        // The envelope is the pinned pure encoder; `sd_bytes` borrows the
        // descriptor, so encode BEFORE freeing it.
        let blob = encode_device_security(true, sd_bytes);
        // SAFETY: single free of the descriptor allocated above.
        unsafe { LocalFree(HLOCAL(descriptor.0.cast())) };

        self.send(codes::SET_DEVICE_SECURITY, &blob)
    }

    fn apply_policies(&self, policies: &DriverPolicies) -> Result<(), DriverControlError> {
        // 1. Injection policy (armed when a sensor path is configured).
        if let Some(injection) = &policies.injection
            && !injection.sensor_path.is_empty()
        {
            self.send(codes::SET_INJECTION_POLICY, &encode_injection_policy(injection))?;
        }

        // 2. Drop policy (armed when a directory is configured).
        if let Some(drops) = &policies.drops
            && !drops.dir.is_empty()
        {
            self.send(codes::SET_DROP_POLICY, &encode_drop_policy(drops))?;
        }

        // 3. Protection policy (armed when names are configured; an empty
        // list disarms — and the disarm blob must pass the driver's length
        // check too, which the old hand-rolled 12-byte header never did).
        if let Some(protection) = &policies.protection {
            self.send(codes::SET_PROTECTED, &encode_protection_policy(protection))?;
        }
        Ok(())
    }

    fn query_stats(&self) -> Result<DriverStatsSnapshot, DriverControlError> {
        let mut out = vec![0u8; 256];
        let mut returned = 0u32;
        // SAFETY: buffered method; output size validated in the decoder.
        let ok = unsafe {
            DeviceIoControl(
                self.device,
                codes::GET_STATS,
                None,
                0,
                Some(out.as_mut_ptr().cast()),
                u32::try_from(out.len()).unwrap_or(0),
                Some(std::ptr::from_mut(&mut returned)),
                None,
            )
        };
        if ok.is_err() {
            return Err(DriverControlError::Io("GET_STATS failed".to_owned()));
        }
        // The pinned decoder validates magic/version/length and applies the
        // fixture-tested field order (the review found five fields swapped).
        // `min` clamps a hostile/large `returned` to the buffer — the lint
        // cannot see the API contract.
        let n = usize::try_from(returned).unwrap_or(0).min(out.len());
        decode_driver_stats(out.get(..n).unwrap_or(&[]))
    }
}
