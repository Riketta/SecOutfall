//! Sensor client: handshake with the driver, map the shared ring, and emit
//! hooked-API events.
//!
//! Contract (mirrored from `driver/secoutfall/secoutfallCommon.h` — the C
//! side pins the kernel↔agent wire via golden fixtures; this handshake is
//! pinned by the self-check tests below and by the kernel's own validation:
//! every challenge is ledger-gated and every slot is sequence-validated, so
//! a drifted mirror can only fail closed, never poison the driver):
//!
//!   SENSOR_CHALLENGE -> nonce + duplicated ring section handle + geometry
//!   map ring         -> read-write view of the section
//!   SENSOR_REGISTER  -> echo the nonce; the driver flips the ring active
//!   emit             -> claim a slot (InterlockedAdd), write the payload,
//!                       commit the slot sequence (Vyukov-style)
//!
//! Survival rules: the emit path allocates nothing, takes no locks, and has
//! no panic paths — a hook must never slow down or crash its host process.
//! The kernel validates every slot and stamps its own authoritative
//! pid/identity/sequence/time, so this side can be wrong, but never poison.

#![allow(clippy::module_name_repetitions, clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_lossless, clippy::ptr_as_ptr, clippy::borrow_as_ptr, clippy::cast_ptr_alignment, clippy::doc_markdown)]

use std::sync::atomic::{AtomicI64, AtomicPtr, AtomicU32, Ordering};
use std::time::Duration;

use crate::ntapis::{
    CloseHandle, CreateFileW, DeviceIoControl, GetCurrentThreadId, MapViewOfFile, UnmapViewOfFile,
    FILE_MAP_READ, FILE_MAP_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ,
    GENERIC_WRITE, HANDLE, OPEN_EXISTING,
};

const DEVICE_PATH: &[u16] = &[
    0x5C, 0x5C, 0x2E, 0x5C, // \\.\ 
    0x73, 0x65, 0x63, 0x6F, 0x75, 0x74, 0x66, 0x61, 0x6C, 0x6C, 0x00, // secoutfall\0
];

const IOCTL_SENSOR_CHALLENGE: u32 = IOCTL_SECOUTFALL_SENSOR_CHALLENGE;
const IOCTL_SENSOR_REGISTER: u32 = IOCTL_SECOUTFALL_SENSOR_REGISTER;

// IOCTL codes — pinned to the C compiler's macro expansion
// (driver/tests/emit_codes.txt; see the agent's ports::driven::driver_control::codes).
// The review-era hand derivation here dropped the access bits and set junk
// low bits: (0x8000<<16)|(0x806<<2)|1 = 0x80002019 where the driver expects
// 0x80006018 — the handshake would have failed against the real device.
// CTL_CODE(0x8000, fn, METHOD_BUFFERED, access) with access pre-shifted:
const IOCTL_SECOUTFALL_SENSOR_CHALLENGE: u32 = 0x8000_6018; // fn 0x806, FILE_READ_ACCESS
const IOCTL_SECOUTFALL_SENSOR_REGISTER: u32 = 0x8000_A01C; // fn 0x807, FILE_WRITE_ACCESS

#[repr(C)]
#[derive(Clone, Copy)]
struct ChallengeOut {
    nonce: u64,
    ring_handle: HANDLE,
    ring_size: u32,
    slot_size: u32,
    slot_count: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RegisterIn {
    nonce: u64,
    version: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RingControl {
    state: i32,
    slot_size: u32,
    slot_count: u32,
    write_index: i64,
    dropped: i64,
}

const RING_CONTROL_SIZE: usize = std::mem::size_of::<RingControl>();
const SLOT_PAYLOAD_SIZE: usize = 40; // Api + ThreadId + Arg[4]
const SLOT_STRIDE: usize = 8 + SLOT_PAYLOAD_SIZE; // committed sequence + payload

// The mapped ring (set once at handshake, never unmapped — process-lifetime).
static RING: AtomicPtr<RingControl> = AtomicPtr::new(std::ptr::null_mut());
static SENSOR_VERSION: AtomicU32 = AtomicU32::new(1);

/// Behavior API ids (mirror of the driver's `BehaviorApi`; see the protocol
/// crate's `behavior_api` for the authoritative values). Ids 7/8/9/10 are
/// sensor-classified variants: the ring carries no strings, so path- or
/// handle-derived signals must become distinct ids at the hook itself.
/// Hook ids land here BEFORE their hooks exist (the numbering is reserved
/// in all three mirrors at once), so a future hook cannot invent a
/// conflicting value — hence the deliberate dead-code allowance.
#[allow(dead_code)]
pub mod api {
    pub const NT_DELAY_EXECUTION: u32 = 1;
    pub const NT_CREATE_FILE: u32 = 2;
    pub const NT_WRITE_FILE: u32 = 3;
    pub const NT_CREATE_THREAD_EX: u32 = 4;
    pub const NT_DELETE_FILE: u32 = 5;
    pub const NT_SET_VALUE_KEY: u32 = 6;
    pub const NT_SET_VALUE_KEY_RUN_KEY: u32 = 7;
    pub const NT_ALLOCATE_VM_CROSS_PROCESS: u32 = 8;
    pub const NT_WRITE_VM_CROSS_PROCESS: u32 = 9;
    pub const NT_DELETE_FILE_SHADOW_COPY: u32 = 10;
    pub const LDR_LOAD_DLL: u32 = 11;
    pub const CRYPT_ENCRYPT: u32 = 12;
    pub const SHELL_EXECUTE_EX: u32 = 13;
    pub const WIN_EXEC: u32 = 14;
}

fn open_device() -> Result<HANDLE, ()> {
    let handle = unsafe {
        CreateFileW(
            DEVICE_PATH.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() {
        Err(())
    } else {
        Ok(handle)
    }
}

fn ioctl(
    device: HANDLE,
    code: u32,
    in_buf: Option<(*const u8, u32)>,
    out_buf: Option<(*mut u8, u32)>,
) -> Result<(), ()> {
    let mut returned = 0u32;
    let (in_ptr, in_size) = in_buf.unwrap_or((std::ptr::null(), 0));
    let (out_ptr, out_size) = out_buf.unwrap_or((std::ptr::null_mut(), 0));
    let ok = unsafe {
        DeviceIoControl(
            device,
            code,
            in_ptr.cast(),
            in_size,
            out_ptr.cast(),
            out_size,
            &mut returned,
            std::ptr::null(),
        )
    };
    if ok != 0 {
        Ok(())
    } else {
        Err(())
    }
}

// One handshake attempt: challenge -> map -> register. The driver answers
// the challenge exactly once per pid, so a second attempt fails by design.
fn handshake() -> Result<(), ()> {
    let device = open_device()?;

    let mut challenge = ChallengeOut {
        nonce: 0,
        ring_handle: std::ptr::null_mut(),
        ring_size: 0,
        slot_size: 0,
        slot_count: 0,
        reserved: 0,
    };
    let challenge_result = ioctl(
        device,
        IOCTL_SENSOR_CHALLENGE,
        None,
        Some((
            std::ptr::addr_of_mut!(challenge).cast(),
            std::mem::size_of::<ChallengeOut>() as u32,
        )),
    );
    if challenge_result.is_err() {
        unsafe {
            let _ = CloseHandle(device);
        }
        return Err(());
    }

    // Map the ring (all of it — the geometry from the challenge defines the
    // control block + slot area).
    let ring = unsafe {
        MapViewOfFile(
            challenge.ring_handle,
            FILE_MAP_READ | FILE_MAP_WRITE,
            0,
            0,
            usize::try_from(challenge.ring_size).unwrap_or(0),
        )
        .cast::<RingControl>()
    };
    unsafe {
        let _ = CloseHandle(challenge.ring_handle);
    }
    if ring.is_null() {
        unsafe {
            let _ = CloseHandle(device);
        }
        return Err(());
    }

    let register = RegisterIn {
        nonce: challenge.nonce,
        version: SENSOR_VERSION.load(Ordering::Relaxed),
        reserved: 0,
    };
    let register_result = ioctl(
        device,
        IOCTL_SENSOR_REGISTER,
        Some((
            std::ptr::from_ref(&register).cast(),
            std::mem::size_of::<RegisterIn>() as u32,
        )),
        None,
    );
    unsafe {
        let _ = CloseHandle(device);
    }
    if register_result.is_err() {
        unsafe {
            let _ = UnmapViewOfFile(ring.cast());
        }
        return Err(());
    }

    // Geometry sanity: the mirror only understands this layout.
    let control = ring.cast::<RingControl>();
    let (slot_size, slot_count) = unsafe {
        (
            std::ptr::read_volatile(std::ptr::addr_of!((*control).slot_size)) as usize,
            std::ptr::read_volatile(std::ptr::addr_of!((*control).slot_count)) as usize,
        )
    };
    if slot_size != SLOT_PAYLOAD_SIZE || slot_count == 0 || slot_count.count_ones() != 1 {
        unsafe {
            let _ = UnmapViewOfFile(ring.cast());
        }
        return Err(());
    }

    RING.store(control, Ordering::Release);
    Ok(())
}

// Waits until the driver flips the ring active (lazy activation). Bounded:
// a sensor that never activates stays idle and harmless.
fn wait_active(max_wait: Duration) -> bool {
    let deadline = std::time::Instant::now() + max_wait;
    loop {
        let ring = RING.load(Ordering::Acquire);
        if !ring.is_null() {
            let state = unsafe { std::ptr::read_volatile(std::ptr::addr_of!((*ring).state)) };
            if state == 1 {
                return true;
            }
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Emits one hooked-API event into the ring. Allocation-free, lock-free,
/// panic-free: claims a slot, writes the fixed payload, commits the slot
/// sequence. A full ring loses the event (counted producer-side); the kernel
/// validates every slot it reads.
pub fn emit(api: u32, args: [u64; 4]) {
    let ring = RING.load(Ordering::Acquire);
    if ring.is_null() {
        return;
    }
    unsafe {
        if std::ptr::read_volatile(std::ptr::addr_of!((*ring).state)) != 1 {
            return;
        }
        let write_index = AtomicI64::from_ptr(std::ptr::addr_of_mut!((*ring).write_index));
        let claimed = write_index.fetch_add(1, Ordering::Relaxed);

        let slot_count =
            std::ptr::read_volatile(std::ptr::addr_of!((*ring).slot_count)) as i64;
        let slots = (ring as *mut u8).add(RING_CONTROL_SIZE);
        let slot = slots.add((claimed.rem_euclid(slot_count) as usize) * SLOT_STRIDE);
        let slot_seq = AtomicI64::from_ptr(slot.cast::<i64>());

        // Overflow accounting: if this slot still holds a RECENT committed
        // record, the ring is full and our write destroys an undrained one.
        let previous = slot_seq.load(Ordering::Acquire);
        if previous != 0 && claimed - (previous - 1) >= slot_count {
            let dropped = AtomicI64::from_ptr(std::ptr::addr_of_mut!((*ring).dropped));
            dropped.fetch_add(1, Ordering::Relaxed);
        }

        let payload = slot.add(8);
        std::ptr::write_volatile(payload as *mut u32, api);
        std::ptr::write_volatile(payload.add(4) as *mut u32, GetCurrentThreadId());
        for (index, value) in args.iter().enumerate() {
            std::ptr::write_volatile(payload.add(8 + index * 8) as *mut u64, *value);
        }
        slot_seq.store(claimed + 1, Ordering::Release);
    }
}

/// The sensor's init-thread body: handshake (bounded retries), wait for
/// lazy activation, then install the hook set. Never returns — the thread
/// lives as long as the host process.
pub fn run() {
    for _ in 0..3 {
        if handshake().is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    if RING.load(Ordering::Acquire).is_null() {
        return; // idle sensor: the kernel's own telemetry is unaffected
    }
    if !wait_active(Duration::from_secs(30)) {
        return;
    }
    if crate::hooks::install_all().is_err() {
        // Silent by design: no console in a host process, and the kernel's
        // own callbacks remain ground truth.
        return;
    }
    // Hooks installed; the detours emit on their own. Park this thread.
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirror_layout_matches_the_documented_contract() {
        // Handshake mirrors (C layout: nonce, HANDLE, four u32s).
        assert_eq!(std::mem::size_of::<ChallengeOut>(), 32);
        assert_eq!(std::mem::offset_of!(ChallengeOut, ring_handle), 8);
        assert_eq!(std::mem::offset_of!(ChallengeOut, ring_size), 16);
        assert_eq!(std::mem::offset_of!(ChallengeOut, slot_count), 24);
        assert_eq!(std::mem::size_of::<RegisterIn>(), 16);

        // Ring control block.
        assert_eq!(RING_CONTROL_SIZE, 32);
        assert_eq!(SLOT_STRIDE, 48);
        assert_eq!(std::mem::offset_of!(RingControl, write_index), 16);
        assert_eq!(std::mem::offset_of!(RingControl, dropped), 24);
    }

    #[test]
    fn device_path_is_the_expected_pipe() {
        let expected: Vec<u16> = r"\\.\secoutfall".encode_utf16().chain(std::iter::once(0)).collect();
        assert_eq!(DEVICE_PATH, expected.as_slice());
    }
}
