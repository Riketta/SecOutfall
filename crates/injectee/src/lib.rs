//! secoutfall sensor DLL: injected into processes by the kernel driver,
//! registers with a per-injection nonce (anti-impersonation), maps its
//! private event ring, and reports hooked-API activity once activated.
//!
//! Survival rules: `DllMain` does nothing but spawn the init thread (loader
//! lock stays free); the `emit` path allocates nothing and never panics; hook
//! failures are silent (the kernel's own callbacks remain ground truth).
//!
//! Dual-licensed MIT OR Apache-2.0.

// Generated + ABI layers: Win32 naming is intentional there.
#[allow(non_snake_case, non_camel_case_types, unused, clippy::upper_case_acronyms, clippy::doc_markdown)]
mod bindings;
pub(crate) mod hooking;
pub(crate) mod hooks;
#[allow(non_snake_case, non_camel_case_types, unused)]
mod ntapis;
pub(crate) mod sensor;

/// Marker export for injectors that verify the load via `GetProcAddress`.
#[unsafe(no_mangle)]
pub extern "system" fn some_export() {
    std::hint::black_box(());
}

/// `DllMain`: spawn the init thread and return immediately. The thread starts
/// after the loader lock is released, so nothing here can deadlock the
/// loader. The thread lives as long as the host process.
///
/// The init body is `catch_unwind`-contained: a panic on this thread degrades
/// the SENSOR, never the host. The doctrine's earlier `panic = "abort"` was
/// deliberately NOT set — in a cdylib an abort kills the analyzed process,
/// and hooks are enrichment (kernel callbacks remain ground truth; sensor
/// silence is itself a signal). Detour frames are `extern "system"`: a panic
/// there aborts at the FFI boundary regardless of profile, so the real rule
/// is "hooks are written panic-free" — enforced by review, not by unwind.
#[unsafe(no_mangle)]
extern "system" fn DllMain(_dll_module: *mut core::ffi::c_void, call_reason: u32, _reserved: *mut core::ffi::c_void) -> bool {
    // DLL_PROCESS_ATTACH == 1.
    if call_reason == 1 {
        std::thread::spawn(|| {
            // AssertUnwindSafe: the sensor's state is process-lifetime and
            // single-shot; a panic mid-handshake leaves the ring unmapped,
            // which every downstream path already treats as "idle sensor".
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(sensor::run));
        });
    }
    true
}
