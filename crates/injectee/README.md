# injectee — SecOutfall sensor DLL

The in-process sensor of the [SecOutfall](../../README.md) sandbox: a Rust
`cdylib` injected into analyzed processes by the kernel driver. It registers
with the driver using a per-injection nonce (anti-impersonation), maps its
private event ring, and reports what the host process asks the operating
system to do by hooking ntdll-level APIs.

Hooks are **enrichment, not ground truth**: the driver's kernel callbacks
see everything anyway, and direct syscalls bypass user-mode hooks — sensor
silence is itself a scoring signal. The DLL is silent: nothing prints (a
GUI or service host has no console, and `println!` would panic).

> [!WARNING]
> DLL injection and API hooking are dual-use techniques. This project exists
> for education, security research, and testing your own software. Use it
> only on systems you own or are explicitly permitted to experiment with,
> and in compliance with applicable laws. The authors accept no liability
> for misuse.

## Lifecycle

1. `DllMain` spawns the init thread and returns immediately — the loader
   lock stays free, so nothing here can deadlock the host's loader.
2. The init thread (its body is `catch_unwind`-contained: a panic degrades
   the sensor, never the host) runs the handshake with the driver:
   `SENSOR_CHALLENGE` → map the offered ring section → `SENSOR_REGISTER`
   (one-shot, nonce-gated), with bounded retries.
3. It waits until the driver activates the sensor (the analyzed process is
   in scope), then installs every hook. Until then the DLL is inert.
4. Each hook emits `(api id, args[4])` into the lock-free ring; the driver
   drains it into `behavior.call` wire records with kernel-stamped identity.

## Survival rules

- No allocation and no panics on the emit path (bounded, lock-free,
  `fetch_add` slot claim; a full ring drops the record).
- `panic = "abort"` is deliberately NOT set — in a cdylib an abort kills the
  host process. Detours are `extern "system"`, so a panic there aborts at
  the FFI boundary regardless; the real rule is "hooks are written
  panic-free".
- Hook installation failures are collected and reported once; they never
  propagate into the host.

## The `hook!` macro

Hooks are declared with one macro built on
[retour](https://crates.io/crates/retour) static detours. The macro generates
the detour function, a handle to the original function, and an idempotent
`install()`:

```rust
crate::hook! {
    /// Reports delay calls, passes them through unchanged.
    in "ntdll.dll"!NtDelayExecution as NTDELAYEXECUTION_ORIGINAL
    fn ntdelayexecution_detour(alertable: u8, delay_interval: *const i64) -> i32 {
        crate::sensor::emit(
            crate::sensor::api::NT_DELAY_EXECUTION,
            [u64::from(alertable), delay_interval as u64, 0, 0],
        );
        unsafe { NTDELAYEXECUTION_ORIGINAL.call(alertable, delay_interval) }
    }
}
```

The grammar reads: hook `"module.dll"!Symbol`, expose the original function
as `ORIGINAL`, then the detour signature and body. The macro generates:

| Generated item     | Purpose                                                        |
| ------------------ | -------------------------------------------------------------- |
| `fn $name(...)`    | Your detour — called instead of the target                     |
| `static $original` | The original function — call it with `$original.call(...)`     |
| `fn install()`     | Resolves the export and enables the detour; safe to re-call    |

Rules of thumb:

- Signatures are plain Rust types; use raw pointers where the ABI has them.
  They must match the real export — the macro transmutes without checking.
- The `extern "system"` calling convention is assumed, which is correct for
  the Win32 API.
- Keep one hook per module: every hook module exposes `install`.
- The ring carries no strings — path/handle-derived classifications must
  become distinct api ids (`sensor::api`).

## Hook set

The id numbering (1–14) is reserved in all three mirrors at once —
`driver/secoutfall/secoutfallCommon.h`, `protocol::driver_wire`, and
`sensor::api` — so hooks can land one by one without ever inventing a
conflicting id.

Installed (v1):

| Id | Api | Why |
|----|-----|-----|
| 1 | `NtDelayExecution` | Evasion timing (long sleeps between stages) |
| 2 | `NtCreateFile` | File access the kernel telemetry can miss |
| 3 | `NtWriteFile` | Write sizes/patterns |
| 4 | `NtCreateThreadEx` | Thread creation from user mode |

Reserved for follow-up hooks: `NtDeleteFile` (5), `NtSetValueKey` (6) with
the sensor-classified Run-key variant (7), cross-process VM
allocate/write (8, 9), shadow-copy-delete variant (10), `LdrLoadDll` (11),
`CryptEncrypt` (12), `ShellExecuteEx` (13), `WinExec` (14).

## Build

The crate has its own nightly workspace (excluded from the repository's main
cargo workspace); the toolchain is pinned in `rust-toolchain.toml`:

```sh
cd crates/injectee
cargo build --locked
# -> target/debug/injectee.dll (release for deployment)
```

Win32 bindings are generated at build time by `windows-bindgen` (`build.rs`).
The driver injects the built DLL by path; the agent materializes a
per-boot copy under a DACL-protected directory and arms injection with its
verified NT path.

## Project layout

```text
src/
├── lib.rs           # DllMain (init thread only) + marker export
├── sensor.rs        # handshake, ring mapping, emit, reserved api ids
├── hooking.rs       # the framework: hook! macro, symbol resolution, installer
├── hooks/           # the v1 hook set (see table above)
├── ntapis.rs        # hand-written Nt* declarations
└── bindings.rs      # generated by windows-bindgen (build.rs)
```

## License

Licensed under either of

- [MIT license](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
