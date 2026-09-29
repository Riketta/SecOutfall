# injectee

A minimal Windows API hooking framework and DLL-injection testbed, written in Rust.

`injectee` is a `cdylib`: once loaded into a process, it installs detours on
Windows API functions and logs what the process asks the operating system to
do. The framework itself is a single declarative macro (`hook!`) built on
[retour](https://crates.io/crates/retour) static detours. The hooks in
`src/hooks/` are working examples — and double as the framework's test suite.

> [!WARNING]
> DLL injection and API hooking are dual-use techniques. This project exists
> for education, security research, and testing your own software. Use it only
> on systems you own or are explicitly permitted to experiment with, and in
> compliance with applicable laws. The authors accept no liability for misuse.

## Features

- **`hook!` macro** — declare a detour in a few lines; the macro generates the
  detour function, a handle to the original function, and an idempotent
  `install()` function.
- **Symbol resolution** — hook any export of any loaded module
  (`"module.dll"!Export`), resolved at install time via `GetProcAddress`.
- **Batch installer** — installs every registered hook and collects all
  failures instead of stopping at the first one.
- **Executable examples** — `kernel32!Sleep` and `ntdll!NtDelayExecution`
  hooks, verified by tests against real system calls.

## Requirements

- Windows (developed and tested on x64)
- Rust nightly — pinned in `rust-toolchain.toml`, installed automatically by
  `rustup`

## Build

```sh
cargo build --release
```

The library is written to `target\release\injectee.dll`.

## Usage

1. Load `injectee.dll` into a target process with any standard injector that
   calls `LoadLibraryW` (e.g. System Informer's *Inject DLL*, or your own
   loader).
2. On `DLL_PROCESS_ATTACH` the demo entry point:
   - allocates a console and shows the host process ID in a message box,
   - installs every hook registered in `src/hooks/mod.rs`,
   - starts `calc.exe` (remove that from `attach()` in `src/lib.rs` if you
     don't want it).
3. Hook output appears on the allocated console:

   ```text
   Hooking kernel32.dll!Sleep.
   Expected sleep time: 5000.
   Sleep: 100 ms.
   ```

   Beware that the example hooks alter host behavior by design: while active,
   every `Sleep` call in the host lasts one second regardless of the requested
   duration.

The library also exports `some_export`, a no-op marker function useful for
testing `GetProcAddress`-based loaders.

## Writing a hook

Hooks live in `src/hooks/`, one module per hook:

```rust
// src/hooks/myhook.rs
crate::hook! {
    /// Logs relative delays before passing them through unchanged.
    in "ntdll.dll"!NtDelayExecution as NT_DELAY_EXECUTION_ORIGINAL
    fn nt_delay_execution_detour(alertable: bool, delay_interval: *const i64) -> i32 {
        // Negative - relative, positive - absolute timestamp.
        if unsafe { *delay_interval } < 0 {
            println!("Delaying...");
        }

        unsafe { NT_DELAY_EXECUTION_ORIGINAL.call(alertable, delay_interval) }
    }
}
```

The grammar reads: hook `"module.dll"!Symbol`, expose the original function as
`ORIGINAL`, then the detour signature and body. The macro generates:

| Generated item         | Purpose                                                                 |
| ---------------------- | ----------------------------------------------------------------------- |
| `fn $name(...)`        | Your detour — called instead of the target                               |
| `static $original`     | The original function — call it with `$original.call(...)`               |
| `fn install()`         | Resolves the export and enables the detour; safe to call more than once  |

Register the hook in `src/hooks/mod.rs` (hooks are installed top to bottom):

```rust
mod myhook;

pub(crate) fn install_all() -> anyhow::Result<()> {
    crate::hooking::install_all(&[
        ntdelayexecution::install,
        sleep::install,
        myhook::install,
    ])
}
```

Rules of thumb:

- Signatures are plain Rust types; use raw pointers where the ABI has them.
  They must match the real export — the macro transmutes without checking.
- The `extern "system"` calling convention is assumed, which is correct for
  the Win32 API.
- Keep one hook per module: every hook module exposes `install`.

## How it works

`install()` resolves the export address with `GetModuleHandleW` +
`GetProcAddress`, transmutes it to the declared function type, and hands it to
a retour `static_detour`, which patches the function's first instructions with
a jump to your detour. Calling `$original.call(...)` goes through retour's
trampoline — a copy of the patched prologue — so the original code runs
untouched. See `src/hooking.rs`; the whole framework fits in one file.

## Testing

```sh
cargo test
```

The example-hook tests install real detours inside the test process and assert
their effect — e.g. a `Sleep(3000)` must return in about a second while the
hook is active. Everything is process-local and gone once the process exits.

Two tests are `#[ignore]`d because they need the built DLL or manual
interaction:

- `test_get_proc_address_self` — resolves this crate's own export; the test
  executable exports no symbols, so it only works in the injected DLL
- `test_self_injection` — blocks on a message box, and `force_unload` is
  still a stub

Run them explicitly with `cargo test -- --ignored`.

## Project layout

```text
src/
├── lib.rs                  # DllMain entry point + integration tests
├── hooking.rs              # the framework: hook! macro, symbol resolution, installer
├── hooks/
│   ├── mod.rs              # example hook registry
│   ├── sleep.rs            # example: kernel32!Sleep
│   └── ntdelayexecution.rs # example: ntdll!NtDelayExecution
├── utils.rs                # small Win32 helpers (message box)
└── bindings.rs             # generated by windows-bindgen (build.rs)
```

## Status

Early-stage playground project. Not done yet:

- `force_unload` and `hide_self` (`src/lib.rs`) are unimplemented stubs
- no runtime hook removal/disable management
- no automatic hook registration — hooks are listed in one place

## License

Licensed under either of

- [MIT license](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
