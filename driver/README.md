# secoutfall driver

Kernel-mode driver (WDM control device + minifilter in one `.sys`, C) — the
sandbox's trusted component. It starts before services and malware on every
boot and provides:

- **Telemetry** — process (native create-time command line), thread,
  image-load, registry (create/delete/set-value under HKLM), and file
  (created / written / cleaned-up / deleted / renamed) events as versioned
  wire records: magic + version, u32 sizes, capped strings with truncation
  flags, per-boot monotonic sequence, process identity = (pid, witnessed
  creation time).
- **Drop capture** — a hard-link tombstone at the first matching write keeps
  the final content alive across truncate/overwrite/delete; stream-copy
  fallback at cleanup; extension policy + drops directory pushed from the
  agent (`SET_DROP_POLICY`). Content dedup stays in the agent's
  drops-collector.
- **Injection engine** — user-APC injection of the sensor DLL at process
  create (`ntdll!LdrLoadDll` resolved by a kernel-side export walk), guarded
  by an injection ledger and a per-injection nonce handshake
  (`SENSOR_CHALLENGE` / `SENSOR_REGISTER`). Sensor events arrive over a
  per-sensor kernel-mapped ring and are drained as `behavior.call` records.
- **Self-protection** — ObCallbacks strip dangerous access rights
  (terminate / VM write / VM read / create-thread, and thread equivalents)
  for protected process images (`SET_PROTECTED`); every stripped handle is
  reported as an attribution record.
- **Loss accounting** — bounded per-class queues (overwrite-oldest for
  control-class telemetry, stop-collect for drops) with per-class counters
  surfaced via `GET_STATS`.

Events are drained over one IOCTL on a SDDL-secured device (SYSTEM +
Administrators only). The agent consumes the same wire
(`protocol::driver_wire` in the repo's `protocol` crate).

Adapted from the WKP SysMon sample (Pavel Yosifovich, *Windows Kernel
Programming*).

## Wire contract

`secoutfall/secoutfallCommon.h` is the authority for the record wire, the
control-plane IOCTL codes, and every policy-blob / stats layout. The Rust
side mirrors it in `protocol::driver_wire` and
`agent::ports::driven::driver_control::codes`, and both sides are pinned
byte-for-byte by the committed fixtures in `tests/`:

- `golden_v2.bin` — one of every wire record kind (decoder golden test).
- `emit_codes.txt` — the C preprocessor's own `CTL_CODE` expansions.
- `emit_{injection,drops,protection,security,stats,minimal-rename}.bin` —
  policy blobs and stats layouts with distinct canary values per field.

`wiretest.exe` (below) regenerates all of them. **Any change to
`secoutfallCommon.h` must regenerate the fixtures and update the Rust
mirrors in the same commit** — the golden tests on both sides must agree.
Never hand-derive a CTL code or struct layout; use the formula in
`driver_control::codes` and compare against `emit_codes.txt`.

## Layout

- `secoutfall/` — the driver (`secoutfall.sys`, device `\Device\secoutfall`,
  symlink `\??\secoutfall`, minifilter altitude `389910.02`).
- `dump/` — console dumper (`dump.exe`): opens `\\.\secoutfall`, drains and
  pretty-prints events plus the loss counters (prints whenever a counter
  moves). Control-class telemetry only — the file-telemetry class stays
  silent until its watch filter is pushed (`SET_FILE_WATCH`), which is the
  agent's job.
- `wiretest/` — fixture generator: `--emit <name>` writes the control-plane
  fixtures from the real C structs/macros; `--verify <file>` checks a golden
  wire file against the live decoder.
- `tests/` — the committed golden fixtures the Rust tests assert against.
- `build.ps1` — builds all three projects (x64, Debug or Release) with
  MSBuild.
- `install.ps1` — registers the kernel service + the Filter Manager instance
  the minifilter attaches through; `-Start` boots it, `-Remove` undoes
  everything.
- `sign.ps1` — creates a self-signed code-signing certificate, exports the
  public `.cer`, test-signs the driver.

## Prerequisites

- Visual Studio 2022 (MSBuild, v143) with the C++ workload.
- Windows Driver Kit **10.0.26100** — the `WindowsKernelModeDriver10.0`
  toolset must appear under the VS MSBuild `PlatformToolsets` (the WDK
  installer deploys it automatically).
- `signtool.exe` (ships with the Windows SDK, already part of a WDK install).

CI installs both kits via winget (`Microsoft.WindowsSDK.10.0.26100` +
`Microsoft.WindowsWDK.10.0.26100`) — see `.github/workflows/ci.yml`.

## Build

```powershell
cd driver
.\build.ps1 -Configuration Release
# -> secoutfall\x64\Release\secoutfall.sys
# -> dump\x64\Release\dump.exe
# -> wiretest\x64\Release\wiretest.exe
```

## Sign (test-signing)

```powershell
.\sign.ps1
# creates CN=SecOutfall Test Driver in the user store on first run,
# exports secoutfall-test.cer, signs secoutfall.sys
```

## Lab VM one-time prep

1. Secure Boot **off** (test-signed drivers will not load otherwise).
2. Memory integrity (HVCI) **off**.
3. `bcdedit /set testsigning on`, reboot (desktop shows "Test Mode").
4. Import the certificate (from the dev box, after `sign.ps1`):
   ```bat
   certutil -addstore Root secoutfall-test.cer
   certutil -addstore TrustedPublisher secoutfall-test.cer
   ```

## Install, observe, unload

```bat
:: elevated console (dev box built Release):
install.ps1 -Start

:: drain and pretty-print events + loss counters:
dump\x64\Release\dump.exe

install.ps1 -Remove
```

Kernel-side traces go through `KdPrint` (visible in DebugView with "Capture
kernel" enabled, or a kernel debugger).

## Notes and limitations

- x64 only; requires Windows 10 2004+ (`ExAllocatePool2`).
- Writes of exactly {4096, 8192, 16384} bytes at a non-zero offset are
  skipped as operating-system cache noise (counted).
- PPL targets tolerate injection failure by design: the kernel-side
  allocation works, the in-target `LdrLoadDll` fails code-integrity checks —
  harmless, counted.
- The lab altitude and test-signing posture are for lab VMs only; a real
  minifilter altitude assignment and production certificate are needed to
  leave the lab.
