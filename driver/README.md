# secoutfall driver

Kernel-mode telemetry driver (WDM, C) — the sandbox's trusted early event
source. D0 skeleton: process / thread / registry-set-value callbacks feeding
a bounded in-kernel queue, drained by a user-mode client over one IOCTL.

Adapted from the WKP SysMon sample (Pavel Yosifovich, *Windows Kernel
Programming*). Hardening applied so far: secure device creation (SDDL:
SYSTEM + Administrators only), clamped command-line capture, clamped registry
name copies, `ExAllocatePool2` allocations, `/INTEGRITYCHECK` linked image.
The full hardening list and phase plan (D0–D5) live in the repo `AGENTS.md`.

## Layout

- `secoutfall/` — the driver (`secoutfall.sys`, device `\Device\secoutfall`,
  symlink `\??\secoutfall`).
- `dump/` — console dumper (`dump.exe`): opens `\\.\secoutfall`, drains and
  pretty-prints events.
- `build.ps1` — builds both projects (x64, Debug or Release) with MSBuild.
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

## Load, observe, unload

```bat
sc create secoutfall type= kernel start= demand binPath= C:\path\to\secoutfall.sys
sc start secoutfall

:: elevated console:
dump\x64\Release\dump.exe

sc stop secoutfall
sc delete secoutfall
```

Kernel-side traces go through `KdPrint` (visible in DebugView with "Capture
kernel" enabled, or a kernel debugger).

## D0 limitations (by design, resolved in later phases)

- Wire format is the unversioned WKP layout with `short` sizes — command
  lines are clamped to 8 KiB; D1 replaces it with the versioned schema
  mirrored into the `protocol` crate.
- Registry event names are clamped into fixed buffers (the base's
  unbounded `memcpy` overflow is fixed); D1's wire rework supersedes this.
- Queue overflow (256 items) drops oldest silently — D1 adds per-class loss
  counters and split queues; D2+ moves flood-class events to a shared-memory
  ring.
- x64 only; requires Windows 10 2004+ (`ExAllocatePool2`).
- Image-load events and the minifilter (file telemetry, drop capture) are D1/D2.
