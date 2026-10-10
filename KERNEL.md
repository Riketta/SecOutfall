# KERNEL.md — Kernel Driver Track (Plan of Record)

The kernel driver is the trusted event source: it starts before services and malware each boot, sees everything synchronously, captures drops tamper-proof, injects the sensor DLL, and protects the platform's own processes. It REPLACES user-mode ETW as the active event source — both stay supported, exactly ONE is active at a time (config selects).

Status: decisions RESOLVED with the user; D0 is next; dev box is ready (WDK 10.0.26100.0 + VS 2022 MSBuild + signtool confirmed installed). AGENTS.md carries the resolved-decisions summary for agents; THIS file is the detailed plan of record — when details drift, this file wins.

## 1. Resolved decisions (user-confirmed)

| # | Decision | Choice |
|---|----------|--------|
| 1 | Driver language | C, WDM. Rust-in-kernel rejected: `windows-drivers-rs` is KMDF-centric, WDM would be raw FFI, panic = BSOD, no ecosystem. Schema sharing happens via versioned wire models in `protocol` + golden tests — shared MODELS, never a shared language. |
| 2 | Signing | Test-signing for now; real cert later. HVCI/memory integrity off in lab VMs (mandatory for test-signed drivers anyway). |
| 3 | Posture | Observe-only for now — no blocking callbacks. Protection (D4) comes later. |
| 4 | Architecture breadth | x64 first; WOW64/x86 sensor later — ports and structs shaped for it. |
| 5 | Overflow policy | Process/registry class = overwrite-oldest + loss counter; drops class = stop-collect + counter (drop evidence is scarcer than process evidence). |
| 6 | Event source | Driver REPLACES user-mode ETW as the active source; both adapters stay supported, exactly one active at a time (config selects). No dual-feed dedupe required. |
| 7 | Command line | `PsSetCreateProcessNotifyRoutineEx` `CreateInfo->CommandLine` is primary (no PEB walk at create-time). The injectee carries an optional debug self-inspection dump (PEB walk, module list, own command line) for diagnostics. |
| 8 | Binary shape | ONE `.sys` — minifilter + WDM control device in the same binary. |
| 9 | Drain path | ONE drain: the control-device IOCTL. FltMgr's user-mode message port is NOT used — the filter hands events into the same kernel queue: one channel to guard, one ordering, one loss counter. |
| 10 | Base | WKP SysMon sample (Pavel Yosifovich, *Windows Kernel Programming*), hardened (§4). |

## 2. Framework verdict: WDM + FltMgr, no KMDF

Our driver is five subsystems; only the first is framework territory:

1. **Control device + IOCTL drain** — the only piece KMDF would wrap (~200 lines, already in the base).
2. **Kernel callbacks** (process/thread/registry/Ob) — raw kernel APIs, identical under any framework.
3. **Minifilter** — FltMgr-native, its own model entirely.
4. **Injection engine** (user APC) — `KeStackAttachProcess`, APC queueing, raw kernel.
5. **Ring/section buffer + spinlocks** — Mm + Interlocked, IRQL-sensitive raw kernel.

KMDF's value (PnP/power state machines, queue/cancel machinery, filtered device objects) targets hardware drivers. We are a non-PnP control device: `DriverEntry` creates one device, unload destroys it; the drain IOCTL completes synchronously; no pending-for-notification IRPs in v1 (event signaling goes through a kernel semaphore/event duplicated to user mode, never pending IOCTLs). A mixed WDM/WDF driver (half framework abstractions, half raw MDLs/spinlocks/APCs) would be less readable than uniform WDM. Precedent: EDR/AV kernel components are overwhelmingly WDM-style + FltMgr.

## 3. Base: WKP SysMon — audit

**Keep (good bones):** reverse-order teardown with partial-failure rollback (mirrors kernel `boot()` rollback doctrine); `PsSetCreateProcessNotifyRoutineEx` with native command-line capture; `PsSetCreateThreadNotifyRoutine`; `CmRegisterCallbackEx` post set-value; FastMutex-guarded bounded LIST_ENTRY queue with drop-oldest; IOCTL drain batching (`METHOD_OUT_DIRECT`); observe-only posture.

**Must-fix before it faces malware (verified by reading it):**

| # | Defect in base | Fix |
|---|----------------|-----|
| 1 | Default-DACL device + `\??\` symlink, `FILE_ANY_ACCESS` on ENABLE/DISABLE | `IoCreateDeviceSecure` SDDL (SYSTEM + Administrators); access checks in `IRP_MJ_CREATE` |
| 2 | `RegistrySetValueInfo` memcpys attacker-controlled `name->Length` into fixed `KeyName[256]`/`ValueName[64]` | Kernel pool overflow — validated, clamped copies with truncation flags |
| 3 | `ItemHeader.Size` is `short`; ~64 KB command lines overflow it | All sizes/lengths u32 with caps + truncation flags |
| 4 | No magic/version in records | Magic + version in every record (versioned wire schema, mirrored in `protocol`) |
| 5 | Drop-oldest with zero accounting | Per-class loss counters surfaced to the client |
| 6 | Items carry pid only | Process identity = (pid, creation time) — never pid alone (recycling) |
| 7 | Single LIST_ENTRY queue for everything | Split by rate class: control-class list stays; high-rate file/hook events go through a nonpaged shared-memory ring |
| 8 | Oversized single item > client buffer → drain returns 0 forever | Oversized-item policy = skip + count |
| 9 | `KdPrint` only | Proper tracing (WPP or gated DbgPrint); pool tags on every allocation (`DRIVER_TAG` discipline kept) |
| 10 | Registry capture: HKLM post-set-value only | Extend toward taxonomy needs (set/delete/create are the persistence signals); queries stay ETW's job |

**Every IOCTL is hostile input:** the malware is a user of this device. Restrictive device SDDL, validated buffer lengths everywhere, no unprobed `METHOD_NEITHER`, fuzzed framing.

## 4. Runtime architecture (kernel side)

- **Callbacks:** `PsSetCreateProcessNotifyRoutineEx` (create/exit + command line), `PsSetCreateThreadNotifyRoutine`, `CmRegisterCallbackEx`, later `ObRegisterCallbacks` (D4) and the minifilter (D2).
- **Queues:** control-class events (process/thread/registry) → bounded list, overwrite-oldest + loss counter; flood-class events (file, hooked-API telemetry) → nonpaged lock-free ring in a section, same overflow doctrine (coalesce + count, never block, never OOM).
- **Drain:** agent polls batched `IOCTL` reads; kernel assigns a global monotonic seq per producer + interrupt-time timestamp; ordering merges by (ts, seq, source priority).
- **Transport (injectee→driver):** shared-memory lock-free ring written by the sensor DLL — hook paths must never block on a syscall (a slow IOCTL inside `NtCreateFile` distorts the behavior we measure). Control (register, heartbeat, state flips) via `DeviceIoControl`.
- **Overflow policy:** per §1.5.
- **Timestamps:** driver timestamps are real kernel time; the AGENT maps them to fake unix-ms at drain (offset computed at connection). Correlate by session id, never raw driver timestamps.

## 5. Drops capture (D2)

- Minifilter in the same `.sys`; **hard-link tombstone at first write** (post-write or cleanup, extension-filtered): same-MFT link → final content survives truncate/overwrite/delete; delete + recreate-same-path captured as two files (forensics bonus).
- **Stream-copy fallback at cleanup** when the link fails: cross-volume drops path, no link semantics.
- **Content-hash dedup** (aligns with `drops-collector`); carry over the write-noise skip heuristic (write sizes {4096, 8192, 16384} with offset > 0).
- Drops class overflow = stop-collect + counter (§1.5).

## 6. Injection & injectee contract (D3)

- **Method:** kernel user-APC at process-create onto the initial thread (`KeStackAttachProcess` → allocate path buffer → queue APC running `LoadLibraryW`). Earliest possible, race-free, agent-independent (works during the boot window). Config-selectable fallback: agent-requested injection via the control IOCTL into an already-running process.
- **Targets:** ALL processes minus a blocklist (system core: `System`, `smss`, `csrss`, `wininit`, `winlogon`, `services`; PPL — would fail anyway; our own processes; configurable exclusions). Universal injection, LAZY activation: the DLL's init only registers (nonce-gated) and asks "am I active here?"; hooks install once the driver flips state (scoped). Per-process cost stays tiny; coverage never misses an early child.
- **Anti-impersonation:** injection ledger in the driver — registration accepted only from pids the driver injected, plus a per-injection random nonce the DLL echoes (same pattern as the IPC `Hello`). Otherwise malware forges telemetry and poisons scoring.
- **Sensor DLL materialization:** per-boot randomized name in a DACL-protected directory, hash-verified at injection (malware cannot swap the file).
- **Injectee survival rules:** no allocation in hot detours; `panic = "abort"` and no panics in detours (unwinding through foreign frames kills the host); no loader-lock work in `DllMain` — one init thread installs hooks only after the transport is up (else our own file IO recurses into our hooks); `catch_unwind` at detour entry.
- **Hooks are ENRICHMENT, never truth:** direct syscalls bypass ntdll hooks; kernel callbacks remain ground truth. Sensor silence is itself a scoring signal (unhooked/dumped/killed).
- **Debug extras:** optional self-inspection dump (PEB walk, module list, own command line) — user-confirmed request for diagnostics.
- **v1 hook set (scoring enrichment):** `NtCreateFile`/`NtWriteFile`/`NtDeleteFile`, `NtSetValueKey`, `NtCreateUserProcess`/`NtCreateThreadEx`, cross-process `NtAllocateVirtualMemory`/`NtWriteVirtualMemory`, `LdrLoadDll`, `NtDelayExecution`, `CryptEncrypt`, `ShellExecuteEx`/`WinExec`.

## 7. Protection (D4)

- `ObRegisterCallbacks`: strip `PROCESS_TERMINATE`/`VM_WRITE`/`VM_READ`/`CREATE_THREAD` from handles opened to protected pids by non-trusted callers — the standard EDR self-protection mechanism.
- Device SDDL (SYSTEM + Administrators), injection ledger, DACL on the sensor directory.
- Handle-duplicate/Ob events double as attack-attribution telemetry (who is touching us → scoring signal).

## 8. Agent integration (D5)

- **Driving:** `DriverEventSourceAdapter` — implements the existing `EventSourcePort`; drains the kernel queues → `SandboxEvent`s into the pipeline. Exactly one of {ETW adapter, driver adapter} runs, config-selected.
- **Driven:** `DriverControlPort` — set whitelist, request injection, query stats/loss counters; fake beside the production adapter, as always.
- **Config:** `[driver]` section — enabled, event-source selection, exclusions/blocklist, injection mode, buffer sizes, hook set toggle.
- **Taxonomy:** existing canonical events reused; new `behavior.*` family for hooked-API calls and chains (`{pid, tid, api, args, ts}`). Scoring v2 consumes single calls + chains (mass-encrypt + shadow-copy deletion = ransomware; cross-process write + remote thread = injection; Run-key set + autostart = persistence).
- **Clock:** driver → fake unix-ms mapping at drain; session-id correlation everywhere.
- **Install:** agent SCM `install` gains the driver service (AUTO_START; agent depends on driver).

## 9. Build, signing, CI

- **Location:** `driver/` at the repo root — own WDK build (vcxproj/msbuild), NOT part of the cargo workspace.
- **Naming (default, vetoable):** `secoutfall.sys`, device `\Device\secoutfall`, symlink `\??\secoutfall`, service `secoutfall` — config-selectable where it matters. Note: the driver name is visible to the malware; a low-key name is acceptable if preferred.
- **D0 build flags:** link with `/INTEGRITYCHECK` (else `PsSetCreateProcessNotifyRoutineEx`/`ObRegisterCallbacks` fail with `STATUS_ACCESS_DENIED` — classic first-boot gotcha); prefer `ExAllocatePool2` (flags-based, Win10 2004+); nonpaged pool for the flood-path ring; pool tags everywhere.
- **Dev box (confirmed):** WDK 10.0.26100.0 (`km` headers/libs + build targets), VS 2022 Community MSBuild, `signtool.exe`.
- **Signing:** `New-SelfSignedCertificate` + `signtool` script in `driver/`; cert imports into VM Root + TrustedPublisher.
- **CI:** build-only driver job on `windows-latest` (WDK via `microsoft/setup-wdk`, EWDK ISO as fallback) — the driver must BUILD green in CI; loading/signing stays out by design.

## 10. Phases & acceptance

- **D0 — DONE (reviewed; build fixed on the way):** `driver/` scaffold from WKP base, renamed; `/INTEGRITYCHECK` + W4/WX; SDDL-secured device (`IoCreateDeviceSecure`, SYSTEM+Admins); process/thread/registry(set-value) callbacks → queue → IOCTL drain; hostile-length clamps (cmd line, key/value names); atomic `PopIfFits` drain; console dumper. D0-review fixes: literal `WindowsTargetPlatformVersion = 10.0.26100.0` in BOTH vcxproj Globals (latest-SDK resolution picks VS18's 28000 SDK, whose WDK build folder does not exist → WDK props silently no-op → C1083 ntddk.h), build.ps1 pins vswhere to VS2022 `[17.0,18.0)` (WDK 26100 build tasks are MSBuild-major-versioned; VS18 asks for a tasks DLL the WDK never shipped), `OnRegistryNotify` NTSTATUS signature fix.
  *Acceptance met locally:* driver + dumper + wiretest build green; load/dump round-trip on the lab VM still pending (user-side one-time prep).
- **D1 — telemetry core (IN PROGRESS, user-mode contract DONE):** wire format **v2 shipped**: magic+version per record, u32 record sizes (string lengths u16, capped ≤ 8 KiB), per-field truncation flags, per-boot monotonic sequence, process identity = (pid, witnessed creation time — `IdentityTable`, pre-load processes resolve to 0), per-class loss counters surfaced via `IOCTL_SECOUTFALL_GET_STATS` (`DriverStats`), oversized-item drain policy = skip + count, image-load telemetry (`PsSetLoadImageNotifyRoutine`, system-mode images skipped), registry create/delete/set-value under HKLM (prefix match tightened against `\REGISTRY\MACHINEXYZ`), string caps: cmdline 8 KiB, key path/image 1 KiB, value name 512 B, data 128 B. **Golden pinning both sides:** `driver/tests/golden_v2.bin` committed; C-side `wiretest` (generate/verify, runs in CI driver lane) + Rust mirror `protocol::driver_wire` (decode-only, golden + malformed-input unit tests + panic-freedom proptests) decode the same bytes. **Flood chaos on the control queue** still pending (self-flood stress via a debug-gated IOCTL or the dumper); the shared-memory ring moves to D3 — its only producers are the injectee transport (D3) and the minifilter flood class (D2), so D1 carries the overflow doctrine on the control queue and the counters plumbing instead.
  *Remaining for D1 acceptance:* flood-chaos stress + lab-VM round-trip (load → dumper shows v2 events incl. stats) + CI green.
- **D2 — drops:** minifilter (same `.sys`), hard-link tombstone + stream-copy fallback, content-hash dedup, write-noise heuristic; path toward `drops-collector`.
- **D3 — injection + transport:** kernel APC engine, injectee graduates from `crates/injectee` demo (transport, nonce registration, lazy activation, v1 hook set, survival rules), `DriverControlPort` wired.
- **D4 — protection:** ObCallbacks stripping, device SDDL, injection ledger.
- **D5 — agent integration end-to-end:** driver adapter + control port, `[driver]` config, clock mapping, scoring v2 chains, IOCTL framing fuzz targets, 24-session sim extension, VM soak.

## 11. Open items

1. WOW64/x86 sensor — deferred by decision; structs/ports shaped for it.
2. Network ground truth: with the driver active and no WFP callout, net events disappear (ETW is off) — decide WFP timing.
3. Real minifilter altitude when leaving the lab (lab: arbitrary free altitude).
4. EV/real cert + WHQL ambitions — later.
5. Naming veto for `secoutfall.sys` (§9).

## 12. File map

- `driver/` — the C/WDM driver (D0 scaffold; own WDK build, signing script, README).
- `crates/injectee/` — the Rust sensor DLL (nightly cdylib, excluded workspace; demo `hook!` framework today, transport + lazy activation in D3).
- `crates/protocol/` — versioned wire schema shared by driver/injectee/agent + golden tests.
- `crates/agent/` — `DriverEventSourceAdapter` (driving) + `DriverControlPort` (driven), `[driver]` config (D5).
