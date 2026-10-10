# SecOutfall — Driver Track Implementation Plan

Working checklist for the kernel-driver track. Design rationale, resolved
decisions and engine lessons live in **KERNEL.md** — this file tracks only
what is DONE and what REMAINS, in execution order. Keep both in sync:
KERNEL.md wins on details, this file wins on "where are we".

Legend: [x] done · [~] partially done (remaining items listed) · [ ] not
started.

---

## D0 — Driver scaffold + telemetry skeleton [x]

- [x] `driver/` scaffold from the WKP SysMon base, renamed to secoutfall
- [x] `/INTEGRITYCHECK` link flag (PsSetCreateProcessNotifyRoutineEx fails
      with STATUS_ACCESS_DENIED without it)
- [x] SDDL-secured device (`IoCreateDeviceSecure`, SYSTEM + Administrators)
- [x] Process/thread/registry(set-value) callbacks → bounded queue → IOCTL
      drain (`PopIfFits`, skip+count for oversized items)
- [x] Hostile-length clamps: command line, key/value names, value data
- [x] Console dumper (`dump/dump.cpp`) + signing script (`sign.ps1`)
- [x] Build script (`build.ps1`) + CI driver lane (SDK + WDK 10.0.26100)
- [x] D0 review fixes: literal `WindowsTargetPlatformVersion` in both
      vcxproj, vswhere pinned to VS2022 `[17.0,18.0)`, NTSTATUS callback
      signature

## D1 — Telemetry core [~]

- [x] Wire format v2: magic + version, u32 record sizes, capped string
      lengths with per-field truncation flags, per-boot monotonic sequence,
      process identity = (pid, witnessed creation time)
- [x] Image-load telemetry (`PsSetLoadImageNotifyRoutine`, system-mode
      images skipped)
- [x] Registry create/delete/set-value under HKLM
- [x] Per-class loss counters (`GET_STATS`) + oversized skip+count drain
- [x] Golden pinning both sides: `wiretest` (C) + `protocol::driver_wire`
      (Rust) decode the same committed fixture
- [~] Flood-chaos stress on the control queue (self-flood IOCTL exists;
      storm numbers pending)
- [ ] Lab-VM round-trip: load → dumper shows v2 events + stats (needs
      user-side test-signing prep, see driver/README.md)

## D2 — Minifilter telemetry + drop capture [x]

- [x] Minifilter in the same .sys (post-op telemetry only, observe-only)
- [x] File records: created / written / cleaned-up / deleted / renamed
- [x] Second rate-class queue (flood class) with merged 3-queue drain by
      global sequence
- [x] Paging-IO writes skipped at registration level
- [x] Write-noise heuristic (4096/8192/16384 at offset > 0) skipped +
      counted
- [x] Drop capture: hard-link tombstone at first matching write
      (`FileLinkInformation`), stream-copy fallback at cleanup, exactly-
      once per stream via Filter Manager stream contexts
- [x] Drops-class queue (512) with stop-collect policy
- [x] `SET_DROP_POLICY` (extensions + normalized NT drops dir, created on
      first use)
- [x] Kernel-side content dedup deliberately omitted (stays in the agent's
      drops-collector)

## D3 — Injection engine + sensor transport [x]

- [x] Universal user-APC injection off the notify hooks; first thread =
      APC target (delivered during loader init, before user code)
- [x] ntdll!LdrLoadDll resolved once per boot by kernel-side PE export
      walk; 20-byte target-side stub bridges the APC argument to its four
      parameters
- [x] Injection ledger (identity + per-injection nonce) + anti-
      impersonation handshake (SENSOR_CHALLENGE / SENSOR_REGISTER, one-shot)
- [x] Compiled blocklist (smss/csrss/wininit/winlogon/services/lsass/our
      own) + policy extras; PPL tolerated-and-counted; WOW64 gets the x64
      sensor
- [x] Per-sensor unnamed section, kernel-mapped, duplicated into the
      target: Vyukov-style committed-slot ring (4096 × 40 B), lock-free
      kernel drain with sequence validation (corrupted host rings skipped +
      counted)
- [x] BehaviorCall wire records composed at drain with kernel-stamped
      pid/identity/sequence/time
- [x] Sensor client in crates/injectee: challenge → map → register →
      wait-active (bounded), allocation-free lock-free ring emit, Nt* hand
      declarations, heavy windows crate dropped from the DLL
- [x] Hook set v1: NtDelayExecution / NtCreateFile / NtWriteFile /
      NtCreateThreadEx (observe-only)
- [ ] Remaining hook set: NtDeleteFile, NtSetValueKey, cross-process
      NtAllocateVirtualMemory/NtWriteVirtualMemory, LdrLoadDll,
      CryptEncrypt, ShellExecuteEx/WinExec (D4-scoped follow-up)
- [ ] Documented v1 limits to revisit: registration race window; sensor
      IOCTLs from non-elevated targets need the device-security push (D5)

## D4 — Self-protection [x]

- [x] ObCallbacks on process + thread types: strip terminate / VM write /
      VM read / VM operation / create-thread / duplicate (process) and
      terminate / suspend-resume / set-context / set-thread-allowed
      (thread) from handles opened by unprotected callers
- [x] Protected set by name via SET_PROTECTED (opt-in suffix match,
      tracked per-pid at create/exit); protected processes manage each
      other, System always trusted
- [x] ProtectionEvent attribution records (opener identity in header,
      target + requested-vs-stripped access in payload); fixture record 16,
      golden-pinned both sides
- [x] SET_DEVICE_SECURITY: caller-built self-relative SD applied to the
      device DACL (RtlValidRelativeSecurityDescriptor-validated)

## D5 — Agent integration [x]

- [x] `[driver]` config section (enabled / sensor_path / protected_names /
      drops_dir / drop_extensions), documented in docs/Agent.toml
- [x] `DriverEventSourceAdapter` (feature `driver`): GET_DATA drain loop,
      decodes via the golden-pinned protocol::driver_wire, maps all 16 wire
      record kinds to SandboxEvent::Source (incl. behavior.call and
      protection.stripped taxonomy members)
- [x] Lazy real→fake clock offset anchored on the first drained record
- [x] Bounded pid→name cache for process-exit records
- [x] `DriverControlPort` (driven): apply_policies (injection/drops/
      protection blobs) + query_stats + flattened loss_counters; real
      DeviceIoControl adapter + fake
- [x] Composition root: driver.enabled routes the driver source instead of
      ETW; pre-existing default-features Windows build quirk fixed
      (privileges.rs gated on the union of windows-using features)
- [x] Composition-root policy push (`push_driver_policies`, runs before the
      source attaches): device-security → sensor materialization →
      injection/drop/protection blobs → baseline stats. Every failure
      degrades to a log line — a missing driver never takes the service
      down. (The fake `driver_control_fake` was found ORPHANED — written in
      slice 1 but never declared in the module tree; now wired, house-style,
      and unit-tested.)
- [x] Scoring v2: single behavior signals + chains over `behavior.call`
      records — Run/RunOnce write (once per pid); injection chain
      (cross-process VM write + thread creation); ransomware chain (8+
      `CryptEncrypt` + shadow-copy deletion). Weights in `[scoring]`
      (`run_key_set`/`chain_injection`/`chain_ransomware`), thresholds in
      `domain::score` (`ChainDetector`, bounded per-pid, one-shot per chain,
      pids forgotten on scope exit). The scope-tracker bridges only
      scoring-relevant apis of SCOPED pids onto the bus
      (`BehaviorObserved`), so high-rate hooks never flood it. The 24-session
      sim feeds the ransomware chain and asserts the `study.score` per
      session (chain 40 in detonating sessions, 0 in quiet ones).
- [x] Sensor materialization: `SensorStorePort` (driven) — the agent never
      pushes the configured path; the DLL is copied per boot under a random
      name into a `%ProgramData%\SecOutfall\sensors\boot-<rand>` dir with a
      protected DACL (SYSTEM/Admins + creating-token user, `P`), the copy is
      SHA-256-pinned to the source, and only the verified NT path arms the
      injection policy (failure = injection stays OFF). Previous-boot dirs
      are pruned. Real adapter (feature `driver`) + fake; composition-root
      push wrapped in `spawn_blocking`, every failure degrades to a log.
- [x] IOCTL framing fuzz target `decode_driver_wire` (cargo-fuzz, Linux CI —
      fuzzes `protocol::driver_wire::decode_all`; proptest twin lives in
      `driver_wire::proptests`).
- [x] 24-session sim extension (see scoring v2 above).
- [x] Console-user SD push: `DriverControlPort::apply_device_security(sddl)`
      (real adapter converts SDDL → self-relative SD → `SET_DEVICE_SECURITY`
      blob; fake records). The composition root resolves the console-user
      SID (reused `console_user_sid` helper from the IPC server) and pushes
      `device_security_sddl(sid)` = driver-default SYSTEM/Admins + a
      generic-all ACE for the console user, so the sensor reaches the device
      from non-elevated targets.
- [x] Sensor IOCTL plumbing: RESOLVED BY DESIGN — no proxy needed. The
      sensor talks to the control device directly (challenge/register are
      its own `DeviceIoControl` calls); the console-user SD push above is
      exactly what makes that path work from non-elevated targets.
      `DriverControlPort` stays agent→driver only.

## Cross-cutting acceptance (gates for "driver track done")

- [ ] Lab-VM round-trip: driver loads, dumper shows v2 events + stats,
      sensor injects + registers + emits behavior records into the agent
      pipeline end-to-end (needs test-signing prep: driver/README.md)
- [ ] Flood-chaos numbers from a real write storm (ransomware-class
      sample or the self-flood IOCTL at scale)
- [ ] CI green: default + all-features lanes, driver lane, injectee
      build, wiretest fixture verify
- [ ] 24-session sim extension green

## Deferred decisions (open items — see KERNEL.md §11)

- [ ] WOW64/x86 sensor (structs shaped for it)
- [ ] Network ground truth (WFP callout) while the driver replaces ETW
- [ ] Real minifilter altitude + EV/real cert when leaving the lab
- [ ] Driver/device naming (`secoutfall.sys` name is visible to malware)
