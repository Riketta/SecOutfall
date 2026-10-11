# AGENTS Instructions

## Project overview

SecOutfall is an agentic **Windows malware analysis sandbox**. An in-VM agent detonates a sample ("target") inside an isolated Windows VM and observes it; an external **Controller** (not in this repo) receives reports over NATS and HTTP.

**Execution model (critical to understand):** one analysis run = a **study** = N **sessions** separated by **reboots**. The agent (session-0 service) and its scope database persist across reboots — the agent (and the driver service) are the only persistent components. Each boot starts a new session (id increments), session duration comes from an `uptimes` table; after the last session the agent requests shutdown, otherwise reboot. System time is manipulated (fake timestamp at first session, per-reboot offset).

**Components:**

- `agent` — Rust session-0 Windows service (LocalSystem, Automatic). The agent: event-source consumption (kernel driver or user-mode ETW, exactly one active), scope tracking, drop collection/upload, screenshots intake, NATS reporting, finalization/reboot orchestration.
- `user-actor` — Rust interactive-session component launched by the agent (as SYSTEM). Observes the desktop (focus tracking, screenshots) and acts in it (reactive + scripted input). Receives ALL config via IPC from the agent; reads no files.
- `injectee` (`crates/injectee`) — Rust cdylib sensor DLL: declarative API hooks (retour static detours) reporting what the host process asks the OS to do. Own nightly workspace, excluded from the main one.
- `driver/` — C kernel driver (WDM control device + minifilter in one `.sys`): trusted early event source, tamper-proof drop capture, sensor-DLL injection engine, self-protection. See **Driver track**.
- Shared: `kernel` (generic microkernel), `protocol` (boundary DTOs), `devtools` (observer/simulator bins).

**Doctrine:** Rust, hexagonal (ports & adapters) **microkernel** with middleware pipeline + event bus, event-driven fire-and-forget core, TOML config, well-tested — this is a security tool and the analyzed malware is an adversarial user: every byte coming from inside the VM is hostile input.

## Workspace shape

Cargo workspace at the repo root, **lib + bin** per project:

- `kernel` — lib only. Generic microkernel: ports, pipeline runner, event bus, plugin lifecycle. Pure Rust, no Windows deps, runs on any OS (testable in Linux CI).
- `protocol` — lib only. Shared models at port/adapter boundaries: canonical event taxonomy, NATS envelope + payload DTOs, IPC frame schema, driver wire records, TOML config schema. **No hexagon/kernel types leak here** — pure DTOs shared between agent and user-actor.
- `agent` — lib + bin `secoutfall-agent`. Lib: hexagon (domain + app + plugins + adapters). Bin: thin composition root only.
- `user-actor` — lib + bin `secoutfall-user-actor`. Same pattern.

**Role/family layout (both hexagons):** `ports/` and `adapters/` are split by direction — `driving/` (inbound: the adapter SPI that pushes into the kernel `EventInletPort` — ETW, driver, scheduler, SCM, IPC server; UA: focus sources + IPC client) and `driven/` (outbound ports the hexagon calls). `driven` adapters are grouped further by port FAMILY (`broker/`, `clock/`, `launcher/`, `killer/`, `scope_store/`, `shell_association/`, `upload/`, `driver_control/`, `sensor_store/`; UA: `capture/`, `input/`, `launcher/`), and every fake lives beside its production twin in the same family (e.g. `driven/broker/fake.rs` next to `driven/broker/nats.rs`). Two cross-direction facts by design: the agent's ETW mapping is pure and always compiled (`adapters/driving/etw_mapping`), and the UA's production screenshot sink is the IPC client's channel pair — an adapter spanning both directions — so its fake sits alone at `adapters/driven/sink_fake.rs`.
- `devtools` — bins: `dummy-broker` (NATS traffic observer), `session-sim` (fake event source + fake clock harness for study simulations).
- `crates/injectee` — NOT a workspace member: Rust cdylib on nightly (retour static detours), own `rust-toolchain.toml` (nightly, minimal) + `Cargo.lock`; excluded in the root `Cargo.toml` like `fuzz/`. Build from its directory (`cargo build --locked`); CI builds it explicitly.
- `driver/` — C/WDM, own WDK build (`build.ps1`), not part of the cargo workspace.

## Target architecture

Hexagonal microkernel:

- Plugin contracts ARE ports; plugins ARE adapters; kernel IS the inner hexagon. Kernel never imports plugins; plugins never import each other (bus only); kernel domain minimal.
- Port families in kernel: `api_ports` (driving, kernel-implemented — the pipeline entry), `spi_ports` (driven, kernel-consumed — storage/config/scheduler/telemetry), `plugin_ports` (plugin-facing — `PluginPort`, `MiddlewarePluginPort`, `EventBusPort`).
- Cardinality: kernel service ports = single adapter, single instance, kernel-owned, injected into plugins. Plugin-facing ports = many adapters (one per plugin), registered into kernel.
- Lifecycle: `boot()` = `init()` all plugins, then `start()` all; `shutdown()` = `stop()` all. `boot()` rolls back on failure (reverse-order `stop` over every processed plugin, including a mid-start failure — `stop` is contractually idempotent and must tolerate init-only/partially-started plugins).
- Pipeline: inbound events flow forward through `pre` hooks, backward through `post` hooks. `Next::Continue` / `Next::Stop` (skip remaining `pre`, still run `post`) / `Next::Abort` (skip everything). **No payload in `Next`** — fire-and-forget core, no response-context; outputs happen only via injected driven ports.
- Event bus carries only DERIVED plugin-owned domain events, never raw inbound events. Pipeline→bus bridging is plugin behavior. `KernelService<E, S, B, D = E>` keeps the bus event type `D` decoupled from the inbound `E`. `InMemoryEventBus::new(0)` clamps to 1 (tokio broadcast panics on 0).
- Kernel checklist: required for every deployment / breaks platform when removed → kernel. Everything else → plugin.

### Agent (session-0 service) — kernel + plugins

- **Driving adapters** (inject events into pipeline): `EtwKernelTraceAdapter` / `DriverEventSourceAdapter` (both implement `EventSourcePort`, exactly one active at a time, config selects — see **Driver track**), `WindowsServiceAdapter`/`ConsoleModeAdapter` (SCM stop/shutdown/power; console mode for dev), `SchedulerAdapter` (session deadline, keepalive 15 s, stats tick, persist tick), `IpcServerAdapter` (user-actor pipe: ScreenshotReceived inbound; config push in Welcome), *(future)* NATS control subscription (port + fake exist now).
- **Driven ports**: `BrokerPort` (NATS publish), `FileUploadPort` (HTTP multipart), `ScopeRepository` (atomic JSON file `scope.json`), `ConfigPort` (TOML), `ProcessLauncherPort` (**two swappable adapters**: `TokenProcessLauncher` = CreateProcessAsUser/WTSQueryUserToken; `SchedTaskLauncher` = schtasks EventID-777 trick; config selects), `SystemClockPort` (SetSystemTime/W32Time/w32tm), `ShellAssociationPort`, `UserActorLauncherPort`, `DriverControlPort`, `SensorStorePort`, `TelemetryPort`.
- **Plugins**: `scope-tracker` (process-tree membership, drop detection; publishes `DropObserved`/`DropClosed`/`ScopeDied`), `event-reporter` (NATS forwarding, verbosity gate), `drops-collector` (copy/dedupe/quota/upload), `screenshot-intake`, `finalizer` (session state machine, reboot/shutdown, kills configured processes, persists scope), `system-time`, `target-launcher`, `user-actor-supervisor`, `scoring` (single signals + behavior chains), `heartbeat` + `state-reporter`, `statistics`.
- **One wire seq counter per boot** (`AgentDeps::seq`, shared by runtime + assembler + IPC server) — never add a second; Controller-side loss detection depends on it being monotonic and gapless per publisher connection.
- **Launches are off the pipeline**: target-launcher + supervisor submit to a bounded JobQueue spawned in `start` (refusal = detonation lost = error-logged). The scope-expectation race is closed by ordering: the tracker drains its expectation subscription via `try_recv` at the top of every `pre`, and the launcher publishes BEFORE launching — the interpreter's `process.started` can only arrive after, so the drain always sees it.
- `debug.skip_reboot_and_shutdown` is honored by the finalizer for ALL modes: it gates the finalize REQUEST publish (the agent only ever publishes the request; the Controller/VM acts on it).

### User actor (user session) — hexagon reusing the kernel crate lightly

The user actor ("UA" as shorthand) both **observes** the desktop (focus tracking, screenshots) and **acts** in it (reactive + scripted input) — hence the name.

- Same kernel crate, light configuration (few middleware plugins, sparse bus). Scripted activities ARE plugins (`ActivityPort`: Start/Stop/Pause/Resume).
- **Driving**: `WinEventHookAdapter` (EVENT_SYSTEM_FOREGROUND 0x0003 / EVENT_OBJECT_FOCUS 0x8005 — REQUIRES a dedicated thread with a Win32 message pump bridging into tokio via channel), `PollingFocusAdapter` (50 ms), `IpcClientAdapter` (connect, Hello handshake, future commands).
- **Driven**: `ScreenCaptureAdapter` (GDI→JPEG, DPI-aware, all monitors), `InputSynthesisAdapter` (`SendInput` only — `SendMessage`/`mouse_event` are deprecated), `ScreenshotSink` (IPC), `TelemetryPort`.
- Crate shape: kernel-light hexagon (`app::assemble`), inbound `ActorEvent {Welcome, FocusChanged}`, bus `ActorBusEvent {ConfigApplied, ForegroundChanged, ScreenshotTaken, CaptureQuotaExhausted}`; plugins `config-apply`, `focus-watch` (capture + quota, strictly gated by pushed config), `reactive` (bus subscriber, Enter hold 300 ms, storm gate: pure `press_allowed` helper, `PRESS_MIN_INTERVAL` = 1 s), `scripted-runner`. Windows adapters are feature-gated: `ipc`, `focus-poll` (50 ms), `focus-winevents` (pump thread + std→tokio bridge), `capture` (GDI DIB section → jpeg-encoder, DPI-aware), `input` (SendInput: `press_enter`, `type_text` via `KEYEVENTF_UNICODE`, `press_key`, `press_hotkey` chords), `apps` (`CreateProcessW` app launcher). Focus sources dedup via `domain::FocusDedup`; the focus source starts only after the config push names it.
- **Scripted activities:** `plugins/scripted` holds `ActivityPort` (name/start/stop/pause/resume over an `ActivityControl` token pair), the pure `ActivityStep` script model (Launch/Wait/TypeText/Key/Hotkey), the `run_script` loop (passes forever, `iteration_delay` 30 s; a failed launch aborts the pass — typing into a missing window is skipped — and the loop retries; stop/pause check before every step), and the `scripted-runner` plugin (starts activities when the pushed config has `scripted: true`; kernel shutdown stops them). `plugins/activities` holds the three scenarios as pure step data: notepad (launch → type notes), calc (launch → digit/operator sequences, numpad VKs), explorer (`Win+E`, `Ctrl+L` address-bar navigation — hotkey, not launch). Activities are `ActivityPort` components OWNED by the runner plugin (assembly-time injection) — kernel plugins never call each other, so activities are not kernel plugins themselves. Scripts favor layout-independent input: Unicode typing for text, named VKs (`ports::Key`) for keys/chords.
- The capture quota is reserved via `compare_exchange` — the kernel inlet accepts concurrent adapters, so check-then-act could over-run; sink/capture failures release the slot. The UA sink never blocks (`try_send` → `ScreenshotSinkError::Full`, overflow policy = drop + count); outbound screenshot frames are capped at the sink (`ScreenshotSinkError::Oversize`, never queued — an over-cap frame would be rejected by the peer and resent forever across reconnects).

## Canonical event taxonomy

Source-agnostic (driver or ETW, one active at a time). Owned by `protocol` crate. The envelope `type` field carries this name; the `data` payload schema is keyed by it. `agent.state`, `study.score`, `study.drops_summary` are regular typed events — no separate "Report" packet kind.

```
process.started | process.stopped
thread.started | thread.stopped
image.loaded | image.unloaded
registry.key_created | registry.key_deleted | registry.key_opened | registry.key_closed
registry.key_queried | registry.value_queried | registry.value_set
file.created | file.written | file.closed | file.cleaned_up | file.deleted | file.renamed | file.fsctl
net.tcp.connected | net.tcp.accepted | net.tcp.disconnected
session.started | session.finalizing | session.ended | scope.died | target.launched
drop.observed | drop.closed | drop.copied | drop.uploaded
screenshot.received | screenshot.uploaded
user_actor.started | user_actor.stopped | clock.adjusted
agent.state | study.score | study.drops_summary
study.reboot_requested | study.shutdown_requested
behavior.call | protection.stripped
```

The ETW adapter maps Task/Opcode → these names; mapping table lives (and is tested) in the adapter — registry events map EXPLICITLY (no `_` fallthrough may fabricate events; PID parsed via candidates `PID`/`ProcessId`). The driver adapter maps all wire record kinds 1:1. `behavior.call` is the sensor-family event (hooked-API calls and chains) consumed by scoring.

## Wire protocol v3

- NATS (`async-nats`, the maintained native Rust client). Broker and GlitchTip are reachable from analysis VMs on the lab network.
- Channels: `control_channel` + `event_channel` only. Agent self-diagnostics go to Sentry/GlitchTip, behavioral telemetry to `event_channel` with verbosity gating.
- Envelope (all messages, both channels):

  ```json
  {"v": 3, "type": "process.started", "ts": 1699999999999, "study": "<uuid>", "session": 4, "seq": 12345, "data": {}}
  ```

  `ts` = unix ms from the (deliberately fake) clock; `study` = id generated at session 0, persisted in scope.json; `seq` = monotonic per publisher connection → Controller-side loss detection. With the driver active, `ts` is the SOURCE event's kernel time mapped to fake unix ms (`SandboxEvent::SourceDated`) — ETW/scripted events keep `Source` (stamped at consumption); matchers unify via `SandboxEvent::source_event()`.
- Control events: `control.keepalive` (every 15 s), `control.reboot`, `control.shutdown` (`data.error` optional). Agent never subscribes yet (observe-only); inbound control port + fake exist for the future.
- HTTP uploads: multipart parts `meta` (`application/json`, `{"path", "study", "session"}`) + `blob` (`application/octet-stream`), streamed and size-capped. Screenshot pseudo-name: `screenshot-{session}-{seq}.jpeg`. No auth.

## Agent↔User-actor IPC v1 (named pipes)

- Pipe `\\.\pipe\secoutfall\user-actor-v1`, tokio `ServerOptions` + `security_attributes_raw` with restrictive DACL (SYSTEM, Administrators, launch user only), `reject_remote_clients` + deny-Network ACE, bounded instances.
- Frames: 8-byte header `{len: u32 LE, type: u16, flags: u16}` + payload; hard cap 16 MiB. Frames REJECT nonzero `flags` (`FrameError::ReservedFlags`). Control frames = JSON; screenshot frames = raw JPEG.
- Anti-impostor: per-boot random nonce passed to the user actor at launch, echoed in `Hello`; server verifies client token is SYSTEM and client PID is the child we spawned (`with_expected_client_pid(Arc<AtomicU32>)` gate — supervisor stores the launched pid, `0` = ungated sentinel; an armed gate also accepts a **LocalSystem client** via `client_is_system`, covering the sched-task UA whose pid is never reported; FFI failure can only deny).
- Commands: `Hello {protocol, nonce, module_version}` → `Welcome {session_id, config}` (config push; a pull-only `GetConfig` re-pull is kept), `Screenshot {seq, jpeg}`, `Error`. Correlation ids where confirmation matters.
- Client adapter lives in `user-actor` (`adapters/driving/ipc_client`) — sink/queue channel pair (`IpcClientAdapter::channel`) so plugins get the sink at assembly; bounded queue (4) applies backpressure; client reconnects on connection loss with a 500 ms backoff (nonce stays valid per boot, server re-pushes `WELCOME`), a pre-WELCOME `ERROR` is fatal (`HandshakeRejected`); connect retries have a deadline. A failed `connect()` logs, backs off, and rebuilds the instance — only pipe-CREATION failures are fatal.
- Server details that matter: no WELCOME/GET_CONFIG before verified HELLO; 10 s handshake deadline (silent client cannot squat the instance); next pipe instance created before serving (spawn per-client task); SDDL descriptor converted once per `run()` with RAII `LocalFree`; a console-user SID ACE is added at runtime (`console_user_pipe_sddl`, WTSQueryUserToken → TokenUser → ConvertSidToStringSidW); `with_pipe_name` overrides the pipe for tests.
- **UA IPC reads run on a dedicated task** — `read_exact` consumes pipe bytes even when its future is dropped, so a `select!` over reads desyncs the stream; the reader is cancel-aware, and teardown closes the writer then allows a 1 s grace before aborting (the reader holds the ReadHalf — without closing the writer first this DEADLOCKS).
- `user_actor.started`/`stopped` are handshake-evidence events: published by the IPC server on verified `HELLO` (module_version + client pid via `GetNamedPipeClientProcessId`) and on disconnect-after-handshake — never on launch intention. The supervisor (`user-actor-supervisor` plugin) only launches the UA on the marker-process sighting, passing `--nonce <hex>`; marker matching lives in `agent::domain::marker::is_marker_process` (case-insensitive `.exe` strip; degenerate names like empty sides never match).

## Config (TOML)

- `C:\Agent.toml`, strict validation (reject unknown/ill-typed keys with clear errors), no auto-back-fill, native arrays. Defaults in code.
- Structure instead of flat keys; the schema lives in the `protocol` crate with golden tests. Sections: `[broker] uri/control_channel/event_channel/verbosity`, `[target] path/args/every_session`, `[study] uptimes/autoshutdown/processes_to_terminate/scope_path/files_to_validate`, `[drops] path/extensions/max_size/limit_per_session/upload_uri`, `[screenshots] path/save/max_per_session/upload_uri`, `[time] timestamp/offset_secs`, `[platform] launch_mechanism/non_s0_process/shutdown_delay_secs/runas_utility_path`, `[user_actor] path/reactive/scripted/focus_method/screencapture`, `[scoring] cli_started/drop_observed/run_key_set/chain_injection/chain_ransomware`, `[driver] enabled/sensor_path/protected_names/drops_dir/drop_extensions`, `[telemetry] sentry_enabled/dsn/user_actor_dsn/log_dir`, `[debug] skip_reboot_and_shutdown/skip_time_manipulation/console`.
- The shipped full-defaults sample is `docs/Agent.toml`, pinned to the schema by a golden test (`crates/protocol/tests/config_sample.rs`): parse(sample) must equal the built-in defaults plus a non-empty `target.path`, must validate, and a stripped minimal document must parse to the same config. Config keys added/renamed/retyped break that test until the sample is updated — by design.
- `EventVerbosity::Partial` is rejected at config validation until implemented. Empty `uptimes` + `autoshutdown` = dynamic sessions ending in shutdown (never reboot-forever).
- State paths default ABSOLUTE under `C:\ProgramData\SecOutfall\` (a session-0 service's CWD is System32); UA launches resolve relative paths against the agent exe dir (textual `is_absolute_path` in `domain::image_name`).

## Telemetry

- `tracing` macros everywhere = single instrumentation API. Subscriber = `registry()` + `EnvFilter` + `tracing-appender` non-blocking rolling files + console (debug) + `sentry-tracing` layer → **local GlitchTip** (Sentry-protocol compatible; standard DSN).
- No conflict between `sentry` and `tracing-subscriber` — Sentry joins as a layer in the single global registry, set up once in each bin's composition root. Layer captures ERROR+ as events, spans as breadcrumbs — tune filters. **Every new bin gets `init_tracing` on day one** — a bin without a subscriber logs nowhere.
- Gated by `telemetry.sentry_enabled` (egress from analysis VM is visible to malware). Scrub file paths/malware-derived strings from outbound breadcrumbs. `sentry::init` PANICS on a malformed DSN — parse first; malformed = warn + no egress.
- Agent activates Sentry after config load; user-actor activates once on the WELCOME-pushed DSN — `init_sentry_once` is called on EVERY config push (idempotent; gating it behind a one-shot flag locked out a valid re-push after an invalid first DSN; the leaked guard is deliberate — process-lifetime transport).
- **Fake clock caveat:** Sentry/GlitchTip timestamps will be skewed by deliberate time manipulation — correlate by session id in payloads, never by SDK timestamps.
- User actor reports to GlitchTip directly (own DSN, received via IPC config push; reads no files) — independent failure domains, no custom relay through the agent.

## CI (GitHub-hosted lanes)

- **Linux job** (`ubuntu-latest`): nightly rustfmt gate, clippy + tests over the workspace, `cargo-deny`, and the fuzz loop (`parse_frame`, `parse_config`, `decode_screenshot_payload`, `decode_driver_wire` — `cargo +nightly fuzz run`, short budget). Platform-independent code and the unix-gated lanes live here.
- **Windows job** (`windows-latest`): clippy + tests TWICE (default and `--all-features` — the default lane does NOT see Windows-feature-gated code), full build, an explicit nightly build of the excluded `crates/injectee` workspace, and the driver job (SDK + WDK 10.0.26100 via winget, `driver/build.ps1` build-only + `wiretest --verify`).
- Gates are the validation contract — never a bare clippy (warnings don't fail it; new clippy releases keep adding lints).
- Target matrix: Windows 10/11 x64.

### Local gates (match CI exactly)

Full local match of the Windows lane:

```sh
cargo +nightly fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo test --workspace --all-features
```

The default lane does NOT see Windows-feature-gated code — lints/tests can pass there and fail under `--all-features`.

### WSL lane for `#[cfg(unix)]` code

Neither Windows lane compiles unix-gated code. The host has WSL Ubuntu with a matching stable toolchain; run the Linux lane there:

```sh
wsl -e sh -c 'export PATH="$HOME/.cargo/bin:$PATH"; export CARGO_TARGET_DIR="$HOME/secoutfall-target"; cd /mnt/d/Dev/SecOutfall; cargo clippy --workspace --all-targets -- -D warnings'
```

(and the same for `cargo test --workspace`). WSL needs `pkg-config libssl-dev` for `openssl-sys`; keep the target dir on ext4 (`CARGO_TARGET_DIR`), never on `/mnt`. WSL caveat: `.wslconfig` uses `networkingMode=VirtioProxy`, which BREAKS in-VM loopback TCP (bind works, connect refused). The one Linux test that spins an in-process HTTP server (`uploads_meta_and_blob_parts`) fails there for environment reasons, not code — skip it locally with `-- --skip uploads_meta_and_blob_parts`; CI's ubuntu runner covers it.

## Non-negotiables for new code

- No `BinaryFormatter`-style opaque serialization — explicit, versioned schemas on every wire boundary.
- No `Thread.Abort`, no `async void` equivalents, no unsynchronized shared mutable state. Single-owner tasks + channels.
- Atomic file writes (write temp + rename; temp via `create_new` + `write_all` + `sync_all` before rename; remove leftover temp first; dir fsync is unix-only — Windows cannot `File::open` a directory). Never truncate persistent state in place.
- Bounded queues with explicit overflow policy (coalesce + loss counter + report, never OOM) — malware WILL flood any event source.
- No `unwrap`/`expect`/panic in production paths of agent/user-actor crates (clippy-denied).
- Validate every external byte: IPC frames, config files, drop file paths (unicode, >MAX_PATH, reserved names CON/NUL, locked files). Fuzz the parsers.
- Restrictive DACLs on any `Global\` kernel objects and named pipes.
- The driver's IOCTL surface is hostile input too: restrictive device SDDL (SYSTEM + Administrators), validated buffer lengths everywhere, no unprobed `METHOD_NEITHER`, versioned wire records with caps + truncation flags, fuzzed framing. Injectee↔driver registration is gated by the injection ledger + per-injection nonce (same anti-impostor pattern as the IPC `Hello`).
- Injectee survival rules: no allocation in hot detours, no loader-lock work in `DllMain` (one init thread installs hooks only after the transport is up); hooks are ENRICHMENT — kernel callbacks are ground truth (direct syscalls bypass user-mode hooks; sensor silence is itself a scoring signal). **The host process must NEVER die from our sensor:** `panic = "abort"` is deliberately NOT set (in a cdylib, abort = host death); the init body is `catch_unwind`-contained (a panic degrades the sensor, never the host), and detours are `extern "system"` — a panic there aborts at the FFI boundary regardless of profile, so the real rule is "hooks are written panic-free". The DLL is SILENT: `println!`/`eprintln!` panic on a missing console (a GUI/service host has none) — nothing in the injectee prints.
- Timestamps on the wire: unix milliseconds. Careful UTC vs local everywhere (system time is deliberately fake).
- Windows-only target (x86_64-pc-windows-msvc, edition 2024, stable toolchain), but keep domain logic pure and platform-agnostic; adapters thin.

## Tech choices

- Runtime: `tokio` (rt-multi-thread, time, sync, net, process). Serialization: `serde`/`serde_json`; config: TOML parsed directly with the `toml` crate (strict schema: deny-unknown-keys + explicit defaults; the `config` crate merges loosely and cannot enforce a strict schema). Transport: `async-nats`, `reqwest` (multipart, streaming). Windows: `windows` + `windows-service` crates. ETW: `ferrisetw` (chosen after a spike; `etw-reader` is a dead ETL-file fork). Uploader: `reqwest` with `multipart`+`stream`+`native-tls` (schannel — avoids aws-lc-rs build pain; switch to rustls only if https to controller becomes mandatory). Error handling: `thiserror` (domain) + `anyhow` (bin edges). Builders: `bon`. Locks: `parking_lot`. Observability: `tracing` + `tracing-subscriber` + `tracing-appender` + `sentry`/`sentry-tracing` → local GlitchTip (see Telemetry). **NO database inside the VM** — scope stays a local atomic JSON file.
- Driver track components: driver in C (WDM + FltMgr, WKP SysMon base, WDK build); injectee in Rust nightly (`retour` static detours behind the declarative `hook!` macro, `windows-bindgen`-generated bindings, cdylib, excluded workspace). The driver↔user-mode wire schema lives in `protocol` and is pinned by golden tests on BOTH sides — shared MODELS, never a shared language (Rust-in-kernel rejected: `windows-drivers-rs` is KMDF-centric, WDM would be raw FFI, panic = BSOD, no ecosystem).
- Conventions: `rustfmt.toml` at the repo root; clippy lints in the workspace `Cargo.toml` (`pedantic` warn, `indexing_slicing`/`string_slice`/`unwrap_used`/`expect_used`/`panic` deny, `undocumented_unsafe_blocks` warn, `cargo` warn + `cargo_common_metadata`/`multiple_crate_versions` allow). English comments/docs.
- Testing doctrine: Fake adapter per port — **every fake gets wired + unit-tested the day it is written** (an undeclared fake file compiles nothing); property tests (`proptest`) for scope membership & drop invariants; golden wire tests (captured envelopes); `cargo-fuzz` targets for IPC framing + config parsing + driver wire (pure Rust, fuzzable on Linux CI); chaos tests (broker death mid-finalize, locked/unicode/oversized drops, IPC peer death mid-transfer, concurrent focus storms, disk full); deterministic injected clock — a full 24-session study must simulate in milliseconds as the core regression suite.

## Agent persistence & scope semantics

- scope.json persist: `create_new` temp + `write_all` + `sync_all` before rename; leftover temp from a crash never blocks a save; corrupted file is reported, not silently reset.
- **Unclean reboot** never reuses the stale session — an open session at init is stamped `ended_at_ms` + `abandoned: true` (serde-default field) and a fresh session always opens, so ids advance one-per-boot and the clock is never re-faked (an abandoned session consumes its `uptimes` slot — ids stay index-aligned).
- **PID recycling**: `is_scoped` matches only LIVE records (a stopped pid neither inherits scope nor attributes drops) and a repeated `process.started` for a pid REPLACES its record (newest wins). The prop_scope model matches this.
- Drop quota counts SUCCESSFUL collections, not attempts (gate = cheap `load()`, increment after `persist_copy` returns Some; the single-consumer JobQueue makes this exact); the dedup hash is inserted only after a successful rename (rename failure removes the `.part`). Disk-full: a drops path that refuses every write never blocks finalization or the scope persist; a failed copy leaves no `.part` litter and does not poison collection.
- The `local` bin mode (`secoutfall-agent local`) runs real adapters with zero services: config from `--config` or `--target` (built-in defaults otherwise), in-memory scope DB, `TeeBroker` → console + `events.jsonl`, `LocalScopeRepository` → `local-scope.json`, safety-forced by `standalone_config` (time/reboot/shutdown manipulation off, kill list cleared). `console --demo` shares the console broker + in-memory scope. Finalization completion is signalled by `finalize_done` (set at the END of finalize) — never poll `ended_at_ms` (stamped at the START); polling the latter drops the pipeline future mid-persist.

## Driver track

The kernel driver is the trusted component: it starts before services and malware each boot, sees everything synchronously, captures drops tamper-proof, injects the sensor DLL, and protects the platform's own processes. It REPLACES user-mode ETW as the active source — both event sources stay supported, exactly ONE is active at a time (config `[driver].enabled` selects). All decisions below are resolved.

**Shape:** ONE `.sys` — WDM control device (`\Device\secoutfall`, SDDL SYSTEM + Administrators via `IoCreateDeviceSecure`) + minifilter (lab altitude `389910.02`) in the same binary — and ONE drain path (the control-device IOCTL; the filter hands events into the same kernel queue: one channel to guard, one ordering, one loss counter). WDM is the right shape for a non-PnP control device; the minifilter is FltMgr-native regardless. Link with `/INTEGRITYCHECK` (else `PsSetCreateProcessNotifyRoutineEx`/`ObRegisterCallbacks` fail with `STATUS_ACCESS_DENIED`); `ExAllocatePool2` needs `NTDDI_VERSION=NTDDI_WIN10_VB` set as the MSBuild *property*; nonpaged pool for anything reachable at DISPATCH. Test-signed in the lab (Secure Boot + memory integrity off, `bcdedit /set testsigning on`, cert into Root + TrustedPublisher — see `driver/README.md`).

**The wire + control contract is `driver/secoutfall/secoutfallCommon.h` (authority)**, pinned on the Rust side by committed fixtures — and the CONTROL PLANE (IOCTL codes, policy blobs, stats layout) is pinned exactly like the record wire:
- `ports::driven::driver_control::codes` computes every CTL_CODE by formula; `wiretest --emit codes` (the C compiler's own macro expansion, committed as `driver/tests/emit_codes.txt`) is the authority the Rust tests assert against — `MAX_RECORD_BYTES` (the `GET_DATA` output-buffer floor; a smaller buffer would silently destroy the queue) is pinned on the same fixture. Policy blobs + the stats layout are pinned byte-exact by `wiretest --emit <name>` fixtures (`emit_injection/drops/filewatch/protection/security/stats/minimal-rename.bin`). **NEVER hand-derive a code or a struct layout** — hand-derived constants produced three separate defects (drain method, stats field order, policy-blob shapes) before the pinning existed.
- C-array list convention: policy string lists are NUL-terminated per entry PLUS the array's implicit terminator (the last entry is double-NUL'd); byte counts are `sizeof(WCHAR[])`-derived; an empty list (disarm) is zero bytes with the count field 0. The drops/protection handlers validate `inputLength == sizeof(struct) + listBytes` exactly.
- After ANY `secoutfallCommon.h` change: regenerate ALL `emit_*` fixtures with wiretest and update the Rust mirrors in the same commit — both golden tests must agree.
- IOCTL policy pushes validate the WHOLE input before any Apply — a failed push must never leave a half-applied policy.

**Kernel concurrency contracts are real, not formalities:**
- `PsLookupProcessByProcessId` is PASSIVE-only — never under a FastMutex that is held at DISPATCH_LEVEL; snapshot under the lock, attempt unlocked, re-find the LIVE entry for state fixup; never dereference a raw ledger entry after the lock drops (process exit frees it).
- Post-op callbacks may run at DISPATCH: allocations there are nonpaged and bounded by fixed-size queues.
- The protected table holds PROCESS pids; a thread handle resolves via `PsGetThreadProcessId(thread)` before lookup — the raw TID never matches; attribution records keep the resolved pid.
- A code path is live only if a callback is REGISTERED to reach it (an unregistered disposition class silently disables its post-op branch).
- The drain is per-record drop+count: decode + `record_size` per record, skip sizeable rejects, drop the remainder only when the size header itself is unusable — one degenerate record never poisons a whole batch.

**Time:** driver timestamps are kernel FILETIME (100 ns since 1601). The drain loop maps them to fake unix ms (`filetime_to_unix_ms` + the boot's lazy offset anchored on the first record) and the pipeline carries `SandboxEvent::SourceDated(event, ts)` — correlate by session id, never raw driver timestamps.

- **Overflow policy:** process/registry class = overwrite-oldest + loss counter; drops class = stop-collect + counter (drop evidence is scarcer than process evidence); oversized items = skip + count.

**Kernel-side review lessons now encoded as contracts:** the sensor-ring drain runs inside `GET_DATA` (rings first, promoted records join the same batch); the injection state machine advances `PendingThread → (PendingNtdll|Ready)` on the notify hooks and injects via CAS from `Ready` (a fresh entry could otherwise NEVER reach `Injected` — the dead-sensor defect class); every PASSIVE-only `Zw*` (section create/map/duplicate, `PsLookupProcessByProcessId`) runs OUTSIDE the FastMutex via snapshot → unlock → work → re-find-live-entry; every `new (PooledObject)` honors its pool argument and DISPATCH-reachable objects (identity table, watch filters, queues) are nonpaged; ledger teardown (thread deref, ring unmap, section close) happens outside the lock; the drop-copy destination stream is pre-marked `CopyDone` so the driver never captures its own copy.

**Drops:** minifilter + hard-link tombstone at first write (same-MFT link → final content survives truncate/overwrite/delete; delete + recreate-same-path captured as two files); stream-copy fallback at cleanup (cross-volume, link failure); extension policy + normalized NT drops dir pushed via `SET_DROP_POLICY`; write-noise skip heuristic (write sizes {4096, 8192, 16384} with offset > 0); content-hash dedup stays in the agent's drops-collector; `DropCaptured` records are currently logged, not yet routed into the collector.

**Injection:** kernel user-APC at process-create onto the initial thread (delivered during loader init, before user code); `ntdll!LdrLoadDll` resolved once per boot by kernel-side PE export walk; a 20-byte target-side stub bridges the APC argument. Inject into ALL processes minus a blocklist (system core, PPL, our own) with LAZY activation — the DLL only registers (nonce-gated, one-shot) and installs hooks once scoped. Per-sensor unnamed section, kernel-mapped, duplicated into the target: Vyukov-style committed-slot ring (4096 × 40 B), lock-free kernel drain with sequence validation (corrupted host rings skipped + counted). Accepted v1 limits: registration race window (worst case = degraded telemetry for that one process), PPL targets fail in-target `LdrLoadDll` harmlessly (counted), WOW64 gets the x64 sensor.

**Sensor materialization** (`SensorStorePort`): per-boot random dir under `%ProgramData%\SecOutfall\sensors`, DACL-protected, SHA-256-pinned copy, injection armed ONLY with the verified NT path, previous boots pruned. An explicit `CREATOR_OWNER` ACE never matches at access check (`CO` is rewritten only on INHERITED ACEs) — grant the creating token's user explicitly.

**Agent integration:** `DriverEventSourceAdapter` (feature `driver`) drains `GET_DATA` and decodes via the golden-pinned `protocol::driver_wire` (per-record skip semantics); bounded pid→name cache for process-exit records. `DriverControlPort` (driven): `apply_policies` (injection/drops/protection blobs) + `apply_device_security` (caller-built self-relative SD, RtlValidRelativeSecurityDescriptor-validated, console-user SID included) + `set_file_watch` (file telemetry AND drop capture are gated behind the watch — the driver boots with it OFF, so the composition root pushes enabled-all-files whenever the driver source is active) + `query_stats`. Composition root pushes policies BEFORE the event source attaches (injection armed before any process can be created into an unpolled driver); every push failure = log, never a crash. Scoring chains run over `behavior.call` of SCOPED pids: unordered-per-pid one-shot detectors (`chain_injection` = cross-process VM write + thread creation; `chain_ransomware` = 8+ CryptEncrypt + shadow-copy deletion), plus `run_key_set`; weights in `[scoring]`. The session deadline measures BOOT-LOCAL monotonic time (scheduler start + scheduled uptime) — never fake-wall-clock deltas: a forward-dated `time.timestamp` would otherwise finalize session 0 instantly.

**v1 hook set (enrichment for scoring):** `NtCreateFile`/`NtWriteFile`/`NtDeleteFile`, `NtSetValueKey`, `NtCreateUserProcess`/`NtCreateThreadEx`, cross-process `NtAllocateVirtualMemory`/`NtWriteVirtualMemory`, `LdrLoadDll`, `NtDelayExecution`, `CryptEncrypt`, `ShellExecuteEx`/`WinExec`. The full id numbering (1–14, incl. sensor-classified variants `NT_SET_VALUE_KEY_RUN_KEY`/`NT_ALLOCATE_VM_CROSS_PROCESS`/`NT_WRITE_VM_CROSS_PROCESS`/`NT_DELETE_FILE_SHADOW_COPY`) is RESERVED in all three mirrors at once (`secoutfallCommon.h`, `protocol::driver_wire::behavior_api`, injectee `sensor::api`) — hooks land one by one but can never invent a conflicting id; the ring carries no strings, so path/handle-derived classifications MUST become distinct sensor-side ids.

**Acceptance status:** implemented and unit/golden-tested end-to-end; still pending lab-VM proof — driver load + dumper round-trip, sensor inject → register → behavior records into the agent pipeline (one-time prep in `driver/README.md`), and flood-chaos numbers from a real write storm.

## Path & platform-divergence rules

- Any logic feeding a Windows-style path string into `std::path` APIs diverges on Linux (`C:\...` is ONE component on Unix). Keep path-string logic textual: `domain::image_name` (`image_name`, `extension_of`, `is_absolute_path`) splits on BOTH `/` and `\`; `Path::file_name` on config/event paths is BANNED, use the helper.
- In tests, build paths with `join` (real components) instead of `Path::new("Z:\\...")` literals — `Path::ends_with` compares components, not strings.
- Parallel tests sharing a named pipe must use distinct names (`with_pipe_name` / `test_pipe(suffix)`) — `first_pipe_instance` and cross-connect otherwise break them.
- Linux test runs litter the checkout when tests use Windows-absolute default paths (they parse as relative on Linux): keep test state in per-run temp dirs. Litter dirs may contain invisible U+F03A private-use characters — delete by exact path, never by broad glob.

## Windows API quirks worth remembering

- `windows` crate 0.57: `ConvertStringSecurityDescriptorToSecurityDescriptorW` out-param style `(sddl, rev, &mut PSECURITY_DESCRIPTOR, None)`, length via `GetSecurityDescriptorLength`, `PSECURITY_DESCRIPTOR(std::ptr::null_mut())` + `.0.is_null()`, `Error::from_win32()` (no `from_thread`), `BOOL` not bool; `PsGetThreadProcessId` is single-arg returning a HANDLE.
- WDK 26100: `CmRegisterCallbackEx`/`CmUnRegisterCallback`/`CmCallbackGetKeyObjectIDEx` cookies are `LARGE_INTEGER` (docs say ULONG — the header wins); `POOL_FLAG_PAGED` (not `PagedPool`); unsigned literals in `CTL_CODE` overflow int — not a constant expression, breaks case labels; `OverrideTargetVersionDefines` starves `SUBSYSTEM_NATVER`.
- cert ops must run in a sanitized child powershell — pwsh7 `PSModulePath` pollution breaks the `Cert:` provider (see `sign.ps1`).
- New clippy releases keep adding lints (recent additions: `manual_is_multiple_of`, `collapsible_if` let-chains, `borrow_as_ptr`, `doc_markdown`, `items_after_statements`, `indexing_slicing` even after length guards — use `.get()`); expect to fix a few on toolchain bumps.

## Open items (small, non-blocking)

1. Controller side must implement protocol v3 (envelope, taxonomy, upload `meta`) — external repo; coordinate when it is updated.
2. Driver lab-VM acceptance (see Driver track): load + dumper + sensor round-trip; one-time prep in `driver/README.md`.
3. `user_actor.path` delivered over the IPC config push still carries the nonce on argv (documented residual risk; hardening = protected per-boot file, pattern exists in the sensor store).
4. Driver-track follow-ups: remaining sensor hooks (ids 5–14, reserved), `DropCaptured` → drops-collector routing, WOW64/x86 sensor (structs shaped for it), network ground truth (WFP callout — with the driver active and no WFP, net events disappear since ETW is off), real minifilter altitude + EV cert when leaving the lab, driver/device naming visibility to malware.

## Glossary

- **Study** — one full analysis run; N sessions separated by reboots.
- **Session** — one boot-to-reboot interval; has id, uptime, scoped processes, drops.
- **Scope** — set of processes deemed part of the analysis (seeded by target, inherited by parent PID); persisted across reboots in the scope DB.
- **Drop** — file written by a scoped process, matched by extension filter, copied + uploaded.
- **Target/sample** — the detonated malware.
- **Controller** — external fleet manager consuming agent reports.
- **User actor** — interactive-session module that observes the desktop (focus tracking, screenshots) and acts in it (reactive/scripted input). Shorthand: "UA".
- **Driver** — kernel-mode trusted event source, drop captor, injection engine, self-protection (`driver/`).
- **Injectee/sensor** — the DLL injected into processes; hooks ntdll-level APIs and reports through the driver (`crates/injectee`; hook set grows one API at a time from the reserved id table).
- **Finalize** — end-of-session orchestration (reports, clock offset, kills, persist, reboot/shutdown request).
