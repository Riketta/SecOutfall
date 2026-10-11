# SecOutfall

An agentic **Windows malware analysis sandbox** written in Rust, with a C
kernel-mode driver and an injected sensor DLL. An in-VM agent detonates a
sample (the *target*) inside an isolated Windows VM and observes it; an
external Controller (separate repository) consumes its reports over NATS and
HTTP.

One analysis run = a **study** = N **sessions** separated by reboots. The
agent (a session-0 service), the kernel driver, and the scope database
persist across reboots; each boot opens a new session with an incrementing
id. The system clock inside the VM is deliberately fake — reports are
correlated by study/session ids, never by wall timestamps.

> ⚠️ This is dual-use security tooling. Install it only inside isolated
> analysis VMs — the analyzed malware is an adversarial user, and every byte
> coming from inside the VM is hostile input.

## How it observes

- **Kernel driver** (`secoutfall.sys`, optional) — the trusted component. It
  starts before services and malware on every boot and provides process /
  thread / image / registry / file telemetry, tamper-proof drop capture
  (hard-link tombstone + stream-copy fallback), user-APC injection of the
  sensor DLL with a nonce-gated handshake, and self-protection (ObCallbacks
  strip dangerous handle access to protected processes, reporting every
  attempt).
- **Sensor DLL** (`injectee.dll`, optional) — injected by the driver into
  analyzed processes; hooks a set of ntdll APIs and reports what the host
  process asks the OS to do. Enrichment only: kernel callbacks remain ground
  truth, and sensor silence is itself a scoring signal.
- **ETW** (fallback) — user-mode kernel-trace consumption when the driver is
  not deployed. Exactly one event source is active at a time, selected by
  config.
- **User actor** — helper process in the interactive session: observes the
  desktop (focus tracking, screenshots) and acts in it (reactive + scripted
  input). Receives all config over IPC from the agent; reads no files.
- **Agent** — the session-0 service tying it together: scope tracking, drop
  collection/upload, screenshot intake, scoring (single signals + behavior
  chains such as injection and ransomware), NATS reporting, and
  finalization/reboot orchestration.

Architecture: hexagonal (ports & adapters) **microkernel** with a middleware
pipeline and an event bus; event-driven, fire-and-forget core. The
architecture doctrine, conventions, and development rules live in the
repository `AGENTS.md`.

## Crates

| Crate | Kind | What it is |
|---|---|---|
| `kernel` | lib | Generic microkernel: ports, pipeline runner, in-memory event bus, plugin lifecycle. Pure Rust, no Windows deps, tested on any OS. |
| `protocol` | lib | Shared boundary models: canonical event taxonomy, NATS envelope + payload DTOs (v3), IPC frame schema, driver wire records, strict TOML config. No kernel types leak here. |
| `agent` | lib + bin `secoutfall-agent` | The session-0 agent. Lib: hexagon (domain, app, plugins, adapters). Bin: thin composition root. |
| `user-actor` | lib + bin `secoutfall-user-actor` | Interactive-session component: observes the desktop (focus tracking, screenshots) and acts in it (reactive + scripted input). Kernel-light hexagon. |
| `devtools` | bins | `dummy-broker` (NATS traffic observer), `session-sim` (fake-source multi-session study simulator). |
| `crates/injectee` | cdylib `injectee.dll` | Sensor DLL: declarative API hooks (retour static detours) behind the `hook!` macro, nonce-gated driver handshake, lock-free event ring. Own **nightly** workspace, excluded from the main one — build from its directory. |
| `driver/` | C kernel driver (WDM + minifilter) `secoutfall.sys` | Trusted early event source, drop captor, injection engine, self-protection. Own WDK build — `driver/build.ps1`; see [`driver/README.md`](driver/README.md). Not part of the cargo workspace. |
| `fuzz/` | separate workspace | cargo-fuzz targets (IPC framing, config parsing, screenshot payload decode, driver wire decode). Linux + nightly only. |

## The agent binary

```
secoutfall-agent [MODE] [--config <path>] [--target <path>] [--demo] [--start]
```

| Mode | What it does |
|---|---|
| *(default)* `console` | Full runtime on this host; Ctrl+C finalizes the session. |
| `console --demo` | Same runtime over fakes (in-memory scope, console-printed events) for dev boxes without a NATS broker or VM isolation. |
| `local` | Standalone run for quick local target testing: real launchers and adapters, no broker/Controller/user-actor needed. Every wire event is printed to stdout AND appended to `events.jsonl` (one envelope per line); the final scope snapshot lands in `local-scope.json`. Safety-forced: never shifts the clock, kills processes, or requests a reboot. Point it at a sample with `--target <path>`, or a full `--config <path>`. |
| `simulate` | Scripted single-session demo, fakes only, prints a report. |
| `service` | SCM service mode (`--features service`); Stop/Shutdown become finalize events. |
| `install` | Create the SCM entry pointing at this exe with `--config <path>` (validates the config first; refuses double-install). `--start` boots it immediately. |
| `uninstall` | Stop (bounded wait) and delete the SCM entry. |
| `etw-probe [secs]` | Live kernel-trace probe (`--features etw`, admin required). |

`--config` defaults to `C:\Agent.toml`. The sample config with every key and
default documented is [`docs/Agent.toml`](docs/Agent.toml) — parsing is strict
(unknown/ill-typed keys rejected), and a golden test keeps that file in sync
with the schema.

Feature flags (`agent`): `etw` (kernel-trace consumption), `driver` (kernel
driver event source + control device), `launcher` (`CreateProcessAsUser`
token launcher), `schedtask` (EventID-777 scheduled-task launcher via the
run-as helper), `associations` (shell-association target resolution),
`killer` (finalize process termination), `time_shift` (`SetSystemTime` fake
clock), `ipc` (user-actor named-pipe server), `service` (SCM mode +
install/uninstall).

Feature flags (`user-actor`): `ipc`, `focus-poll`, `focus-winevents`,
`capture`, `input`, `apps`.

## Wire protocol & IPC

- NATS, two channels (`[broker] control_channel` / `event_channel`), envelope
  `{"v":3,"type","ts","study","session","seq","data"}` — `seq` is monotonic
  per publisher for Controller-side loss detection. The agent publishes only;
  it never subscribes. With the driver active, hooked-API activity arrives as
  `behavior.call` events feeding the scoring chains.
- HTTP uploads: multipart `meta` (JSON) + `blob` (octet-stream), streamed and
  size-capped.
- Agent ↔ user-actor: named pipe `\\.\pipe\secoutfall\user-actor-v1`,
  8-byte-framed (hard cap 16 MiB), restrictive DACL, per-boot nonce
  handshake, config pushed in `Welcome`.
- Agent ↔ driver: IOCTL drain on a SDDL-secured device (SYSTEM +
  Administrators); wire records and control blobs are pinned byte-for-byte
  across the C and Rust sides by committed golden fixtures.

## Quick start

Dev box (no VM needed):

```sh
cargo run -p agent -- simulate                 # scripted study demo
cargo run -p agent -- console --demo           # full runtime over fakes

# Standalone: real adapters against a local target, events on stdout,
# no broker/Controller needed (add --features etw and run elevated to
# actually observe process/file activity):
cargo run -p agent --features launcher -- local --target C:\Windows\System32\notepad.exe

cargo run -p devtools --bin dummy-broker       # observe real NATS traffic
cargo run -p devtools --bin session-sim        # 24-session study in milliseconds
```

`dummy-broker` subscribes to the control + event channels and pretty-prints
every envelope, counting per-type traffic and flagging sequence gaps — point
it at a running nats-server with `--uri`, or let it spawn one with
`--spawn <path-to-nats-server.exe>`.

Analysis VM (Windows 10/11 x64, isolated, snapshot first):

```sh
copy secoutfall-agent.exe C:\
copy secoutfall-user-actor.exe C:\
copy Agent.toml C:\            # see docs/Agent.toml
C:\secoutfall-agent.exe install --config C:\Agent.toml
C:\secoutfall-agent.exe install --start   # or let the next boot start it
```

To run with the kernel driver, build + test-sign it and prep the VM once
(Secure Boot off, memory integrity off, `bcdedit /set testsigning on`,
certificate import) — the full procedure is in
[`driver/README.md`](driver/README.md). Then set `[driver] enabled = true`
and `[driver] sensor_path` to the built `injectee.dll` (NT form) in the
config.

## Telemetry

`tracing` macros everywhere; subscriber = `registry()` + `EnvFilter` + console
+ a non-blocking daily rolling file under `[telemetry] log_dir` (default
`C:\ProgramData\SecOutfall\logs`) + `sentry-tracing` layer → a **local
GlitchTip**. Sentry joins as a layer in the single global registry — no
conflict with `tracing-subscriber`. Egress is gated by `[telemetry]
sentry_enabled` (egress from the analysis VM is visible to malware). The user
actor reports to GlitchTip directly with its own DSN, pushed over IPC, and
writes its own rolling file in the same default directory. Timestamps are
skewed by the fake clock — correlate by session id, never by SDK timestamps.

## Testing

```sh
cargo test --workspace --all-features   # unit + integration + property + chaos
```

- Fakes per port for every plugin; deterministic injected clock.
- `proptest` property suites on the hostile-input boundaries (wire framing,
  screenshot payloads, config, driver wire, scope membership, domain models)
  — the same call sites the Linux-CI fuzz targets drive.
- Chaos suites: broker death mid-session, share-locked/vanishing/Unicode
  drops, unusable drops volume, IPC peer death mid-frame, 200-task focus
  storms.
- A complete 24-boot study simulation (reboot/shutdown control tail,
  gap-free sequences, stable study id, driver-fed ransomware chain) runs in
  ~1 second as part of the regular suite.

## Development

Toolchains are pinned by files: `rust-toolchain.toml` (workspace: stable,
clippy + rustfmt) and `fuzz/rust-toolchain.toml` (nightly). Formatting needs
nightly rustfmt because the `rustfmt.toml` uses unstable options:

```sh
cargo +nightly fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

CI (GitHub Actions) runs fmt + clippy + tests + `cargo-deny` on Linux; on
Windows it runs clippy + tests twice (default and all features — the default
lane does not see Windows-feature-gated code), a full build, an explicit
nightly build of the `crates/injectee` workspace, and the driver build via
the Windows SDK + WDK.
