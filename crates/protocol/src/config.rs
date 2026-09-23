//! Agent TOML config schema and the user-actor config pushed over IPC.
//!
//! Contract:
//! - Defaults live in code (`Default` impls below), never in the file — a missing
//!   section/key falls back to its default, like legacy but explicit.
//! - Unknown keys/sections are rejected with clear errors (no VersaINI-style
//!   silent mis-parsing: unparseable int → 0 must never happen again).
//! - No auto-back-fill of the file; `validate` checks cross-field invariants.
//!
//! Legacy INI → TOML mapping (behavioral parity, names improved):
//! `broker_uri`→`broker.uri`, `ctl_channel`→`broker.control_channel`,
//! `event_channel`→`broker.event_channel`, `elog_verbosity`→`broker.verbosity`,
//! `file_path`→`target.path`, `file_args`→`target.args` (native array),
//! `start_target_every_session`→`target.every_session`,
//! `uptimes`→`study.uptimes` (native array, seconds),
//! `autoshutdown`→`study.autoshutdown`,
//! `processes_to_terminate`→`study.processes_to_terminate` (native array),
//! `storage_path`→`study.scope_path`, `files_to_validate`→`study.files_to_validate`,
//! `drops_path`→`drops.path`, `drops_extensions`→`drops.extensions` (native array),
//! `drops_maxsize`→`drops.max_size`, `drops_limit_per_session`→`drops.limit_per_session`,
//! `drops_uri`→`drops.upload_uri`,
//! `screenshots_path`→`screenshots.path`, `ua_save_screenshots`→`screenshots.save`,
//! `ua_max_screenshots_per_session`→`screenshots.max_per_session`,
//! `screenshots_uri`→`screenshots.upload_uri`,
//! `system_time_timestamp`→`time.timestamp`, `system_time_offset`→`time.offset_secs`,
//! `external_module_path`→`user_actor.path`,
//! `ua_reactive_enabled`→`user_actor.reactive`, `ua_scripted_enabled`→`user_actor.scripted`,
//! `ua_focus_tracking_method`→`user_actor.focus_method`,
//! `ua_screencapture_enabled`→`user_actor.screencapture`,
//! `non_s0_process`→`platform.non_s0_process`,
//! `shutdown_delay`→`platform.shutdown_delay_secs`,
//! `runas_utility_path`→`platform.runas_utility_path`,
//! `debug_skiprebootandshutdown`→`debug.skip_reboot_and_shutdown`,
//! `debug_skipsystemtimemanipulation`→`debug.skip_time_manipulation`.
//! Dropped (dead in legacy): `trace_channel`, `try_start_drops`,
//! `resave_config_with_missing_fields`, `_file_path`/`_file_args` stash.

use serde::{
    Deserialize,
    Serialize,
};

/// How verbose the event stream to the Controller is (legacy `elog_verbosity`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventVerbosity {
    /// Report nothing but control/keepalive.
    None,
    /// Report scope-relevant events only (policy defined by the reporter plugin).
    Partial,
    /// Report everything the source produces.
    #[default]
    Full,
}

/// Interactive-process launch mechanism; adapters are swappable per config.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchMechanism {
    /// `CreateProcessAsUser` with the interactive user's duplicated token.
    #[default]
    Token,
    /// Legacy scheduled-task trick (EventID-777 + run-as-system helper).
    SchedTask,
}

/// Desktop focus tracking method (legacy `FocusTrackingMethod`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FocusMethod {
    /// 50 ms `GetForegroundWindow` polling.
    Polling,
    /// `EVENT_SYSTEM_FOREGROUND` / `EVENT_OBJECT_FOCUS` hooks.
    #[default]
    WinEvents,
    /// Hooks plus UIA element tracking (future work; reserved).
    WinEventsWithElements,
}

/// Broker connection and reporting verbosity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrokerConfig {
    /// NATS server URL (e.g. `nats://127.0.0.1:4222`).
    pub uri: String,
    /// Control subject: keepalive/reboot/shutdown.
    pub control_channel: String,
    /// Event subject: all reports and sandbox events.
    pub event_channel: String,
    /// Event stream verbosity gate.
    pub verbosity: EventVerbosity,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            uri: "nats://127.0.0.1:4222".to_owned(),
            control_channel: "control".to_owned(),
            event_channel: "events".to_owned(),
            verbosity: EventVerbosity::Full,
        }
    }
}

/// The detonated sample and its launch policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TargetConfig {
    /// Sample path; non-executables are resolved via shell associations.
    pub path: String,
    /// Sample arguments.
    pub args: Vec<String>,
    /// Relaunch the sample in every session, not only session 0.
    pub every_session: bool,
}

/// Study orchestration: session uptimes, early shutdown, scope DB location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StudyConfig {
    /// Session durations in seconds, one entry per planned session.
    /// An empty table means dynamic mode: sessions end when the scope dies.
    pub uptimes: Vec<u64>,
    /// Finalize early (and end the study) as soon as every scoped process died.
    pub autoshutdown: bool,
    /// Extra processes killed at every finalization.
    pub processes_to_terminate: Vec<String>,
    /// Scope DB path (atomic-write JSON).
    pub scope_path: String,
    /// Ransomware canary files; reserved (not yet enforced).
    pub files_to_validate: Vec<String>,
}

impl Default for StudyConfig {
    fn default() -> Self {
        Self {
            uptimes: Vec::new(),
            autoshutdown: false,
            processes_to_terminate: vec![
                "WINWORD".to_owned(),
                "POWERPNT".to_owned(),
                "EXCEL".to_owned(),
                "OfficeClickToRun".to_owned(),
            ],
            scope_path: "scope.json".to_owned(),
            files_to_validate: Vec::new(),
        }
    }
}

/// Drop collection and upload policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DropsConfig {
    /// Local copy directory.
    pub path: String,
    /// Extension filter (`*` = all, `none` = extensionless, dot optional).
    pub extensions: Vec<String>,
    /// Per-file size cap in bytes (enforced in the rewrite; legacy ignored it).
    pub max_size: u64,
    /// Max drops collected per session.
    pub limit_per_session: u32,
    /// Upload endpoint; `None` disables drop upload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_uri: Option<String>,
}

impl Default for DropsConfig {
    fn default() -> Self {
        Self {
            path: "Drops".to_owned(),
            extensions: [".txt", ".exe", ".dll", ".bat", ".ps1", ".py", ".js", ".vbs", "none"]
                .iter()
                .map(ToString::to_string)
                .collect(),
            max_size: 10 * 1024 * 1024,
            limit_per_session: 30,
            upload_uri: None,
        }
    }
}

/// Screenshot intake and upload policy (agent side).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScreenshotsConfig {
    /// Local save directory (when [`save`](Self::save) is on).
    pub path: String,
    /// Save received screenshots locally.
    pub save: bool,
    /// Max screenshots per session; also pushed to the user-actor as its capture quota.
    pub max_per_session: u32,
    /// Upload endpoint; `None` disables screenshot upload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_uri: Option<String>,
}

impl Default for ScreenshotsConfig {
    fn default() -> Self {
        Self { path: "Screenshots".to_owned(), save: false, max_per_session: 30, upload_uri: None }
    }
}

/// System time manipulation policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TimeConfig {
    /// Fake wall clock at study start, unix seconds; `0` = NTP resync then freeze.
    pub timestamp: u64,
    /// Seconds added to the clock at each finalization (may be negative).
    pub offset_secs: i64,
}

/// Platform mechanics that rarely change between studies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlatformConfig {
    /// Interactive-process launch mechanism.
    pub launch_mechanism: LaunchMechanism,
    /// Marker process signalling an interactive session (legacy: `explorer`).
    pub non_s0_process: String,
    /// Delay before requesting reboot/shutdown, seconds.
    pub shutdown_delay_secs: u32,
    /// Helper binary for the `SchedTask` mechanism.
    pub runas_utility_path: String,
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            launch_mechanism: LaunchMechanism::Token,
            non_s0_process: "explorer".to_owned(),
            shutdown_delay_secs: 5,
            runas_utility_path: "windows-run-as-system.exe".to_owned(),
        }
    }
}

/// User-actor launch and behavior toggles (`[user_actor]` section).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UserActorSection {
    /// User-actor binary path.
    pub path: String,
    /// React to focus changes (installer click-through).
    pub reactive: bool,
    /// Run scripted activities (notepad/calc/explorer scenarios).
    pub scripted: bool,
    /// Focus tracking method.
    pub focus_method: FocusMethod,
    /// Capture screenshots on focus changes.
    pub screencapture: bool,
}

impl Default for UserActorSection {
    fn default() -> Self {
        Self {
            path: "secoutfall-user-actor.exe".to_owned(),
            reactive: false,
            scripted: false,
            focus_method: FocusMethod::WinEvents,
            screencapture: false,
        }
    }
}

/// Telemetry egress policy (`[telemetry]` section).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    /// Master switch for Sentry-protocol egress (local `GlitchTip`).
    pub sentry_enabled: bool,
    /// Agent DSN; empty disables agent reporting even when enabled.
    pub dsn: String,
    /// User-actor DSN, pushed over IPC; empty disables user-actor reporting.
    pub user_actor_dsn: String,
}

/// Scoring weights (`[scoring]` section).
///
/// Legacy scored process starts with hardcoded values and ignored its own
/// parameters entirely (bug #12); here the weights are real configuration. The
/// session score is the **maximum** over observed signals (legacy parity).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScoringConfig {
    /// Score for a CLI/interpreter process entering the scope.
    pub cli_started: u32,
    /// Score for an observed drop.
    pub drop_observed: u32,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self { cli_started: 4, drop_observed: 5 }
    }
}

/// Debug switches (`[debug]` section) — for development on non-VM hosts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DebugConfig {
    /// Do not request reboot/shutdown at finalization.
    pub skip_reboot_and_shutdown: bool,
    /// Do not manipulate the system clock.
    pub skip_time_manipulation: bool,
    /// Log to console in addition to rolling files.
    pub console: bool,
}

/// Complete agent configuration (`C:\Agent.toml`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    /// Broker connection and reporting verbosity.
    pub broker: BrokerConfig,
    /// The detonated sample.
    pub target: TargetConfig,
    /// Study orchestration.
    pub study: StudyConfig,
    /// Drop collection.
    pub drops: DropsConfig,
    /// Screenshot intake.
    pub screenshots: ScreenshotsConfig,
    /// System time manipulation.
    pub time: TimeConfig,
    /// Platform mechanics.
    pub platform: PlatformConfig,
    /// User-actor section.
    pub user_actor: UserActorSection,
    /// Session scoring weights.
    pub scoring: ScoringConfig,
    /// Telemetry egress.
    pub telemetry: TelemetryConfig,
    /// Debug switches.
    pub debug: DebugConfig,
}

/// Errors from config parsing and validation.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// TOML syntax or schema violation (unknown/ill-typed keys included).
    #[error("config parse error: {0}")]
    Parse(#[from] toml::de::Error),
    /// Cross-field invariants violated.
    #[error("config validation failed: {0}")]
    Validation(String),
}

impl AgentConfig {
    /// Parse and schema-validate a TOML document.
    ///
    /// # Errors
    /// [`ConfigError::Parse`] on TOML syntax, unknown keys/sections, or ill-typed
    /// values.
    pub fn from_toml_str(toml_source: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(toml_source)?)
    }

    /// Cross-field invariants beyond the schema. Run after loading; adapters may
    /// add their own (e.g. URI shape) checks.
    ///
    /// # Errors
    /// [`ConfigError::Validation`] listing every violated invariant.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut problems = Vec::new();
        if self.target.path.is_empty() {
            problems.push("target.path must not be empty");
        }
        if self.broker.uri.is_empty() {
            problems.push("broker.uri must not be empty");
        }
        if self.broker.control_channel.is_empty() {
            problems.push("broker.control_channel must not be empty");
        }
        if self.broker.event_channel.is_empty() {
            problems.push("broker.event_channel must not be empty");
        }
        if self.drops.max_size == 0 {
            problems.push("drops.max_size must be positive");
        }
        if self.drops.limit_per_session == 0 {
            problems.push("drops.limit_per_session must be positive");
        }
        if self.screenshots.max_per_session == 0 {
            problems.push("screenshots.max_per_session must be positive");
        }
        if self.user_actor.path.is_empty() {
            problems.push("user_actor.path must not be empty");
        }
        if self.platform.launch_mechanism == LaunchMechanism::SchedTask
            && self.platform.runas_utility_path.is_empty()
        {
            problems.push("platform.runas_utility_path must not be empty for sched_task");
        }
        if self.telemetry.sentry_enabled && self.telemetry.dsn.is_empty() {
            problems.push("telemetry.dsn must not be empty when sentry_enabled");
        }

        if problems.is_empty() { Ok(()) } else { Err(ConfigError::Validation(problems.join("; "))) }
    }

    /// Build the runtime config pushed to the user-actor in `WELCOME` — the
    /// module reads no files, this is everything it gets.
    #[must_use]
    pub fn user_actor_config(&self) -> UserActorConfig {
        UserActorConfig {
            console: self.debug.console,
            reactive: self.user_actor.reactive,
            scripted: self.user_actor.scripted,
            focus_method: self.user_actor.focus_method,
            screencapture: self.user_actor.screencapture,
            max_screenshots_per_session: self.screenshots.max_per_session,
            telemetry_dsn: if self.telemetry.sentry_enabled
                && !self.telemetry.user_actor_dsn.is_empty()
            {
                Some(self.telemetry.user_actor_dsn.clone())
            } else {
                None
            },
        }
    }
}

/// Runtime configuration pushed to the user-actor in the IPC `WELCOME` frame.
///
/// Kept deliberately small and file-free: the user-actor never reads `Agent.toml`.
#[allow(clippy::struct_excessive_bools)] // the config mirrors behavior toggles 1:1
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UserActorConfig {
    /// Console logging on (debug builds only matter).
    pub console: bool,
    /// React to focus changes.
    pub reactive: bool,
    /// Run scripted activities.
    pub scripted: bool,
    /// Focus tracking method.
    pub focus_method: FocusMethod,
    /// Capture screenshots on focus changes.
    pub screencapture: bool,
    /// Capture quota per session.
    pub max_screenshots_per_session: u32,
    /// Sentry-protocol DSN for direct `GlitchTip` reporting; `None` disables it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub telemetry_dsn: Option<String>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// A full document mirroring the legacy `Agent.ini` sample, expressed in TOML.
    const FULL_SAMPLE: &str = r#"
        [broker]
        uri = "nats://127.0.0.1:4222"
        control_channel = "control"
        event_channel = "events"
        verbosity = "full"

        [target]
        path = "C:\\Targets\\DummySampleSimple.exe"
        args = ["--iterations", "1000"]
        every_session = false

        [study]
        uptimes = [6000, 6000, 6000]
        autoshutdown = false
        processes_to_terminate = ["notepad", "CalculatorApp"]
        scope_path = "scope.json"
        files_to_validate = []

        [drops]
        path = "Drops"
        extensions = [".txt", ".ps1", ".bat", ".exe", ".dll", ".cld", ".dat", ".cvd"]
        max_size = 20971520
        limit_per_session = 30
        upload_uri = "http://127.0.0.1:8085"

        [screenshots]
        path = "Screenshots"
        save = false
        max_per_session = 100
        upload_uri = "http://127.0.0.1:8080"

        [time]
        timestamp = 1465182366
        offset_secs = 2680000

        [platform]
        launch_mechanism = "token"
        non_s0_process = "explorer"
        shutdown_delay_secs = 5
        runas_utility_path = "windows-run-as-system.exe"

        [user_actor]
        path = "secoutfall-user-actor.exe"
        reactive = false
        scripted = false
        focus_method = "win_events"
        screencapture = true

        [telemetry]
        sentry_enabled = true
        dsn = "http://glitchtip.lab.local/agent-project/1"
        user_actor_dsn = "http://glitchtip.lab.local/user-actor-project/2"

        [debug]
        skip_reboot_and_shutdown = false
        skip_time_manipulation = false
        console = true
    "#;

    #[test]
    fn full_sample_parses_to_expected_values() {
        let config = AgentConfig::from_toml_str(FULL_SAMPLE).unwrap();

        assert_eq!(config.broker.uri, "nats://127.0.0.1:4222");
        assert_eq!(config.broker.verbosity, EventVerbosity::Full);
        assert_eq!(config.target.args, vec!["--iterations", "1000"]);
        assert_eq!(config.study.uptimes, vec![6000, 6000, 6000]);
        assert_eq!(config.study.processes_to_terminate, vec!["notepad", "CalculatorApp"]);
        assert_eq!(config.drops.max_size, 20 * 1024 * 1024);
        assert_eq!(config.drops.upload_uri.as_deref(), Some("http://127.0.0.1:8085"));
        assert_eq!(config.screenshots.max_per_session, 100);
        assert_eq!(config.time.timestamp, 1_465_182_366);
        assert_eq!(config.time.offset_secs, 2_680_000);
        assert_eq!(config.platform.launch_mechanism, LaunchMechanism::Token);
        assert_eq!(config.user_actor.focus_method, FocusMethod::WinEvents);
        assert!(config.user_actor.screencapture);
        assert!(config.telemetry.sentry_enabled);
        assert!(config.debug.console);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn missing_sections_fall_back_to_defaults() {
        let config = AgentConfig::from_toml_str(
            "[broker]\nuri = \"nats://10.0.0.1:4222\"\n\n[target]\npath = \"C:\\\\t.exe\"\n",
        )
        .unwrap();

        assert_eq!(config.broker.control_channel, "control");
        assert_eq!(config.study.uptimes, Vec::<u64>::new());
        assert_eq!(config.drops.limit_per_session, 30);
        assert_eq!(config.platform.shutdown_delay_secs, 5);
        assert_eq!(config.user_actor.focus_method, FocusMethod::WinEvents);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn unknown_key_is_rejected() {
        let source = "[broker]\nuri = \"x\"\nctl_channel = \"legacy\"\n";
        let error = AgentConfig::from_toml_str(source).unwrap_err();
        assert!(error.to_string().contains("ctl_channel"), "{error}");
    }

    #[test]
    fn unknown_section_is_rejected() {
        let error = AgentConfig::from_toml_str("[internal]\nfoo = 1\n").unwrap_err();
        assert!(error.to_string().contains("internal"), "{error}");
    }

    #[test]
    fn ill_typed_value_is_rejected_not_zero_filled() {
        let source = "[study]\nuptimes = [\"abc\"]\n";
        assert!(AgentConfig::from_toml_str(source).is_err());
    }

    #[test]
    fn enum_values_are_validated() {
        let source = "[platform]\nlaunch_mechanism = \"teleport\"\n";
        assert!(AgentConfig::from_toml_str(source).is_err());
    }

    #[test]
    fn validation_catches_empty_target_path() {
        let config = AgentConfig::default();
        let error = config.validate().unwrap_err();
        assert!(error.to_string().contains("target.path"), "{error}");
    }

    #[test]
    fn validation_catches_sentry_without_dsn() {
        let mut config = AgentConfig::default();
        config.target.path = "C:\\t.exe".to_owned();
        config.telemetry.sentry_enabled = true;
        let error = config.validate().unwrap_err();
        assert!(error.to_string().contains("telemetry.dsn"), "{error}");
    }

    #[test]
    fn user_actor_config_is_built_from_sections() {
        let mut config = AgentConfig::default();
        config.debug.console = true;
        config.user_actor.reactive = true;
        config.user_actor.screencapture = true;
        config.screenshots.max_per_session = 100;
        config.telemetry.sentry_enabled = true;
        config.telemetry.user_actor_dsn = "http://glitchtip/ua".to_owned();

        let ua = config.user_actor_config();
        assert!(ua.console);
        assert!(ua.reactive);
        assert!(ua.screencapture);
        assert_eq!(ua.max_screenshots_per_session, 100);
        assert_eq!(ua.telemetry_dsn.as_deref(), Some("http://glitchtip/ua"));
    }

    #[test]
    fn user_actor_telemetry_disabled_without_dsn() {
        let mut config = AgentConfig::default();
        config.telemetry.sentry_enabled = true;
        assert_eq!(config.user_actor_config().telemetry_dsn, None);
    }

    #[test]
    fn scoring_section_has_legacy_parity_defaults_and_parses() {
        // Missing section → legacy-parity defaults.
        let config = AgentConfig::from_toml_str("[target]\npath = 'x'\n").unwrap();
        assert_eq!(config.scoring.cli_started, 4);
        assert_eq!(config.scoring.drop_observed, 5);

        let config = AgentConfig::from_toml_str(
            "[target]\npath = 'x'\n\n[scoring]\ncli_started = 10\ndrop_observed = 20\n",
        )
        .unwrap();
        assert_eq!(config.scoring.cli_started, 10);
        assert_eq!(config.scoring.drop_observed, 20);
    }
}
