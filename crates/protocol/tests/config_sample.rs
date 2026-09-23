//! Golden parity test: the shipped `docs/Agent.toml` must never drift from
//! the strict config schema. Parsing it must yield exactly the built-in
//! defaults (plus the one non-empty `target.path` the sample sets for
//! validation), and the result must pass cross-field validation. If a config
//! key is added, renamed, retyped, or its default changes, this test breaks
//! until the shipped sample is updated — that is the point.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use protocol::config::{
    AgentConfig,
    TargetConfig,
};

const SAMPLE: &str = include_str!("../../../docs/Agent.toml");

/// The documented sample, as the golden test expects it: everything at its
/// default value except the sample path.
fn expected_config() -> AgentConfig {
    AgentConfig {
        target: TargetConfig {
            path: "C:\\Targets\\sample.exe".to_owned(),
            ..TargetConfig::default()
        },
        ..AgentConfig::default()
    }
}

#[test]
fn sample_matches_documented_defaults() {
    let parsed = AgentConfig::from_toml_str(SAMPLE).unwrap();
    assert_eq!(parsed, expected_config(), "docs/Agent.toml drifted from the schema defaults");
}

#[test]
fn sample_is_a_valid_runtime_config() {
    let parsed = AgentConfig::from_toml_str(SAMPLE).unwrap();
    parsed.validate().expect("shipped sample must pass validation");
}

#[test]
fn stripped_sample_still_parses_to_the_same_config() {
    // Operators are told that whole sections are optional; dropping every
    // commented-out suggestion and any section must not change the meaning.
    let minimal = "[target]\npath = \"C:\\\\Targets\\\\sample.exe\"\n";
    let parsed = AgentConfig::from_toml_str(minimal).unwrap();
    assert_eq!(parsed, expected_config());
}
