//! Fuzz the strict TOML config parser — `C:\Agent.toml` is attacker-modified
//! state inside the VM. Any byte sequence may parse or fail, but must never
//! panic, and parsing must be deterministic (same bytes → same verdict).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let source = String::from_utf8_lossy(data);
    let first = protocol::config::AgentConfig::from_toml_str(&source);
    let second = protocol::config::AgentConfig::from_toml_str(&source);
    match (first, second) {
        (Ok(config_a), Ok(config_b)) => assert_eq!(config_a, config_b, "parse determinism"),
        (Err(error_a), Err(error_b)) => assert_eq!(error_a.to_string(), error_b.to_string()),
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => panic!("nondeterministic config parse"),
    }
});
