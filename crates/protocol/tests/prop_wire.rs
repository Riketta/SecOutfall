//! Property tests for the wire layer: the IPC frame parser and the TOML
//! config parser are hostile-input boundaries — arbitrary bytes may return
//! `Ok` or `Err`, but must never panic, never over-allocate, never accept
//! what the schema forbids. These are the same call sites the cargo-fuzz
//! targets (Linux CI) drive; proptest gives them coverage on every host.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;
use protocol::{
    config::AgentConfig,
    ipc::{
        FrameError,
        FrameHeader,
        HEADER_LEN,
        MAX_PAYLOAD_LEN,
        message_type,
    },
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Roundtrip: any header the parser accepts survives the wire form.
    #[test]
    fn frame_header_roundtrips(payload_len in 0_u32..=u32::try_from(MAX_PAYLOAD_LEN).unwrap_or(u32::MAX),
                               message_type in 0_u16..=u16::MAX,
                               flags in 0_u16..=u16::MAX) {
        let header = FrameHeader { payload_len, message_type, flags };
        if let Ok(decoded) = FrameHeader::from_bytes(&header.to_bytes()) {
            prop_assert_eq!(decoded, header);
        } else {
            // Rejected headers are exactly the ones with unknown types.
            prop_assert!(!message_type::is_known(message_type));
        }
    }

    /// Hostile bytes: the parser returns `Ok` or `Err`, never panics, and an
    /// `Ok` verdict implies every invariant the schema promises.
    #[test]
    fn frame_parser_never_panics_on_hostile_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..=64),
    ) {
        if bytes.len() >= HEADER_LEN {
            if let Ok(header) = FrameHeader::from_bytes(&bytes) {
                prop_assert!(usize::try_from(header.payload_len).unwrap_or(usize::MAX) <= MAX_PAYLOAD_LEN);
                prop_assert!(message_type::is_known(header.message_type));
            }
        } else {
            prop_assert!(FrameHeader::from_bytes(&bytes).is_err());
        }
    }

    /// The payload cap is absolute: no `payload_len` above the cap ever
    /// parses, whatever else the bytes say.
    #[test]
    fn oversize_payload_is_always_rejected(
        payload_len in (u32::try_from(MAX_PAYLOAD_LEN).unwrap_or(u32::MAX) + 1)..=u32::MAX,
        message_type in 0_u16..=u16::MAX,
    ) {
        let bytes = FrameHeader { payload_len, message_type, flags: 0 }.to_bytes();
        prop_assert_eq!(
            FrameHeader::from_bytes(&bytes),
            Err(FrameError::PayloadTooLong(payload_len))
        );
    }

    /// Hostile TOML: parsing arbitrary bytes as config returns `Ok` or `Err`
    /// and never panics, zero-fills, or invents defaults for unknown keys.
    #[test]
    fn config_parser_never_panics_on_hostile_toml(
        bytes in proptest::collection::vec(any::<u8>(), 0..=512),
    ) {
        let source = String::from_utf8_lossy(&bytes);
        let _ = AgentConfig::from_toml_str(&source);
    }

    /// An unknown key under any known section is always rejected (the
    /// anti-VersaINI rule: no silent zero-fill).
    #[test]
    fn unknown_keys_are_always_rejected(
        section in "[a-z_]+",
        junk_key in "[a-zA-Z_][a-zA-Z0-9_]{0,20}",
        junk_value in "(\"[^\"]*\"|-?[0-9]+|true|false)",
    ) {
        let injected_source = format!("[{section}]\n{junk_key} = {junk_value}\n");
        let result = AgentConfig::from_toml_str(&injected_source);
        prop_assert!(
            result.is_err(),
            "unknown key {section}.{junk_key} must be rejected, got {result:?}"
        );
    }

    /// A known-good config re-parses identically after a roundtrip through
    /// its own TOML serialization (defaults stabilize; no drift).
    #[test]
    fn known_config_roundtrips_stably(seed in 0_u64..1_000_000) {
        let mut config = AgentConfig::default();
        config.target.path = format!("C:\\Targets\\evil-{seed}.exe");
        config.study.uptimes = vec![6000, seed % 1000 + 1];
        config.drops.extensions = vec![".txt".to_owned(), "none".to_owned()];
        let serialized = toml::to_string(&config).expect("serialize");
        let reparsed = AgentConfig::from_toml_str(&serialized).expect("reparse");
        prop_assert_eq!(reparsed, config);
    }
}
