//! Drop copy naming — pure helpers for the collector's generated artifact
//! names (`{session}-{seq}-{hash8}.{ext}`, per the artifact naming scheme).
//!
//! The extension comes from a file name the analyzed malware chose, so it is
//! hostile input: it is whitelisted (ASCII alphanumerics, `-`, `_`), length-
//! capped, and never empty. This kills a whole attack class on the copy side:
//! colon-suffixed names (`file.js:ads`) cannot mint NTFS alternate data
//! streams in the drops directory, reserved-device names degrade harmlessly,
//! and absurd lengths cannot break filesystems.

/// Maximum kept extension length in the generated copy name.
const MAX_EXTENSION_LEN: usize = 16;

/// Fallback extension when nothing survives sanitization.
const FALLBACK_EXTENSION: &str = "bin";

/// Sanitize a source extension for the generated copy name.
#[must_use]
pub fn sanitize_extension(extension: &str) -> String {
    let cleaned: String = extension
        .chars()
        .take(MAX_EXTENSION_LEN)
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .collect();
    if cleaned.is_empty() { FALLBACK_EXTENSION.to_owned() } else { cleaned.to_lowercase() }
}

/// The generated copy file name: `{session}-{seq}-{hash8}.{ext}`.
#[must_use]
pub fn copy_file_name(session: u32, seq: u64, hash8: &str, sanitized_extension: &str) -> String {
    format!("{session}-{seq}-{hash8}.{sanitized_extension}")
}

/// First 8 hex characters of a SHA-256 digest (lowercase).
#[must_use]
pub fn hash8(digest: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(8);
    for byte in digest.iter().take(4) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn extension_is_whitelisted_and_lowercased() {
        assert_eq!(sanitize_extension("TXT"), "txt");
        assert_eq!(sanitize_extension("tar.gz-1"), "targz-1");
        assert_eq!(sanitize_extension("js:ads"), "jsads");
    }

    #[test]
    fn hostile_extensions_degrade_to_bin() {
        assert_eq!(sanitize_extension(""), "bin");
        assert_eq!(sanitize_extension(":"), "bin");
        assert_eq!(sanitize_extension(":$DATA"), "data");
        assert_eq!(sanitize_extension("кон"), "bin");
    }

    #[test]
    fn extension_is_length_capped() {
        let long = "a".repeat(64);
        assert_eq!(sanitize_extension(&long), "a".repeat(MAX_EXTENSION_LEN));
    }

    #[test]
    fn copy_name_follows_the_naming_scheme() {
        assert_eq!(copy_file_name(3, 42, "ab12cd34", "txt"), "3-42-ab12cd34.txt");
    }

    #[test]
    fn hash8_is_the_digest_prefix() {
        let mut digest = [0_u8; 32];
        digest[0] = 0xAB;
        digest[1] = 0x12;
        // 8 hex chars = first 4 bytes.
        assert_eq!(hash8(&digest), "ab120000");
    }
}
