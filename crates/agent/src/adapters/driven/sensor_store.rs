//! `SensorStorePort` family: the real per-boot materializer and the fake.

pub mod fake;

#[cfg(all(windows, feature = "driver"))]
pub mod windows;

/// Random hex of `bytes` entropy (uuid v4 — no extra RNG dependency).
#[must_use]
pub fn random_hex(bytes: usize) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes * 2);
    while out.len() < bytes * 2 {
        let id = uuid::Uuid::new_v4();
        for byte in id.as_bytes() {
            let _ = write!(out, "{byte:02x}");
        }
    }
    out.truncate(bytes * 2);
    out
}

/// Win32 path → NT-form path (`\??\C:\...`), the form `LdrLoadDll` wants.
#[must_use]
pub fn to_nt_path(dos: &str) -> String {
    let trimmed = dos.trim_start_matches(r"\??\");
    format!(r"\??\{}", trimmed.replace('/', "\\"))
}

/// SHA-256 of `bytes`, lowercase hex.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{
        Digest,
        Sha256,
    };
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        for nibble in [byte >> 4, byte & 0x0f] {
            out.push(char::from_digit(u32::from(nibble), 16).unwrap_or('?'));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn random_hex_has_requested_length_and_is_random() {
        let a = random_hex(16);
        let b = random_hex(16);
        assert_eq!(a.len(), 32);
        assert_ne!(a, b, "uuid v4 randomness — a collision here is a bug");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(random_hex(1).len(), 2);
    }

    #[test]
    fn nt_paths_are_prefixed_and_slash_normalized() {
        assert_eq!(to_nt_path(r"C:\x\y.dll"), r"\??\C:\x\y.dll");
        assert_eq!(to_nt_path("C:/x/y.dll"), r"\??\C:\x\y.dll");
        // Already-NT paths survive unchanged (idempotent).
        assert_eq!(to_nt_path(r"\??\C:\x\y.dll"), r"\??\C:\x\y.dll");
    }

    #[test]
    fn sha256_matches_the_known_digest() {
        // Known empty-input digest.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
