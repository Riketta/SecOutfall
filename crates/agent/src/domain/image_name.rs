//! Image-name extraction from configured paths — pure text on purpose.
//!
//! `std::path` is host-separator-dependent: on Unix, `C:\Targets\evil.exe`
//! has no separators at all, so `Path::file_name` returns the whole string.
//! The configured target path is Windows-style by contract (the agent
//! detonates samples on Windows VMs), yet the bare image name it yields must
//! be identical wherever the code is *built or tested* — the scope tracker
//! matches it against ETW-reported process names. Textual splitting on both
//! separators keeps that deterministic on every host OS.

/// Last path segment, splitting on BOTH `/` and `\`.
///
/// A path that is only separators (or ends with one) yields an empty string;
/// callers already treat an empty expected name as "never matches"
/// (`ScopeTracker::expect` rejects it), which is the safe degradation for a
/// degenerate config path.
#[must_use]
pub fn image_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// Extension of the final path component, splitting on BOTH `/` and `\` —
/// the host-independent twin of [`image_name`]. `std::path::Path::extension`
/// on a Windows-style string diverges per host (`C:\dir.d\file`: no extension
/// on Windows, `d\file` on Unix). Dot-files (`.gitignore`) have no extension
/// and a trailing dot is an empty extension, mirroring `std::path`.
#[must_use]
pub fn extension_of(path: &str) -> Option<&str> {
    let component = image_name(path);
    let dot = component.rfind('.')?;
    if dot == 0 {
        return None;
    }
    component.get(dot + 1..)
}

#[cfg(test)]
mod tests {
    use super::{
        extension_of,
        image_name,
    };

    #[test]
    fn windows_style_paths_split_on_backslash_on_any_host() {
        // The Linux-CI regression: `Path::file_name` saw one component here.
        assert_eq!(image_name("C:\\Targets\\evil.exe"), "evil.exe");
        assert_eq!(image_name("C:\\Targets\\sub\\dir\\sample.js"), "sample.js");
    }

    #[test]
    fn unix_style_paths_split_on_slash() {
        assert_eq!(image_name("/usr/bin/evil"), "evil");
        assert_eq!(image_name("/tmp/странный/sample.js"), "sample.js");
    }

    #[test]
    fn mixed_separators_split_on_the_last_of_either() {
        assert_eq!(image_name("C:/Targets\\evil.exe"), "evil.exe");
        assert_eq!(image_name("C:\\Targets/evil.exe"), "evil.exe");
    }

    #[test]
    fn bare_names_pass_through() {
        assert_eq!(image_name("evil.exe"), "evil.exe");
        assert_eq!(image_name("wscript.exe"), "wscript.exe");
    }

    #[test]
    fn degenerate_paths_yield_empty_not_garbage() {
        // A trailing separator is a config bug; empty is safely inert
        // (an expected empty name never matches an observed process).
        assert_eq!(image_name("C:\\Targets\\"), "");
        assert_eq!(image_name(""), "");
        assert_eq!(image_name("\\"), "");
        assert_eq!(image_name("/"), "");
    }

    #[test]
    fn extension_of_matches_std_semantics_host_independently() {
        // THE divergence case: a dotted directory must not leak into the
        // extension (std::path on Unix: Some("d\\file"), Windows: None).
        assert_eq!(extension_of("C:\\dir.d\\file"), None);
        assert_eq!(extension_of("C:\\dir.d\\file.txt"), Some("txt"));
        assert_eq!(extension_of("/tmp/x.d/file"), None);
        // Case is preserved; callers lowercase for comparison.
        assert_eq!(extension_of("C:\\a\\b\\file.TXT"), Some("TXT"));
        // Dot-files have no extension (std::path parity).
        assert_eq!(extension_of("C:\\repo\\.gitignore"), None);
        assert_eq!(extension_of(".gitignore"), None);
        // Trailing dot: an empty extension (std::path parity).
        assert_eq!(extension_of("file."), Some(""));
        assert_eq!(extension_of("archive.tar.gz"), Some("gz"));
        assert_eq!(extension_of("no-extension"), None);
        assert_eq!(extension_of(""), None);
    }
}
