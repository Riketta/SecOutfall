//! Marker-process detection: the configured interactive-session marker
//! (legacy `explorer`) seen under ETW is the "interactive session is up"
//! signal for both the target launcher and the user-actor supervisor.

/// Marker-process check, tolerant of configured names with or without
/// `.exe` (legacy stored `explorer`, images report `explorer.exe`).
#[must_use]
pub fn is_marker_process(configured: &str, observed: &str) -> bool {
    strip_exe(observed).eq_ignore_ascii_case(strip_exe(configured))
}

/// Strip a trailing `.exe` (any case) for marker comparisons.
fn strip_exe(value: &str) -> &str {
    let split = value.len().checked_sub(4);
    match split.and_then(|at| value.get(at..)) {
        Some(suffix) if suffix.eq_ignore_ascii_case(".exe") => {
            value.get(..split.unwrap_or(0)).unwrap_or(value)
        }
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    use super::is_marker_process;

    #[test]
    fn matches_with_and_without_extension() {
        assert!(is_marker_process("explorer", "explorer.exe"));
        assert!(is_marker_process("explorer.exe", "explorer"));
        assert!(is_marker_process("explorer", "explorer"));
    }

    #[test]
    fn comparison_is_case_insensitive() {
        assert!(is_marker_process("Explorer", "EXPLORER.EXE"));
    }

    #[test]
    fn non_markers_are_rejected() {
        assert!(!is_marker_process("explorer", "evil.exe"));
        assert!(!is_marker_process("explorer", "explorer_helper.exe"));
    }
}
