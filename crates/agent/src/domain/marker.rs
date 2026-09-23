//! Marker-process detection: the configured interactive-session marker
//! (legacy `explorer`) seen under ETW is the "interactive session is up"
//! signal for both the target launcher and the user-actor supervisor.

/// Marker-process check, tolerant of configured names with or without
/// `.exe` (legacy stored `explorer`, images report `explorer.exe`).
///
/// Empty names never match — not even each other. An empty configured marker
/// (config bug) must not be fired by every anonymous ETW process-start; an
/// empty observed image (ETW anomaly) must not match a real marker.
#[must_use]
pub fn is_marker_process(configured: &str, observed: &str) -> bool {
    if configured.is_empty() || observed.is_empty() {
        return false;
    }
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

    #[test]
    fn hostile_and_degenerate_names_never_match() {
        // Empty names on either side: an empty observed image is an ETW
        // anomaly, an empty configured marker is a config bug — neither may
        // "match" everything by degenerate equality.
        assert!(!is_marker_process("explorer", ""));
        assert!(!is_marker_process("", "explorer.exe"));
        assert!(!is_marker_process("", ""));
        // The .exe strip happens once, not recursively: a real image named
        // `explorer.exe.exe` is NOT the marker.
        assert!(!is_marker_process("explorer", "explorer.exe.exe"));
        // Similar-looking but distinct names stay distinct.
        assert!(!is_marker_process("explorer", "expl0rer.exe"));
        assert!(!is_marker_process("explorer", "explorer2.exe"));
    }
}
