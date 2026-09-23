//! Session scoring model — pure logic, legacy-grounded.
//!
//! Legacy (`ScoringManager`) kept the **maximum** per-signal score over the
//! session and reported it once at finalize; the weights were hardcoded and
//! its own parameters were ignored (bug #12). The rewrite keeps the max
//! semantics, makes the weights configuration (`[scoring]`), and widens the
//! CLI/interpreter set to the processes malware actually abuses.

/// Signals the scoring model reacts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreSignal<'a> {
    /// A CLI/interpreter process image entered the scope.
    CliInterpreter(&'a str),
    /// A drop was observed.
    DropObserved,
}

/// Weights, mirroring `[scoring]` config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScoreWeights {
    /// Score for a CLI/interpreter entering the scope.
    pub cli_started: u32,
    /// Score for an observed drop.
    pub drop_observed: u32,
}

/// Is this image one of the CLI/interpreter processes malware commonly abuses?
/// Case-insensitive, `.exe`-suffix tolerant.
#[must_use]
pub fn is_cli_interpreter(image: &str) -> bool {
    let lowered = image.to_ascii_lowercase();
    let bare = lowered.strip_suffix(".exe").unwrap_or(&lowered);
    matches!(
        bare,
        "cmd" | "powershell" | "pwsh" | "wscript" | "cscript" | "mshta" | "rundll32" | "regsvr32"
    )
}

/// Score one signal (`None` = not score-worthy), using the configured weights.
#[must_use]
pub fn score_signal(weights: &ScoreWeights, signal: &ScoreSignal<'_>) -> Option<u32> {
    match signal {
        ScoreSignal::CliInterpreter(image) if is_cli_interpreter(image) => {
            Some(weights.cli_started)
        }
        ScoreSignal::CliInterpreter(_) => None,
        ScoreSignal::DropObserved => Some(weights.drop_observed),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn weights() -> ScoreWeights {
        ScoreWeights { cli_started: 4, drop_observed: 5 }
    }

    #[test]
    fn cli_interpreters_are_recognized_case_insensitively() {
        for name in ["cmd", "CMD.exe", "PowerShell", "powershell.exe", "mshta.EXE", "wscript"] {
            assert!(is_cli_interpreter(name), "{name} should be a CLI interpreter");
        }
        for name in ["evil.exe", "notepad", "explorer.exe", "cmDEXplorer"] {
            assert!(!is_cli_interpreter(name), "{name} should not be a CLI interpreter");
        }
    }

    #[test]
    fn scores_follow_weights_and_max_semantics() {
        let w = weights();
        assert_eq!(score_signal(&w, &ScoreSignal::CliInterpreter("cmd.exe")), Some(4));
        assert_eq!(score_signal(&w, &ScoreSignal::CliInterpreter("evil.exe")), None);
        assert_eq!(score_signal(&w, &ScoreSignal::DropObserved), Some(5));
    }
}
