//! Session scoring model — pure logic, legacy-grounded.
//!
//! Legacy (`ScoringManager`) kept the **maximum** per-signal score over the
//! session and reported it once at finalize; the weights were hardcoded and
//! its own parameters were ignored (bug #12). The rewrite keeps the max
//! semantics, makes the weights configuration (`[scoring]`), and widens the
//! CLI/interpreter set to the processes malware actually abuses.
//!
//! Scoring v2 (driver track) adds `behavior.call` signals: single calls
//! (Run-key writes) and **chains** — api sets that only mean something
//! together (cross-process write + thread creation = injection; mass
//! encryption + shadow-copy deletion = ransomware). The ring carries no
//! strings, so path-derived classifications (Run-key, shadow-copy,
//! cross-process) arrive as distinct sensor-classified api ids.

use protocol::driver_wire::behavior_api;

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
    /// Score for a Run/RunOnce value write by a scoped process.
    pub run_key_set: u32,
    /// Score for the injection chain completing.
    pub chain_injection: u32,
    /// Score for the ransomware chain completing.
    pub chain_ransomware: u32,
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

/// Is this hooked api a scoring signal at all? The scope-tracker bridge
/// publishes only these over the bus, so high-rate apis (`NtCreateFile`,
/// `NtWriteFile`, `NtDelayExecution`) never reach the scoring consumer.
#[must_use]
pub fn is_scoring_relevant(api: u32) -> bool {
    matches!(
        api,
        behavior_api::NT_CREATE_THREAD_EX
            | behavior_api::NT_SET_VALUE_KEY_RUN_KEY
            | behavior_api::NT_WRITE_VM_CROSS_PROCESS
            | behavior_api::NT_DELETE_FILE_SHADOW_COPY
            | behavior_api::CRYPT_ENCRYPT
    )
}

/// A behavior chain: named api set that scores once complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainId {
    /// Cross-process VM write + thread creation — classic injection.
    Injection,
    /// Mass encryption + shadow-copy deletion — ransomware.
    Ransomware,
}

impl ChainId {
    /// Members as `(api, min sightings)` — the chain completes when EVERY
    /// member has been seen at least `min` times from the same pid.
    #[must_use]
    pub fn members(self) -> &'static [(u32, u32)] {
        const MASS_ENCRYPT_MIN: u32 = 8;
        match self {
            Self::Injection => &[
                (behavior_api::NT_WRITE_VM_CROSS_PROCESS, 1),
                (behavior_api::NT_CREATE_THREAD_EX, 1),
            ],
            Self::Ransomware => &[
                (behavior_api::CRYPT_ENCRYPT, MASS_ENCRYPT_MIN),
                (behavior_api::NT_DELETE_FILE_SHADOW_COPY, 1),
            ],
        }
    }

    /// The configured score when the chain completes.
    #[must_use]
    pub fn weight(self, weights: &ScoreWeights) -> u32 {
        match self {
            Self::Injection => weights.chain_injection,
            Self::Ransomware => weights.chain_ransomware,
        }
    }
}

/// What one behavior observation newly scored for its pid.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BehaviorFinding {
    /// Chains that JUST completed (one-shot per pid — never re-fired).
    pub chains: Vec<ChainId>,
    /// True only on the pid's FIRST Run/RunOnce write (the signal scores
    /// once per pid; max semantics make repeats pointless anyway, but the
    /// one-shot keeps the bus quiet).
    pub run_key_set: bool,
}

/// Per-pid behavior memory, bounded by [`MAX_TRACKED_PIDS`]. The scoring
/// consumer owns one detector per session; exited pids are forgotten so a
/// long session cannot grow it.
#[derive(Debug, Default)]
pub struct ChainDetector {
    per_pid: Vec<(u32, PidBehavior)>,
    dropped_pids: u64,
}

/// Bound on simultaneously tracked pids. Scope membership already bounds
/// the honest population; the cap only caps the hostile one.
const MAX_TRACKED_PIDS: usize = 4096;

#[derive(Debug, Default)]
struct PidBehavior {
    counts: Vec<(u32, u32)>,
    fired: Vec<ChainId>,
    run_key_seen: bool,
}

impl ChainDetector {
    /// Record one hooked call. Returns what it NEWLY scored.
    pub fn observe(&mut self, pid: u32, api: u32) -> BehaviorFinding {
        let mut finding = BehaviorFinding::default();
        let Some(slot) = self.slot_for(pid) else {
            return finding;
        };

        if api == behavior_api::NT_SET_VALUE_KEY_RUN_KEY && !slot.run_key_seen {
            slot.run_key_seen = true;
            finding.run_key_set = true;
        }

        bump(&mut slot.counts, api);
        for chain in [ChainId::Injection, ChainId::Ransomware] {
            if slot.fired.contains(&chain) {
                continue;
            }
            if chain.members().iter().all(|(api, min)| count_of(&slot.counts, *api) >= *min) {
                slot.fired.push(chain);
                finding.chains.push(chain);
            }
        }
        finding
    }

    /// Drop one pid's memory (process exit).
    pub fn forget(&mut self, pid: u32) {
        self.per_pid.retain(|(entry, _)| *entry != pid);
    }

    /// Pids dropped for exceeding the cap (observability).
    #[must_use]
    pub fn dropped_pids(&self) -> u64 {
        self.dropped_pids
    }

    fn slot_for(&mut self, pid: u32) -> Option<&mut PidBehavior> {
        if !self.per_pid.iter().any(|(entry, _)| *entry == pid) {
            if self.per_pid.len() >= MAX_TRACKED_PIDS {
                self.dropped_pids += 1;
                return None;
            }
            self.per_pid.push((pid, PidBehavior::default()));
        }
        // The pid is definitely present; find borrows instead of indexing.
        self.per_pid.iter_mut().find(|(entry, _)| *entry == pid).map(|(_, slot)| slot)
    }
}

fn bump(counts: &mut Vec<(u32, u32)>, api: u32) {
    if let Some(entry) = counts.iter_mut().find(|(existing, _)| *existing == api) {
        entry.1 += 1;
    } else {
        counts.push((api, 1));
    }
}

fn count_of(counts: &[(u32, u32)], api: u32) -> u32 {
    counts.iter().find(|(entry, _)| *entry == api).map_or(0, |(_, count)| *count)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn weights() -> ScoreWeights {
        ScoreWeights {
            cli_started: 4,
            drop_observed: 5,
            run_key_set: 3,
            chain_injection: 20,
            chain_ransomware: 40,
        }
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

    #[test]
    fn relevance_covers_chain_members_and_run_key_only() {
        assert!(is_scoring_relevant(behavior_api::NT_CREATE_THREAD_EX));
        assert!(is_scoring_relevant(behavior_api::NT_SET_VALUE_KEY_RUN_KEY));
        assert!(is_scoring_relevant(behavior_api::NT_WRITE_VM_CROSS_PROCESS));
        assert!(is_scoring_relevant(behavior_api::NT_DELETE_FILE_SHADOW_COPY));
        assert!(is_scoring_relevant(behavior_api::CRYPT_ENCRYPT));
        // High-rate noise never crosses the bridge.
        assert!(!is_scoring_relevant(behavior_api::NT_CREATE_FILE));
        assert!(!is_scoring_relevant(behavior_api::NT_WRITE_FILE));
        assert!(!is_scoring_relevant(behavior_api::NT_DELAY_EXECUTION));
        // Unknown/garbage api ids are inert, never panicking.
        assert!(!is_scoring_relevant(0));
        assert!(!is_scoring_relevant(u32::MAX));
    }

    #[test]
    fn injection_chain_fires_on_both_members_and_never_refires() {
        let mut detector = ChainDetector::default();
        let pid = 100;
        assert_eq!(detector.observe(pid, behavior_api::NT_CREATE_THREAD_EX).chains, []);
        let finding = detector.observe(pid, behavior_api::NT_WRITE_VM_CROSS_PROCESS);
        assert_eq!(finding.chains, vec![ChainId::Injection]);
        // One-shot: repeats stay silent.
        assert_eq!(detector.observe(pid, behavior_api::NT_WRITE_VM_CROSS_PROCESS).chains, []);
        assert_eq!(detector.observe(pid, behavior_api::NT_CREATE_THREAD_EX).chains, []);
    }

    #[test]
    fn ransomware_chain_needs_mass_encryption_not_one_call() {
        let mut detector = ChainDetector::default();
        let pid = 200;
        detector.observe(pid, behavior_api::NT_DELETE_FILE_SHADOW_COPY);
        // Below the mass threshold the chain must NOT fire.
        for _ in 0..7 {
            assert_eq!(detector.observe(pid, behavior_api::CRYPT_ENCRYPT).chains, []);
        }
        let finding = detector.observe(pid, behavior_api::CRYPT_ENCRYPT);
        assert_eq!(finding.chains, vec![ChainId::Ransomware]);
    }

    #[test]
    fn run_key_signal_scores_once_per_pid() {
        let mut detector = ChainDetector::default();
        assert!(detector.observe(300, behavior_api::NT_SET_VALUE_KEY_RUN_KEY).run_key_set);
        assert!(!detector.observe(300, behavior_api::NT_SET_VALUE_KEY_RUN_KEY).run_key_set);
        // A second pid scores its own first write.
        assert!(detector.observe(301, behavior_api::NT_SET_VALUE_KEY_RUN_KEY).run_key_set);
    }

    #[test]
    fn chains_are_per_pid_not_global() {
        let mut detector = ChainDetector::default();
        detector.observe(400, behavior_api::NT_WRITE_VM_CROSS_PROCESS);
        // Another pid's thread creation must not complete OUR chain.
        assert_eq!(detector.observe(401, behavior_api::NT_CREATE_THREAD_EX).chains, []);
        assert_eq!(
            detector.observe(400, behavior_api::NT_CREATE_THREAD_EX).chains,
            vec![ChainId::Injection]
        );
    }

    #[test]
    fn forget_clears_pid_memory_and_fired_chains() {
        let mut detector = ChainDetector::default();
        detector.observe(500, behavior_api::NT_WRITE_VM_CROSS_PROCESS);
        detector.observe(500, behavior_api::NT_CREATE_THREAD_EX);
        detector.forget(500);
        // After exit + pid reuse the slate is clean.
        detector.observe(500, behavior_api::NT_WRITE_VM_CROSS_PROCESS);
        let finding = detector.observe(500, behavior_api::NT_CREATE_THREAD_EX);
        assert_eq!(finding.chains, vec![ChainId::Injection]);
    }

    #[test]
    fn unknown_pids_beyond_the_cap_are_dropped_and_counted() {
        let mut detector = ChainDetector::default();
        let limit = u32::try_from(MAX_TRACKED_PIDS).unwrap_or(u32::MAX);
        for pid in 0..limit {
            assert_eq!(detector.observe(pid, behavior_api::CRYPT_ENCRYPT).chains, []);
        }
        let finding = detector.observe(limit, behavior_api::CRYPT_ENCRYPT);
        assert!(finding.chains.is_empty() && !finding.run_key_set);
        assert_eq!(detector.dropped_pids(), 1);
    }

    #[test]
    fn chain_weights_follow_config() {
        let w = weights();
        assert_eq!(ChainId::Injection.weight(&w), 20);
        assert_eq!(ChainId::Ransomware.weight(&w), 40);
    }
}
