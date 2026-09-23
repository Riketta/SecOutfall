//! Property tests for the analysis scope and drop invariants — the core
//! adversarial-surface of the agent. The analyzed malware chooses pids,
//! image names, and file paths; these properties must hold for every
//! sequence of hostile inputs:
//!
//! - only expected or LIVE-scope-inherited processes join, uniquely per
//!   session (a pid that got a stop event no longer inherits for children
//!   nor attributes drops); a re-start for an already-recorded pid REPLACES
//!   the record (pid recycling: newest wins) and returns true exactly when
//!   the new process is itself scopable;
//! - a process exits at most once; the scope is dead iff at least one
//!   process was scoped and every one of them exited (the fixed legacy bug);
//! - drop observation is once per (session, path), closes are once per
//!   path across the session, and only LIVE scoped writers mint drops;
//! - the extension filter's conventions hold for arbitrary paths;
//! - hostile extensions sanitize into the whitelisted alphabet.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use agent::domain::{
    drop_copy::sanitize_extension,
    drop_filter::DropFilter,
    scope::{
        ScopeState,
        ScopeTracker,
    },
};
use proptest::prelude::*;
use protocol::payload::{
    FileReleasedData,
    FileWrittenData,
    ProcessStartedData,
    ProcessStoppedData,
};

fn started(pid: u32, parent: Option<u32>, name: &str) -> ProcessStartedData {
    ProcessStartedData {
        pid,
        parent_pid: parent,
        name: name.to_owned(),
        image_path: None,
        command_line: None,
        os_session_id: Some(1),
    }
}

fn written(pid: u32, path: &str) -> FileWrittenData {
    FileWrittenData {
        pid,
        file_object: Some(1),
        file_key: Some(2),
        file_name: Some(path.to_owned()),
        io_size: Some(512),
        offset: Some(0),
    }
}

fn released(pid: u32, path: &str) -> FileReleasedData {
    FileReleasedData {
        pid,
        file_object: Some(1),
        file_key: Some(2),
        file_name: Some(path.to_owned()),
    }
}

/// The test-side model of "which pids currently hold a live (unended) scope
/// record" — mirrors `is_scoped` matching only records with `ended_at_ms`
/// set to `None`.
#[derive(Default)]
struct LiveModel {
    /// Pids that ever received a scope record (one record per pid at most).
    ever: BTreeSet<u32>,
    /// Pids whose record is currently live (not exited).
    live: BTreeSet<u32>,
}

impl LiveModel {
    fn is_live(&self, pid: u32) -> bool {
        self.live.contains(&pid)
    }

    fn on_entered(&mut self, pid: u32) {
        self.ever.insert(pid);
        self.live.insert(pid);
    }

    fn on_exited(&mut self, pid: u32) {
        self.live.remove(&pid);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Membership: a process joins only when expected or live-scope-
    /// inherited; a re-start for a recorded pid replaces the record (true
    /// when scopable, false — leaving the old record untouched — when not);
    /// records stay unique per pid per session; exits stamp at most once;
    /// the scope-death verdict is exactly "some scoped ∧ all exited".
    #[test]
    fn membership_invariants_hold_under_hostile_input(
        pids in proptest::collection::vec(any::<u32>(), 1..24),
        names in proptest::collection::vec("[a-zA-Z][a-zA-Z0-9_.-]{0,20}", 1..24),
        exits in proptest::collection::vec(any::<bool>(), 24),
        restarts in proptest::collection::vec(any::<bool>(), 24),
    ) {
        let tracker = ScopeTracker::new(vec!["evil.exe".to_owned()]);
        let mut state = ScopeState::default();
        tracker.open_session(&mut state, 1_000, Some(60));
        let mut model = LiveModel::default();

        // Phase 1 — initial starts. Inheritance consults LIVE parent
        // records; duplicates replace instead of being rejected.
        for (index, (pid, name)) in pids.iter().zip(names.iter().cycle()).enumerate() {
            let parent = if index % 3 == 0 { None } else { pids.first().copied() };
            let expected = name.to_lowercase() == "evil.exe";
            let parent_live = parent.is_some_and(|parent| model.is_live(parent));
            let allowed = expected || parent_live;
            let entered = tracker.process_entered(&mut state, &started(*pid, parent, name), 2_000);
            prop_assert_eq!(entered, allowed, "pid {} name {}", pid, name);
            if entered {
                model.on_entered(*pid);
            }
        }

        // Phase 2 — exits: exactly the live pids stamp; a second exit (or an
        // exit for a never-scoped pid) reports false. After the stamp the
        // record is dead: no further inheritance, no further attribution.
        for (pid, should_exit) in pids.iter().zip(&exits) {
            if !*should_exit {
                continue;
            }
            let was_live = model.is_live(*pid);
            let stamped = tracker.process_exited(
                &mut state,
                &ProcessStoppedData { pid: *pid, name: "whatever.exe".to_owned() },
                3_000
            );
            prop_assert_eq!(stamped, was_live, "exit stamp for pid {}", pid);
            if was_live {
                model.on_exited(*pid);
                prop_assert!(
                    !tracker.process_exited(
                        &mut state,
                        &ProcessStoppedData { pid: *pid, name: "whatever.exe".to_owned() },
                        3_001
                    ),
                    "double exit for pid {}",
                    pid
                );
            }
        }

        // Phase 3 — replacement after death: a re-start for a recorded pid
        // succeeds exactly when the new process is itself scopable (its own
        // expected name, or a LIVE parent — a parent that exited in phase 2
        // no longer transmits the scope); a non-scopable re-start must leave
        // the old record untouched.
        for (index, ((pid, name), restart)) in
            pids.iter().zip(names.iter().cycle()).zip(&restarts).enumerate()
        {
            if !*restart {
                continue;
            }
            let parent = if index % 3 == 0 { None } else { pids.first().copied() };
            let expected = name.to_lowercase() == "evil.exe";
            let parent_live = parent.is_some_and(|parent| model.is_live(parent));
            let allowed = expected || parent_live;
            let entered =
                tracker.process_entered(&mut state, &started(*pid, parent, name), 4_000);
            prop_assert_eq!(entered, allowed, "replacement pid {} name {}", pid, name);
            if entered {
                model.on_entered(*pid);
            }
        }

        // Uniqueness: at most one record per pid, so the record count equals
        // the distinct pids that ever joined.
        let session = state.current_session().expect("session was opened");
        let mut seen: BTreeSet<u32> = BTreeSet::new();
        for process in &session.scoped_processes {
            prop_assert!(seen.insert(process.pid), "duplicate record for pid {}", process.pid);
        }
        prop_assert_eq!(
            session.scoped_processes.len(),
            model.ever.len(),
            "one record per ever-scoped pid"
        );

        // Liveness bookkeeping matches the persisted records.
        let live_in_state = session
            .scoped_processes
            .iter()
            .filter(|process| process.ended_at_ms.is_none())
            .count();
        prop_assert_eq!(live_in_state, model.live.len(), "live records match the model");
        for pid in &model.live {
            prop_assert!(seen.contains(pid), "live pid {} has no record", pid);
        }

        // Death verdict: iff at least one record exists and every record
        // (live model: no live pid remains) has exited.
        let all_ended = session
            .scoped_processes
            .iter()
            .all(|process| process.ended_at_ms.is_some());
        prop_assert_eq!(
            ScopeTracker::scope_dead(&state),
            !session.scoped_processes.is_empty() && all_ended
        );
        prop_assert_eq!(ScopeTracker::scope_dead(&state), !model.ever.is_empty() && model.live.is_empty());
    }

    /// Drops: observed exactly once per (session, path) for LIVE scoped
    /// writers passing the filter; never for unscoped writers and never for
    /// writers whose record already ended (a stopped pid no longer
    /// attributes); closes exactly once per observed path, and never for
    /// unobserved ones.
    #[test]
    fn drop_invariants_hold_under_hostile_paths(
        scoped in any::<bool>(),
        exited in any::<bool>(),
        // File names only (no separators, no drive prefixes): a separator
        // or `:` immediately before `.txt` makes the file name `.txt`
        // itself, which has no extension by Path semantics — the tracker
        // correctly skips those.
        paths in proptest::collection::vec("[a-zA-Z0-9_][a-zA-Z0-9_ .\\-]{0,29}\\.txt", 1..16),
    ) {
        let mut tracker = ScopeTracker::new(vec!["evil.exe".to_owned()]);
        let mut state = ScopeState::default();
        tracker.open_session(&mut state, 1_000, Some(60));
        prop_assert!(tracker.process_entered(&mut state, &started(7, None, "evil.exe"), 2_000));
        if scoped && exited {
            prop_assert!(
                tracker.process_exited(
                    &mut state,
                    &ProcessStoppedData { pid: 7, name: "evil.exe".to_owned() },
                    2_500
                ),
                "evil exit stamp"
            );
        }

        // Attribution requires a LIVE scoped record: an unscoped pid never
        // attributes, and neither does a scoped pid that already exited.
        let attributes = scoped && !exited;
        let writer_pid = if scoped { 7 } else { 999 };

        let filter = DropFilter::new(&[".txt".to_owned()]);

        // The once-per-path invariant is per unique path — dedupe first.
        let unique_paths: BTreeSet<&String> = paths.iter().collect();
        for path in &unique_paths {
            let observed = tracker.drop_observed(&mut state, &written(writer_pid, path), &filter);
            let second = tracker.drop_observed(&mut state, &written(writer_pid, path), &filter);
            if attributes {
                prop_assert_eq!(observed, Some((*path).clone()));
                prop_assert_eq!(second, None, "path {} observed twice", path);
            } else {
                prop_assert_eq!(observed, None, "dead/unscoped writer must not mint drops");
                prop_assert_eq!(second, None);
            }
        }

        if attributes {
            // Every observed path closes exactly once; closing an
            // unobserved path never reports.
            for path in &unique_paths {
                prop_assert!(tracker.drop_closed(&state, &released(7, path)).is_some());
            }
            prop_assert!(tracker.drop_closed(&state, &released(7, "C:\\unobserved.txt")).is_none());
        }
        // Observed set persisted exactly once per path — and only for
        // live-scoped writers.
        let session = state.current_session().unwrap();
        let expected_len = if attributes { unique_paths.len() } else { 0 };
        prop_assert_eq!(session.observed_drops.len(), expected_len);
    }

    /// Filter conventions for arbitrary path strings: `*` matches all;
    /// empty matches nothing; an extension rule matches exactly the
    /// case-insensitive extension; `none` matches extensionless.
    #[test]
    fn filter_conventions_hold_for_arbitrary_paths(
        path in "[a-zA-Z0-9_/\\\\: .\\-\\u{0400}-\\u{04FF}]{0,40}((\\.[a-zA-Z0-9]{1,8})?)",
        ext in "[a-zA-Z0-9]{1,8}",
    ) {
        let all = DropFilter::new(&["*".to_owned()]);
        prop_assert!(all.matches(&path));

        let none = DropFilter::default();
        prop_assert!(!none.matches(&path));

        let rule = DropFilter::new(&[format!(".{ext}")]);
        let path_ext = std::path::Path::new(&path)
            .extension()
            .map(|value| value.to_string_lossy().to_lowercase());
        prop_assert_eq!(rule.matches(&path), path_ext.as_deref() == Some(ext.to_lowercase().as_str()));
    }

    /// Hostile extensions sanitize into the whitelist: ASCII
    /// alphanumerics/`-`/`_` only, lowercase, capped at 16 chars, never
    /// empty.
    #[test]
    fn sanitized_extensions_stay_whitelisted(
        hostile in "(?s).{0,40}",
    ) {
        let sanitized = sanitize_extension(&hostile);
        prop_assert!(!sanitized.is_empty());
        prop_assert!(sanitized.len() <= 16);
        prop_assert!(
            sanitized.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_')),
            "sanitized `{hostile}` produced `{sanitized}`"
        );
        prop_assert_eq!(sanitized.clone(), sanitized.to_lowercase());
    }
}
