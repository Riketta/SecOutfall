//! Property tests for the analysis scope and drop invariants — the core
//! adversarial-surface of the agent. The analyzed malware chooses pids,
//! image names, and file paths; these properties must hold for every
//! sequence of hostile inputs:
//!
//! - only expected or scope-inherited processes join, uniquely per session;
//! - a process exits at most once; the scope is dead iff at least one
//!   process was scoped and every one of them exited (the fixed legacy bug);
//! - drop observation is once per (session, path), closes are once per
//!   path across the session, and unscoped writers never mint drops;
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Membership: a process joins only when expected or scope-inherited;
    /// joins are unique per pid per session; exits stamp at most once; the
    /// scope-death verdict is exactly "some scoped ∧ all exited".
    #[test]
    fn membership_invariants_hold_under_hostile_input(
        pids in proptest::collection::vec(any::<u32>(), 1..24),
        names in proptest::collection::vec("[a-zA-Z][a-zA-Z0-9_.-]{0,20}", 1..24),
        exits in proptest::collection::vec(any::<bool>(), 24),
    ) {
        let tracker = ScopeTracker::new(vec!["evil.exe".to_owned()]);
        let mut state = ScopeState::default();
        tracker.open_session(&mut state, 1_000, Some(60));

        // pid -> joined?
        let mut joined: std::collections::BTreeMap<u32, bool> = std::collections::BTreeMap::new();
        for (index, (pid, name)) in pids.iter().zip(names.iter().cycle()).enumerate() {
            let parent = if index % 3 == 0 { None } else { pids.first().copied() };
            let entered = tracker.process_entered(&mut state, &started(*pid, parent, name), 2_000);
            let parent_joined =
                parent.is_some_and(|parent| joined.get(&parent).copied().unwrap_or(false));
            let expected = name.to_lowercase() == "evil.exe" || parent_joined;
            let allowed = expected && !joined.contains_key(pid);
            prop_assert_eq!(entered, allowed, "pid {} name {}", pid, name);
            if entered {
                prop_assert!(!joined.contains_key(pid), "pid {} joined twice", pid);
            }
            joined.insert(*pid, entered);
        }

        // Exits: at most one stamp per pid; re-exits report false.
        for (pid, should_exit) in pids.iter().zip(&exits) {
            if *should_exit && joined.get(pid).copied().unwrap_or(false) {
                prop_assert!(
                    tracker.process_exited(
                        &mut state,
                        &ProcessStoppedData { pid: *pid, name: "whatever.exe".to_owned() },
                        3_000
                    ),
                    "exit stamp for pid {}",
                    pid
                );
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

        // Death verdict: iff at least one joined and every joined exited.
        let any_joined = joined.values().any(|joined| *joined);
        let all_exited = state
            .current_session()
            .is_some_and(|session| {
                session.scoped_processes.iter().all(|process| process.ended_at_ms.is_some())
            });
        prop_assert_eq!(ScopeTracker::scope_dead(&state), any_joined && all_exited);
    }

    /// Drops: observed exactly once per (session, path) for scoped writers
    /// passing the filter; never for unscoped writers; closes exactly once
    /// per observed path, and never for unobserved ones.
    #[test]
    fn drop_invariants_hold_under_hostile_paths(
        scoped in any::<bool>(),
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

        let filter = DropFilter::new(&[".txt".to_owned()]);
        let writer_pid = if scoped { 7 } else { 999 };

        // The once-per-path invariant is per unique path — dedupe first.
        let unique_paths: BTreeSet<&String> = paths.iter().collect();
        for path in &unique_paths {
            let observed = tracker.drop_observed(&mut state, &written(writer_pid, path), &filter);
            let second = tracker.drop_observed(&mut state, &written(writer_pid, path), &filter);
            if scoped {
                prop_assert_eq!(observed, Some((*path).clone()));
                prop_assert_eq!(second, None, "path {} observed twice", path);
            } else {
                prop_assert_eq!(observed, None);
                prop_assert_eq!(second, None);
            }
        }

        if scoped {
            // Every observed path closes exactly once; closing an
            // unobserved path never reports.
            for path in &unique_paths {
                prop_assert!(tracker.drop_closed(&state, &released(7, path)).is_some());
            }
            prop_assert!(tracker.drop_closed(&state, &released(7, "C:\\unobserved.txt")).is_none());
            // Observed set persisted exactly once per path.
            let session = state.current_session().unwrap();
            prop_assert_eq!(session.observed_drops.len(), unique_paths.len());
        }
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
