//! Scope aggregate: what persists across reboots (`scope.json`) plus the pure
//! tracking logic acting on it.
//!
//! Persisted schema is versioned implicitly by being additive; never truncate in
//! place — the repository writes atomically (temp + rename).

use std::collections::BTreeSet;

use protocol::payload::{
    FileReleasedData,
    FileWrittenData,
    ProcessStartedData,
    ProcessStoppedData,
};
use serde::{
    Deserialize,
    Serialize,
};
use uuid::Uuid;

use crate::domain::drop_filter::DropFilter;

/// Shared handle to the live scope state (pipeline is serial; the mutex guards
/// bus-driven and host-driven accessors).
pub type SharedScopeState = std::sync::Arc<parking_lot::Mutex<ScopeState>>;

/// Root of the persisted scope database.
///
/// A nil `study_id` marks "no study yet" — the composition root assigns a fresh
/// `Uuid` when it observes nil after loading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ScopeState {
    /// Study id — generated at session 0, stable across the study's reboots.
    pub study_id: Uuid,
    /// Session history, ordered by id (`id == index`).
    pub sessions: Vec<SessionRecord>,
}

impl ScopeState {
    /// The session record of the currently open session, if any.
    #[must_use]
    pub fn current_session(&self) -> Option<&SessionRecord> {
        self.sessions.last()
    }

    /// Mutable session record of the currently open session, if any.
    pub fn current_session_mut(&mut self) -> Option<&mut SessionRecord> {
        self.sessions.last_mut()
    }
}

/// One boot-to-reboot interval, persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SessionRecord {
    /// Study-local session id (0-based boot index).
    pub id: u32,
    /// Scheduled duration in seconds; `None` = dynamic mode.
    pub scheduled_duration_secs: Option<u64>,
    /// Wall clock (fake!) at session open, unix milliseconds.
    pub started_at_ms: i64,
    /// Wall clock at finalization; `None` while running.
    pub ended_at_ms: Option<i64>,
    /// `true` when this session was found still open at the NEXT boot — the
    /// VM lost power or hard-reset before finalization. Stamped at boot time
    /// (never by a finalize path); a fresh session is opened afterwards so
    /// session ids keep advancing one-per-boot.
    #[serde(default)]
    pub abandoned: bool,
    /// Processes that joined the scope this session.
    pub scoped_processes: Vec<ScopedProcessRecord>,
    /// Drop paths observed this session (deduplicated, sorted).
    pub observed_drops: BTreeSet<String>,
}

/// A process that joined the analysis scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedProcessRecord {
    /// OS process id.
    pub pid: u32,
    /// Parent process id, when reported.
    pub parent_pid: Option<u32>,
    /// Image name with extension.
    pub name: String,
    /// Full image path, when reported.
    pub image_path: Option<String>,
    /// Command line, when reported.
    pub command_line: Option<String>,
    /// Wall clock at scope entry, unix milliseconds.
    pub started_at_ms: i64,
    /// Wall clock at exit; `None` while running.
    pub ended_at_ms: Option<i64>,
}

/// Pure scope-tracking logic. Owns cross-session state (expected processes,
/// closed-drop bookkeeping) that must NOT persist; mutates the shared
/// [`ScopeState`] under the caller's lock.
#[derive(Debug, Default)]
pub struct ScopeTracker {
    /// Lowercase image names that seed the scope (target, later: drop-derived).
    expected: Vec<String>,
    /// Observed drop paths already reported closed (per session).
    closed: BTreeSet<String>,
}

impl ScopeTracker {
    /// Create a tracker with initial expected process names (normalized).
    #[must_use]
    pub fn new(expected: Vec<String>) -> Self {
        Self { expected, closed: BTreeSet::new() }
    }

    /// Register one more expected process name (normalized internally).
    pub fn expect(&mut self, image_name: &str) {
        let normalized = normalize_image_name(image_name);
        if !normalized.is_empty() && !self.expected.contains(&normalized) {
            self.expected.push(normalized);
        }
    }

    /// Open a new session (id = current session count) at `now_ms`.
    pub fn open_session(
        &self,
        state: &mut ScopeState,
        now_ms: i64,
        scheduled_duration_secs: Option<u64>,
    ) {
        let id = u32::try_from(state.sessions.len()).unwrap_or(u32::MAX);
        state.sessions.push(SessionRecord {
            id,
            scheduled_duration_secs,
            started_at_ms: now_ms,
            ended_at_ms: None,
            abandoned: false,
            scoped_processes: Vec::new(),
            observed_drops: BTreeSet::new(),
        });
    }

    /// Apply a `process.started`. Returns `true` when the process entered the
    /// scope: its image is expected, or its parent is a LIVE scoped process.
    ///
    /// A pid already present in the session replaces its record: Windows
    /// recycles pids, and the previous holder either died without a stop
    /// event (a stale record would fake scope liveness or hide real scope
    /// death) or the event is a duplicate (replacing is harmless).
    pub fn process_entered(
        &self,
        state: &mut ScopeState,
        data: &ProcessStartedData,
        now_ms: i64,
    ) -> bool {
        let name = normalize_image_name(&data.name);
        let inherited = data.parent_pid.is_some_and(|parent| self.is_scoped(state, parent));
        let expected = self.expected.contains(&name);
        if !inherited && !expected {
            return false;
        }
        let Some(session) = state.current_session_mut() else {
            return false;
        };
        session.scoped_processes.retain(|process| process.pid != data.pid);
        session.scoped_processes.push(ScopedProcessRecord {
            pid: data.pid,
            parent_pid: data.parent_pid,
            name: name.clone(),
            image_path: data.image_path.clone(),
            command_line: data.command_line.clone(),
            started_at_ms: now_ms,
            ended_at_ms: None,
        });
        true
    }

    /// Apply a `process.stopped`. Returns `true` when the pid belonged to the
    /// current session's scope; stamps the exit time.
    pub fn process_exited(
        &self,
        state: &mut ScopeState,
        data: &ProcessStoppedData,
        now_ms: i64,
    ) -> bool {
        let Some(session) = state.current_session_mut() else {
            return false;
        };
        let Some(process) = session
            .scoped_processes
            .iter_mut()
            .find(|process| process.pid == data.pid && process.ended_at_ms.is_none())
        else {
            return false;
        };
        process.ended_at_ms = Some(now_ms);
        true
    }

    /// Is `pid` a LIVE member of the current session's scope? Dead records
    /// never match: a recycled pid must neither inherit the scope (a new
    /// process spawned by an unrelated owner of a recycled pid) nor
    /// attribute drops to it.
    #[must_use]
    pub fn is_scoped(&self, state: &ScopeState, pid: u32) -> bool {
        state.current_session().is_some_and(|session| {
            session.scoped_processes.iter().any(|p| p.pid == pid && p.ended_at_ms.is_none())
        })
    }

    /// TRUE scope-death check (legacy had this inverted): the scope is dead only
    /// when a session exists, at least one process was scoped, and every one of
    /// them exited. An empty session is *not* dead — the target may not have
    /// launched yet.
    #[must_use]
    pub fn scope_dead(state: &ScopeState) -> bool {
        let Some(session) = state.current_session() else {
            return false;
        };
        !session.scoped_processes.is_empty()
            && session.scoped_processes.iter().all(|process| process.ended_at_ms.is_some())
    }

    /// Apply a `file.written` from a scoped process. Returns the drop path when
    /// this is the first matching write for that path this session.
    pub fn drop_observed(
        &mut self,
        state: &mut ScopeState,
        data: &FileWrittenData,
        filter: &DropFilter,
    ) -> Option<String> {
        let pid = data.pid;
        if !self.is_scoped(state, pid) {
            return None;
        }
        let path = data.file_name.as_ref()?;
        if !filter.matches(path) {
            return None;
        }
        let session = state.current_session_mut()?;
        if session.observed_drops.insert(path.clone()) { Some(path.clone()) } else { None }
    }

    /// Apply a `file.closed`/`file.cleaned_up`. Returns the path when it was an
    /// observed drop getting its close reported (reported once per path).
    pub fn drop_closed(&mut self, state: &ScopeState, data: &FileReleasedData) -> Option<String> {
        let path = data.file_name.as_ref()?;
        let observed =
            state.current_session().is_some_and(|session| session.observed_drops.contains(path));
        if !observed {
            return None;
        }
        if self.closed.insert(path.clone()) { Some(path.clone()) } else { None }
    }
}

/// Normalize an image name for comparisons: lowercase (NTFS case-insensitivity).
#[must_use]
pub fn normalize_image_name(image_name: &str) -> String {
    image_name.to_lowercase()
}

/// Apply a `process.started` (test helper kept private to the module).
#[cfg(test)]
impl ScopeTracker {
    fn entered(&self, state: &mut ScopeState, pid: u32, name: &str, now_ms: i64) -> bool {
        self.process_entered(
            state,
            &ProcessStartedData {
                pid,
                parent_pid: None,
                name: name.to_owned(),
                image_path: None,
                command_line: None,
                os_session_id: Some(1),
            },
            now_ms,
        )
    }

    fn exited(&self, state: &mut ScopeState, pid: u32, name: &str, now_ms: i64) -> bool {
        self.process_exited(state, &ProcessStoppedData { pid, name: name.to_owned() }, now_ms)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::BTreeSet;

    use super::*;

    fn state() -> ScopeState {
        ScopeState { study_id: Uuid::from_u128(1), sessions: Vec::new() }
    }

    fn written(pid: u32, path: &str) -> FileWrittenData {
        FileWrittenData {
            pid,
            file_object: Some(1),
            file_key: Some(2),
            file_name: Some(path.to_owned()),
            io_size: Some(10),
            offset: Some(0),
        }
    }

    #[test]
    fn target_seed_joins_scope() {
        let mut state = state();
        let mut tracker = ScopeTracker::default();
        tracker.open_session(&mut state, 0, Some(60));
        tracker.expect("evil.exe");
        assert!(tracker.entered(&mut state, 100, "evil.EXE", 1));
        assert!(!tracker.entered(&mut state, 200, "notepad.exe", 2));
    }

    #[test]
    fn child_joins_scope_via_parent_pid() {
        let mut state = state();
        let mut tracker = ScopeTracker::default();
        tracker.open_session(&mut state, 0, None);
        tracker.expect("evil.exe");
        assert!(tracker.entered(&mut state, 100, "evil.exe", 1));
        let child = ProcessStartedData {
            pid: 101,
            parent_pid: Some(100),
            name: "cmd.exe".to_owned(),
            image_path: None,
            command_line: None,
            os_session_id: Some(1),
        };
        assert!(tracker.process_entered(&mut state, &child, 2));
    }

    #[test]
    fn scope_death_requires_at_least_one_scoped_process() {
        let mut state = state();
        let mut tracker = ScopeTracker::default();
        tracker.open_session(&mut state, 0, None);
        // Empty session: NOT dead (legacy inverted-check regression guard).
        assert!(!ScopeTracker::scope_dead(&state));
        tracker.expect("evil.exe");
        assert!(tracker.entered(&mut state, 100, "evil.exe", 1));
        assert!(!ScopeTracker::scope_dead(&state));
        assert!(tracker.exited(&mut state, 100, "evil.exe", 2));
        assert!(ScopeTracker::scope_dead(&state));
    }

    #[test]
    fn pid_reuse_replaces_the_stale_record() {
        let mut state = state();
        let mut tracker = ScopeTracker::default();
        tracker.open_session(&mut state, 0, None);
        tracker.expect("evil.exe");
        assert!(tracker.entered(&mut state, 100, "evil.exe", 1));
        // Same pid again — Windows recycled it after an unreported death (or
        // the event is a duplicate): the newest record wins, exactly one
        // record remains, and its clock is the newer sighting.
        assert!(tracker.entered(&mut state, 100, "evil.exe", 2));
        let records = &state.current_session().unwrap().scoped_processes;
        assert_eq!(records.len(), 1);
        assert_eq!(records.first().unwrap().started_at_ms, 2);
        assert!(records.first().unwrap().ended_at_ms.is_none());
    }

    #[test]
    fn dead_scope_members_neither_inherit_nor_attribute() {
        let mut state = state();
        let mut tracker = ScopeTracker::default();
        tracker.open_session(&mut state, 0, None);
        tracker.expect("evil.exe");
        assert!(tracker.entered(&mut state, 100, "evil.exe", 1));
        assert!(tracker.exited(&mut state, 100, "evil.exe", 2));

        // The exited pid no longer counts as live: a new process claiming it
        // as parent does NOT join the scope (pid-recycled parent), and its
        // writes do not count as drops.
        let child = ProcessStartedData {
            pid: 300,
            parent_pid: Some(100),
            name: "cmd.exe".to_owned(),
            image_path: None,
            command_line: None,
            os_session_id: Some(1),
        };
        assert!(!tracker.process_entered(&mut state, &child, 3));
        let filter = DropFilter::new(&["*".to_owned()]);
        assert_eq!(tracker.drop_observed(&mut state, &written(100, "C:\\x.txt"), &filter), None);
    }

    #[test]
    fn drops_only_from_scoped_processes_and_matching_extensions() {
        let mut state = state();
        let mut tracker = ScopeTracker::default();
        tracker.open_session(&mut state, 0, None);
        tracker.expect("evil.exe");
        assert!(tracker.entered(&mut state, 100, "evil.exe", 1));
        let filter = DropFilter::new(&[".txt".to_owned(), "none".to_owned()]);

        // Unscoped process: ignored.
        assert!(!tracker.entered(&mut state, 900, "browser.exe", 2));
        assert_eq!(tracker.drop_observed(&mut state, &written(900, "C:\\x.txt"), &filter), None);
        // Scoped but non-matching extension.
        assert_eq!(tracker.drop_observed(&mut state, &written(100, "C:\\y.dll"), &filter), None);
        // Matching, first time.
        assert_eq!(
            tracker.drop_observed(&mut state, &written(100, "C:\\z.TXT"), &filter),
            Some("C:\\z.TXT".to_owned())
        );
        // Same path again: deduplicated.
        assert_eq!(tracker.drop_observed(&mut state, &written(100, "C:\\z.TXT"), &filter), None);
        assert_eq!(
            state.current_session().unwrap().observed_drops,
            BTreeSet::from(["C:\\z.TXT".to_owned()])
        );
    }

    #[test]
    fn drop_close_reported_once_for_observed_paths() {
        let mut state = state();
        let mut tracker = ScopeTracker::default();
        tracker.open_session(&mut state, 0, None);
        tracker.expect("evil.exe");
        assert!(tracker.entered(&mut state, 100, "evil.exe", 1));
        let filter = DropFilter::new(&["*".to_owned()]);
        assert!(tracker.drop_observed(&mut state, &written(100, "C:\\a.exe"), &filter).is_some());

        let release = |name: &str| FileReleasedData {
            pid: 100,
            file_object: Some(1),
            file_key: Some(2),
            file_name: Some(name.to_owned()),
        };
        assert_eq!(
            tracker.drop_closed(&state, &release("C:\\a.exe")),
            Some("C:\\a.exe".to_owned())
        );
        assert_eq!(tracker.drop_closed(&state, &release("C:\\a.exe")), None);
        assert_eq!(tracker.drop_closed(&state, &release("C:\\never-seen.txt")), None);
    }
}
