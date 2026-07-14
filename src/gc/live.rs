//! Live-session protection. The only code in yomi that reads `/proc`; its root
//! is env-injectable (`$YOMI_PROC_ROOT`) so the spawned-binary e2e tests can
//! fabricate live/dead pids, and unit tests inject a `FakeLiveness` instead.

use crate::source::SourceRoots;
use std::collections::HashSet;
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Injectable liveness oracle. Production reads `/proc` + Claude's session files;
/// tests fake it.
pub trait Liveness {
    /// Is `pid` a running process?
    fn pid_alive(&self, pid: u32) -> bool;
    /// UUIDs of sessions currently considered live — the union of sessions whose
    /// owning pid is alive and sessions with a freshly-touched lock file.
    fn active_session_uuids(&self) -> HashSet<String>;
}

/// Production impl. `proc_root` defaults to `/proc`, overridable by
/// `$YOMI_PROC_ROOT`. `sessions_dir`/`locks_dir` derive from the resolved roots
/// (both already injectable via `YOMI_CLAUDE_HOME`/`HOME`).
pub struct ProcLiveness {
    pub proc_root: PathBuf,
    pub sessions_dir: PathBuf,
    pub locks_dir: PathBuf,
    pub active_window: Duration,
}

impl ProcLiveness {
    pub fn resolve(roots: &SourceRoots, active_window: Duration) -> Self {
        let proc_root = std::env::var_os("YOMI_PROC_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/proc"));
        let locks_dir = crate::util::home_dir()
            .map(|h| h.join(".local/state/claude/locks"))
            .unwrap_or_else(|_| PathBuf::from("/nonexistent"));
        ProcLiveness {
            proc_root,
            sessions_dir: roots.claude_home.join("sessions"),
            locks_dir,
            active_window,
        }
    }

    fn lock_is_recent(&self, path: &Path) -> bool {
        std::fs::metadata(path)
            .ok()
            .and_then(|m| m.modified().ok())
            .map(|t| {
                SystemTime::now()
                    .duration_since(t)
                    .unwrap_or(Duration::ZERO)
                    < self.active_window
            })
            .unwrap_or(false)
    }
}

impl Liveness for ProcLiveness {
    fn pid_alive(&self, pid: u32) -> bool {
        self.proc_root.join(pid.to_string()).exists()
    }

    fn active_session_uuids(&self) -> HashSet<String> {
        let mut set = HashSet::new();

        // sessions/<pid>.json → sessionId when the owning pid is alive.
        if let Ok(rd) = std::fs::read_dir(&self.sessions_dir) {
            for e in rd.flatten() {
                let path = e.path();
                let Some(pid) = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse::<u32>().ok())
                else {
                    continue;
                };
                if !self.pid_alive(pid) {
                    continue;
                }
                if let Ok(txt) = std::fs::read_to_string(&path)
                    && let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt)
                    && let Some(sid) = v.get("sessionId").and_then(|x| x.as_str())
                {
                    set.insert(sid.to_string());
                }
            }
        }

        // Locks (`~/.local/state/claude/locks/*.lock`) are on the archive
        // blacklist (blacklist.rs:37) — that gate covers archive-open only. They
        // are read here deliberately, never through `open_guarded`, purely as a
        // liveness signal: a recently-touched `<uuid>.lock` marks that session live.
        if let Ok(rd) = std::fs::read_dir(&self.locks_dir) {
            for e in rd.flatten() {
                let path = e.path();
                if path.extension().and_then(|s| s.to_str()) != Some("lock") {
                    continue;
                }
                if self.lock_is_recent(&path)
                    && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
                {
                    set.insert(stem.to_string());
                }
            }
        }

        set
    }
}

/// A source is protected from deletion if its session is in the live set, its
/// mtime is within `active_window`, or its age is below `min_age`. The
/// mtime/age clauses are defense-in-depth (also enforced by `policy`). A missing
/// source (already gone) counts as protected — the safe, delete-less answer.
pub fn is_protected(
    active: &HashSet<String>,
    md: &Metadata,
    session_uuid: Option<&str>,
    active_window: Duration,
    min_age: Duration,
) -> bool {
    if let Some(u) = session_uuid
        && active.contains(u)
    {
        return true;
    }
    match md.modified() {
        Ok(mtime) => {
            let age = SystemTime::now()
                .duration_since(mtime)
                .unwrap_or(Duration::ZERO);
            age < active_window || age < min_age
        }
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeLiveness {
        alive: HashSet<u32>,
        active: HashSet<String>,
    }
    impl Liveness for FakeLiveness {
        fn pid_alive(&self, pid: u32) -> bool {
            self.alive.contains(&pid)
        }
        fn active_session_uuids(&self) -> HashSet<String> {
            self.active.clone()
        }
    }

    fn md_of_age(age: Duration) -> Metadata {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("yomi-live-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("s");
        std::fs::write(&f, b"x").unwrap();
        let when = SystemTime::now() - age;
        filetime_set(&f, when);
        std::fs::metadata(&f).unwrap()
    }

    fn filetime_set(path: &Path, when: SystemTime) {
        let ft = filetime::FileTime::from_system_time(when);
        filetime::set_file_mtime(path, ft).unwrap();
    }

    #[test]
    fn active_uuid_protects_regardless_of_age() {
        let live = FakeLiveness {
            alive: HashSet::new(),
            active: HashSet::from(["sess-a".to_string()]),
        };
        let md = md_of_age(Duration::from_secs(30 * 86_400));
        assert!(is_protected(
            &live.active_session_uuids(),
            &md,
            Some("sess-a"),
            Duration::from_secs(3_600),
            Duration::from_secs(7 * 86_400),
        ));
    }

    #[test]
    fn mtime_window_protects_a_fresh_source() {
        let live = FakeLiveness {
            alive: HashSet::new(),
            active: HashSet::new(),
        };
        let md = md_of_age(Duration::from_secs(60));
        assert!(is_protected(
            &live.active_session_uuids(),
            &md,
            None,
            Duration::from_secs(3_600),
            Duration::from_secs(7 * 86_400),
        ));
    }

    #[test]
    fn young_source_below_min_age_protected() {
        let live = FakeLiveness {
            alive: HashSet::new(),
            active: HashSet::new(),
        };
        let md = md_of_age(Duration::from_secs(3 * 86_400));
        assert!(is_protected(
            &live.active_session_uuids(),
            &md,
            None,
            Duration::from_secs(3_600),
            Duration::from_secs(7 * 86_400),
        ));
    }

    #[test]
    fn aged_dead_unlocked_source_not_protected() {
        let live = FakeLiveness {
            alive: HashSet::new(),
            active: HashSet::new(),
        };
        let md = md_of_age(Duration::from_secs(30 * 86_400));
        assert!(!is_protected(
            &live.active_session_uuids(),
            &md,
            Some("sess-x"),
            Duration::from_secs(3_600),
            Duration::from_secs(7 * 86_400),
        ));
    }
}
