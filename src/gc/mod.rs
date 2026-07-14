//! Wipe / GC orchestrator. Owns the run loop, the plan/commit data model, and
//! `gc.log`. All safety logic is delegated to `safety`/`policy`/`live`; nothing
//! here decides a file's fate on its own.

pub mod live;
pub mod policy;
pub mod safety;

use crate::blacklist::Blacklist;
use crate::catalog::Catalog;
use crate::config::{Env, GcConfig};
use crate::source::claude::{self, Selector};
use crate::source::{SourceRoots, single};
use crate::util::now_iso;
use anyhow::Result;
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Family of ephemeral output. Maps 1:1 to `--targets` tokens and retain knobs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target {
    Transcripts,
    Scratch,
    Mcp,
    EmptyDirs,
    Paste,
    Snapshots,
}

impl Target {
    pub fn parse_list(spec: &str) -> Result<Vec<Target>> {
        let mut out = Vec::new();
        for tok in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            out.push(match tok {
                "transcripts" => Target::Transcripts,
                "scratch" => Target::Scratch,
                "mcp" => Target::Mcp,
                "empty-dirs" => Target::EmptyDirs,
                "paste" => Target::Paste,
                "snapshots" => Target::Snapshots,
                other => anyhow::bail!("unknown --targets value: {other}"),
            });
        }
        Ok(out)
    }

    pub fn all() -> Vec<Target> {
        vec![
            Target::Transcripts,
            Target::Scratch,
            Target::Mcp,
            Target::EmptyDirs,
            Target::Paste,
            Target::Snapshots,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Target::Transcripts => "transcripts",
            Target::Scratch => "scratch",
            Target::Mcp => "mcp",
            Target::EmptyDirs => "empty-dirs",
            Target::Paste => "paste",
            Target::Snapshots => "snapshots",
        }
    }
}

/// What kind of candidate this is, which decides the gate path.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    /// Catalog-backed single file → full 5-gate.
    File,
    /// A scratch working tree → manifest-gated janitor.
    ScratchTree,
    /// An empty directory shell → pure janitor.
    EmptyDir,
}

/// One deletion candidate after policy selection, before gates.
pub struct Candidate {
    pub source: PathBuf,
    pub target: Target,
    pub kind: CandidateKind,
    pub session_uuid: Option<String>,
    /// Store key for a `ScratchTree` (`<slug>--<uuid>`).
    pub scratch_key: Option<String>,
}

/// Audit record of a passed gate set, written to `gc.log`.
pub struct PassedChecks {
    pub source_sha256: String,
    pub archive_id: i64,
    pub stored_reverified: bool,
    pub index_ok: bool,
    pub age_secs: u64,
    pub session_live: bool,
}

pub enum SkipReason {
    NoCatalogRow,
    ShaMismatch,
    StoreReverifyFailed,
    EmptyContentSha,
    IndexUnsatisfiable,
    Blacklisted,
    OpenFailed,
}

impl SkipReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            SkipReason::NoCatalogRow => "NoCatalogRow",
            SkipReason::ShaMismatch => "ShaMismatch",
            SkipReason::StoreReverifyFailed => "StoreReverifyFailed",
            SkipReason::EmptyContentSha => "EmptyContentSha",
            SkipReason::IndexUnsatisfiable => "IndexUnsatisfiable",
            SkipReason::Blacklisted => "Blacklisted",
            SkipReason::OpenFailed => "OpenFailed",
        }
    }
}

pub enum ProtectReason {
    SessionLive,
    TooYoung,
    RetainWindow,
}

impl ProtectReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtectReason::SessionLive => "SessionLive",
            ProtectReason::TooYoung => "TooYoung",
            ProtectReason::RetainWindow => "RetainWindow",
        }
    }
}

/// The result of evaluating one candidate through the gates.
pub enum Verdict {
    Delete {
        archive_id: Option<i64>,
        checks: PassedChecks,
    },
    Protected {
        reason: ProtectReason,
    },
    Unverified {
        reason: SkipReason,
    },
}

pub struct PlanItem {
    pub candidate: Candidate,
    pub verdict: Verdict,
    pub bytes: u64,
}

pub struct Plan {
    pub items: Vec<PlanItem>,
    pub reclaimable_bytes: u64,
    pub protected: usize,
    pub unverified: usize,
    pub deletable: usize,
}

#[derive(Default)]
pub struct CommitReport {
    pub deleted: usize,
    pub reclaimed_bytes: u64,
    /// Plan-`Delete` items that flipped to Unverified at the commit re-check.
    pub flipped_unverified: usize,
    /// Plan-`Delete` items that flipped to Protected at the commit re-check.
    pub flipped_protected: usize,
}

/// Enumerate candidates for one target from this user's own roots. Every path is
/// a descendant of a resolved root by construction; cross-user discovery lives
/// in a separate, read-only type (`source::ShapeRecord`) that cannot reach here.
fn candidates(roots: &SourceRoots, env: &Env, target: Target) -> Result<Vec<Candidate>> {
    // Cross-user safety hard guard: never enumerate delete candidates from a root
    // this process does not own. A poisoned `YOMI_TMP_ROOT` (or any root) pointing
    // at another uid's tree — e.g. `/tmp/claude-<other>` — must produce zero wipe
    // candidates, whatever `under_allowed` later says (須佐P2). The discovery path
    // is read-only and untouched.
    let root = primary_root(roots, target);
    if !root_owned_by_euid(root) {
        tracing::warn!(
            root = %root.display(),
            target = target.as_str(),
            "source root is not owned by this user; refusing to generate wipe candidates"
        );
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    match target {
        Target::Transcripts => {
            for s in claude::discover(roots, &Selector::All)? {
                out.push(Candidate {
                    source: s.transcript,
                    target,
                    kind: CandidateKind::File,
                    session_uuid: Some(s.session_uuid),
                    scratch_key: None,
                });
            }
        }
        Target::Mcp => {
            for sf in single::mcp(roots) {
                out.push(file_candidate(sf.source, target));
            }
        }
        Target::Paste => {
            for sf in single::paste(roots)? {
                out.push(file_candidate(sf.source, target));
            }
        }
        Target::Snapshots => {
            for sf in single::snapshots(roots)? {
                out.push(file_candidate(sf.source, target));
            }
        }
        Target::Scratch => {
            for sc in single::scratch(roots)? {
                let session_dir = scratch_session_dir(&sc, roots);
                // The session uuid is the tree's own directory name
                // (`tmp_root/<slug>/<uuid>`), read directly rather than parsed
                // out of the store key — real project slugs contain `--`, so
                // splitting the key on `--` yields the wrong half and defeats the
                // live-session guard (D1).
                let uuid = session_dir
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string());
                out.push(Candidate {
                    source: session_dir,
                    target,
                    kind: CandidateKind::ScratchTree,
                    session_uuid: uuid,
                    scratch_key: Some(sc.key),
                });
            }
        }
        Target::EmptyDirs => {
            let _ = env;
            for dir in safety::empty_dirs_under(&roots.tmp_root) {
                // The owning session's uuid is the second path component under
                // tmp_root (`<slug>/<uuid>/…`), so an empty shell inside a live
                // session is protected, not just mtime-gated (N2).
                let session_uuid = empty_dir_session_uuid(&dir, &roots.tmp_root);
                out.push(Candidate {
                    source: dir,
                    session_uuid,
                    target,
                    kind: CandidateKind::EmptyDir,
                    scratch_key: None,
                });
            }
        }
    }
    Ok(out)
}

fn file_candidate(source: PathBuf, target: Target) -> Candidate {
    Candidate {
        source,
        target,
        kind: CandidateKind::File,
        session_uuid: None,
        scratch_key: None,
    }
}

/// Reconstruct a scratch session dir (`tmp_root/<slug>/<uuid>`) from its entry.
fn scratch_session_dir(sc: &single::ScratchDir, roots: &SourceRoots) -> PathBuf {
    if let Some(sp) = &sc.scratchpad {
        return sp
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| sp.clone());
    }
    if let Some(t) = sc.task_outputs.first() {
        // .../tasks/<name> → .../
        return t
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .unwrap_or_else(|| roots.tmp_root.clone());
    }
    roots.tmp_root.clone()
}

/// Evaluate one candidate through the appropriate gate path.
fn evaluate_candidate(
    env: &Env,
    cfg: &GcConfig,
    cat: &Catalog,
    bl: &Blacklist,
    cand: &Candidate,
    active: &HashSet<String>,
    min_age: Duration,
) -> Result<(Verdict, u64)> {
    let retain = policy::retain_for(cfg, cand.target);
    let active_window = cfg.active_window.0;
    match cand.kind {
        CandidateKind::File => safety::evaluate_file(
            cat,
            bl,
            &env.archive_dir(),
            &cand.source,
            cand.session_uuid.as_deref(),
            active,
            min_age,
            retain,
            active_window,
            cfg.require_indexed,
        ),
        CandidateKind::ScratchTree => safety::evaluate_scratch(
            env,
            cand.scratch_key.as_deref().unwrap_or_default(),
            &cand.source,
            cand.session_uuid.as_deref(),
            active,
            min_age,
            retain,
            active_window,
        ),
        CandidateKind::EmptyDir => {
            safety::evaluate_empty_dir(&cand.source, active, min_age, active_window)
        }
    }
}

/// The source root a target draws candidates from. Ownership and containment
/// guards key off this. Transcripts/paste/snapshots live under `claude_home`,
/// mcp logs under `cache_home`, scratch/empty-dirs under `tmp_root`.
///
/// Design §8.1 says candidates are "strictly under $HOME"; the real contract is
/// *descendant of one of these three resolved roots*, and `tmp_root`
/// (`/tmp/claude-<uid>`) sits **outside** $HOME. The 3-root descendant test below
/// is the accurate invariant.
fn primary_root(roots: &SourceRoots, target: Target) -> &Path {
    match target {
        Target::Transcripts | Target::Paste | Target::Snapshots => &roots.claude_home,
        Target::Mcp => &roots.cache_home,
        Target::Scratch | Target::EmptyDirs => &roots.tmp_root,
    }
}

/// True only if `root` exists and is owned by the effective uid. A genuinely
/// absent root is benign (nothing to enumerate → proceed); a root owned by
/// another uid is a cross-user hazard and must block candidate generation
/// (須佐P2). Any *other* stat failure (EACCES/ELOOP/EIO — e.g. a poisoned
/// `YOMI_TMP_ROOT` symlink into a foreign uid's mode-700 tree) is treated as
/// not-owned and blocks: a root we cannot prove we own is never enumerated
/// (fail-closed). Ownership is read through `metadata` (following symlinks), so
/// a root symlinked at a foreign-owned tree is caught by the target's real owner.
fn root_owned_by_euid(root: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let euid = unsafe { libc::geteuid() };
    match std::fs::metadata(root) {
        Ok(md) => md.uid() == euid,
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    }
}

/// The owning session uuid of an empty-dir candidate: the component immediately
/// under `tmp_root` (`<slug>/<uuid>/…`).
fn empty_dir_session_uuid(dir: &Path, tmp_root: &Path) -> Option<String> {
    let rel = dir.strip_prefix(tmp_root).ok()?;
    let mut comps = rel.components();
    comps.next()?; // slug
    comps
        .next()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
}

/// A canonicalized (symlinks + `..` resolved) form of a path for containment
/// checks, falling back to a lexical normalization when the path is absent.
fn resolved(path: &Path) -> PathBuf {
    path.canonicalize()
        .unwrap_or_else(|_| crate::util::abs_normalize(path))
}

/// Whether `source` is a descendant of one of this user's resolved roots. A hard
/// guard against any candidate escaping the single-user, own-data scope. Both
/// sides are canonicalized before the prefix test so a candidate carrying `..`
/// or a symlink cannot slip past a purely lexical `starts_with` and unlink a
/// path outside the roots (須佐P1/倶生N4, defense-in-depth with Gate 0).
fn under_allowed(source: &Path, roots: &SourceRoots) -> bool {
    let src = resolved(source);
    [&roots.claude_home, &roots.cache_home, &roots.tmp_root]
        .into_iter()
        .any(|r| src.starts_with(resolved(r)))
}

/// Build the plan (pure read, no mutation) for the requested targets.
pub fn plan(
    env: &Env,
    cfg: &GcConfig,
    targets: &[Target],
    cat: &Catalog,
    bl: &Blacklist,
    live: &dyn live::Liveness,
    min_age_override: Option<Duration>,
) -> Result<Plan> {
    let roots = SourceRoots::resolve()?;
    let active = live.active_session_uuids();
    let min_age = policy::effective_min_age(cfg, min_age_override);

    let mut items = Vec::new();
    for &target in targets {
        for cand in candidates(&roots, env, target)? {
            if !under_allowed(&cand.source, &roots) {
                tracing::warn!(path = %cand.source.display(), "candidate escapes user roots; dropped");
                continue;
            }
            let (verdict, bytes) = evaluate_candidate(env, cfg, cat, bl, &cand, &active, min_age)?;
            items.push(PlanItem {
                candidate: cand,
                verdict,
                bytes,
            });
        }
    }

    let mut reclaimable_bytes = 0;
    let mut protected = 0;
    let mut unverified = 0;
    let mut deletable = 0;
    for it in &items {
        match &it.verdict {
            Verdict::Delete { .. } => {
                deletable += 1;
                reclaimable_bytes += it.bytes;
            }
            Verdict::Protected { .. } => protected += 1,
            Verdict::Unverified { .. } => unverified += 1,
        }
    }
    Ok(Plan {
        items,
        reclaimable_bytes,
        protected,
        unverified,
        deletable,
    })
}

/// Execute a plan's `Delete` items under the caller-held write lock, re-running
/// every gate against the live fs immediately before each delete (the plan can
/// be minutes stale), appending each action to `gc.log`.
pub fn commit(
    env: &Env,
    cfg: &GcConfig,
    plan: &Plan,
    cat: &Catalog,
    bl: &Blacklist,
    live: &dyn live::Liveness,
    min_age_override: Option<Duration>,
) -> Result<CommitReport> {
    let active = live.active_session_uuids();
    // Re-evaluation must honor the same effective floor the plan used, so a
    // `--min-age` raise is not silently dropped between plan and unlink (N3).
    let min_age = policy::effective_min_age(cfg, min_age_override);
    let mut log = GcLog::open(env)?;
    let mut report = CommitReport::default();

    for item in &plan.items {
        match &item.verdict {
            // Delete-planned items are re-evaluated against the live fs — the plan
            // can be minutes stale, so liveness and sha are re-checked before unlink.
            Verdict::Delete { .. } => {
                let (verdict, bytes) =
                    evaluate_candidate(env, cfg, cat, bl, &item.candidate, &active, min_age)?;
                match verdict {
                    Verdict::Delete { archive_id, checks } => {
                        if perform_delete(bl, &item.candidate)? {
                            report.deleted += 1;
                            report.reclaimed_bytes += bytes;
                            log.delete(
                                &item.candidate,
                                archive_id,
                                &checks,
                                cfg.require_indexed,
                                bytes,
                            )?;
                        } else {
                            report.flipped_unverified += 1;
                            log.skip(&item.candidate.source, "InodeDriftOrBlacklist")?;
                        }
                    }
                    Verdict::Unverified { reason } => {
                        report.flipped_unverified += 1;
                        log.skip(&item.candidate.source, reason.as_str())?;
                    }
                    Verdict::Protected { reason } => {
                        report.flipped_protected += 1;
                        log.protect(&item.candidate.source, reason.as_str())?;
                    }
                }
            }
            // Plan-time refusals/protections are recorded verbatim for a complete
            // audit; they were never going to be deleted, so no re-evaluation.
            Verdict::Unverified { reason } => log.skip(&item.candidate.source, reason.as_str())?,
            Verdict::Protected { reason } => {
                log.protect(&item.candidate.source, reason.as_str())?
            }
        }
    }
    Ok(report)
}

/// Perform the physical delete for a re-verified candidate. Returns whether the
/// candidate was actually removed.
fn perform_delete(bl: &Blacklist, cand: &Candidate) -> Result<bool> {
    match cand.kind {
        CandidateKind::File => {
            use crate::blacklist::GuardOutcome;
            use std::os::unix::fs::MetadataExt;
            match bl.open_guarded(&cand.source)? {
                GuardOutcome::Opened(file, md) => {
                    // Hold the guarded fd open across the unlink so the pinned
                    // inode cannot be freed and its number reused between the
                    // ownership fstat and the `unlinkat` (倶生N8/須佐P3).
                    let out = safety::safe_unlink(&cand.source, (md.dev(), md.ino()));
                    drop(file);
                    out
                }
                _ => Ok(false),
            }
        }
        CandidateKind::ScratchTree => Ok(matches!(
            safety::remove_tree_guarded(bl, &cand.source)?,
            safety::TreeRemoval::Removed
        )),
        CandidateKind::EmptyDir => Ok(std::fs::remove_dir(&cand.source).is_ok()),
    }
}

/// Append-only JSONL audit log at `~/.yomi/gc.log`, mode 600.
struct GcLog {
    file: std::fs::File,
}

impl GcLog {
    fn open(env: &Env) -> Result<Self> {
        let path = env.home.join("gc.log");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Env::chmod_600(&path)?;
        Ok(GcLog { file })
    }

    fn delete(
        &mut self,
        cand: &Candidate,
        archive_id: Option<i64>,
        checks: &PassedChecks,
        index_required: bool,
        bytes: u64,
    ) -> Result<()> {
        let v = serde_json::json!({
            "ts": now_iso(),
            "action": "delete",
            "target": cand.target.as_str(),
            "source": cand.source.to_string_lossy(),
            "source_sha256": checks.source_sha256,
            "archive_id": archive_id,
            "stored_reverified": checks.stored_reverified,
            "index_required": index_required,
            "age_secs": checks.age_secs,
            "session_live": checks.session_live,
            "bytes": bytes,
        });
        self.write(&v)
    }

    fn skip(&mut self, source: &Path, reason: &str) -> Result<()> {
        self.write(&serde_json::json!({
            "ts": now_iso(), "action": "skip",
            "source": source.to_string_lossy(), "reason": reason,
        }))
    }

    fn protect(&mut self, source: &Path, reason: &str) -> Result<()> {
        self.write(&serde_json::json!({
            "ts": now_iso(), "action": "protect",
            "source": source.to_string_lossy(), "reason": reason,
        }))
    }

    fn write(&mut self, v: &serde_json::Value) -> Result<()> {
        writeln!(self.file, "{v}")?;
        Ok(())
    }
}

#[cfg(test)]
mod guard_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("yomi-guard-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn roots_at(base: &Path) -> SourceRoots {
        let c = base.join("claude");
        let ca = base.join("cache");
        let t = base.join("tmp");
        for d in [&c, &ca, &t] {
            std::fs::create_dir_all(d).unwrap();
        }
        SourceRoots {
            claude_home: c,
            cache_home: ca,
            tmp_root: t,
        }
    }

    #[test]
    fn under_allowed_accepts_descendant_rejects_escape() {
        let base = tmp("under");
        let roots = roots_at(&base);
        // A real descendant file is accepted.
        let inside = roots.claude_home.join("projects/-x/a.jsonl");
        std::fs::create_dir_all(inside.parent().unwrap()).unwrap();
        std::fs::write(&inside, b"x").unwrap();
        assert!(under_allowed(&inside, &roots));

        // A sibling tree outside every root, reached via a symlink planted in a
        // root, is rejected once the path is canonicalized (須佐P1/倶生N4).
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let secret = out.join("secret");
        std::fs::write(&secret, b"s").unwrap();
        let evil_link = roots.claude_home.join("evil");
        std::os::unix::fs::symlink(&out, &evil_link).unwrap();
        let escape = evil_link.join("secret");
        assert!(escape.exists(), "symlink escape path should resolve");
        assert!(
            !under_allowed(&escape, &roots),
            "symlink-escaping candidate slipped past the containment guard"
        );

        // A `..` traversal out of a root is likewise rejected.
        let dotdot = roots.tmp_root.join("../out/secret");
        assert!(!under_allowed(&dotdot, &roots));
    }

    #[test]
    fn root_owned_by_euid_guards_foreign_and_missing() {
        let base = tmp("owner");
        // A dir this process just created is owned by euid.
        assert!(root_owned_by_euid(&base));
        // A nonexistent root is benign (nothing to enumerate).
        assert!(root_owned_by_euid(&base.join("does-not-exist")));
        // A root owned by another uid is refused (skip when running as root).
        if unsafe { libc::geteuid() } != 0 {
            assert!(
                !root_owned_by_euid(Path::new("/")),
                "root-owned / must not be treated as ours"
            );
        }
        // A non-ENOENT stat failure (here: a symlink loop → ELOOP) is NOT
        // ownership — a root we cannot prove we own must block, not proceed (R2).
        let a = base.join("loop-a");
        let b = base.join("loop-b");
        std::os::unix::fs::symlink(&b, &a).unwrap();
        std::os::unix::fs::symlink(&a, &b).unwrap();
        let err = std::fs::metadata(&a).unwrap_err();
        assert_ne!(err.kind(), std::io::ErrorKind::NotFound, "expected ELOOP");
        assert!(
            !root_owned_by_euid(&a),
            "un-stattable root must be treated as not-owned"
        );
    }

    #[test]
    fn empty_dir_session_uuid_reads_second_component() {
        let t = Path::new("/tmp/claude-1007");
        assert_eq!(
            empty_dir_session_uuid(&t.join("-slug/uuid-123/session-env"), t),
            Some("uuid-123".to_string())
        );
        // Only a slug, no session component → None.
        assert_eq!(empty_dir_session_uuid(&t.join("-slug"), t), None);
    }
}
