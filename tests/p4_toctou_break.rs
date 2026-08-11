//! P4 break tests: the plan -> commit window.
//!
//! `gc::plan` applies `under_allowed` (canonicalizing containment against the
//! three source roots); `gc::commit` re-runs only the per-candidate GATES, never
//! containment. These tests drive plan and commit through the library so the
//! filesystem can be mutated in between — the exact window a stale plan opens.
//!
//! `SourceRoots::resolve` and `Blacklist::compile` read process env, so every
//! test here serializes on `ENV_LOCK`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

use yomi::blacklist::Blacklist;
use yomi::catalog;
use yomi::config::Env;
use yomi::gc::live::ProcLiveness;
use yomi::gc::{self, ScratchMode, Target, Verdict};
use yomi::source::SourceRoots;

const BIN: &str = env!("CARGO_BIN_EXE_yomi");

fn env_lock() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn unique() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

struct Fx {
    base: PathBuf,
    home: PathBuf,
    yomi_home: PathBuf,
    tmp_root: PathBuf,
    cache_home: PathBuf,
    proc_root: PathBuf,
    slug: String,
}

impl Fx {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "yomi-p4t-{tag}-{}-{}",
            std::process::id(),
            unique()
        ));
        let fx = Fx {
            home: base.join("home"),
            yomi_home: base.join("yomi"),
            tmp_root: base.join("tmp"),
            cache_home: base.join("cache"),
            proc_root: base.join("proc"),
            slug: "-home-test".to_string(),
            base,
        };
        std::fs::create_dir_all(fx.projects()).unwrap();
        for d in [&fx.tmp_root, &fx.cache_home, &fx.proc_root] {
            std::fs::create_dir_all(d).unwrap();
        }
        fx
    }

    fn projects(&self) -> PathBuf {
        self.home.join(".claude/projects").join(&self.slug)
    }

    fn transcript(&self, uuid: &str) -> PathBuf {
        self.projects().join(format!("{uuid}.jsonl"))
    }

    fn write_transcript(&self, uuid: &str, texts: &[&str]) {
        let mut body = String::new();
        for t in texts {
            body.push_str(&user_line(uuid, t));
            body.push('\n');
        }
        std::fs::write(self.transcript(uuid), body).unwrap();
    }

    fn archive(&self) {
        self.archive_with(&["archive", "--all"]);
    }

    /// Archive via the real binary (its own process, so no env leakage here).
    fn archive_with(&self, args: &[&str]) {
        let out = Command::new(BIN)
            .args(args)
            .arg("--home")
            .arg(&self.yomi_home)
            .env("HOME", &self.home)
            .env("YOMI_TMP_ROOT", &self.tmp_root)
            .env("YOMI_CACHE_HOME", &self.cache_home)
            .env("YOMI_PROC_ROOT", &self.proc_root)
            .env_remove("YOMI_HOME")
            .env_remove("YOMI_CLAUDE_HOME")
            .output()
            .expect("archive");
        assert!(
            out.status.success(),
            "archive failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Point this process's env at the fixture. Caller must hold `ENV_LOCK`.
    fn adopt_env(&self) {
        for (k, v) in [
            ("HOME", &self.home),
            ("YOMI_TMP_ROOT", &self.tmp_root),
            ("YOMI_CACHE_HOME", &self.cache_home),
            ("YOMI_PROC_ROOT", &self.proc_root),
        ] {
            // SAFETY: test-only; serialized by ENV_LOCK, single-threaded here.
            unsafe { std::env::set_var(k, v) };
        }
        // SAFETY: same.
        unsafe {
            std::env::remove_var("YOMI_HOME");
            std::env::remove_var("YOMI_CLAUDE_HOME");
        }
    }
}

fn user_line(uuid: &str, text: &str) -> String {
    serde_json::json!({
        "type": "user",
        "uuid": format!("u-{}", unique()),
        "parentUuid": null,
        "timestamp": "2026-07-12T10:00:00.000Z",
        "cwd": "/home/test",
        "gitBranch": "main",
        "version": "2.1.207",
        "sessionId": uuid,
        "message": {"role": "user", "content": text}
    })
    .to_string()
}

fn set_mtime_days(path: &Path, days: u64) {
    let when = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86_400);
    filetime::set_file_mtime(path, filetime::FileTime::from_system_time(when)).unwrap();
}

fn deletable(plan: &gc::Plan) -> usize {
    plan.items
        .iter()
        .filter(|i| matches!(i.verdict, Verdict::Delete { .. }))
        .count()
}

// ---------------------------------------------------------------------------

/// Plan the delete, then swap `.claude/projects` for a symlink at an
/// out-of-roots tree holding a byte-identical twin, then commit. Every gate
/// re-run at commit passes on content alone — only containment could stop this,
/// and `gc::commit` never re-checks it.
#[test]
fn p4t_containment_is_not_rechecked_between_plan_and_commit() {
    let _g = env_lock();
    let fx = Fx::new("escape");
    let u = "aaaaaaaa-1111-2222-3333-444444444444";
    fx.write_transcript(u, &["alpha", "beta"]);
    fx.archive();
    set_mtime_days(&fx.transcript(u), 200);

    // The out-of-roots twin: identical bytes, identical name, identical age.
    let outside = fx.base.join("outside");
    std::fs::create_dir_all(outside.join(&fx.slug)).unwrap();
    let twin = outside.join(&fx.slug).join(format!("{u}.jsonl"));
    std::fs::copy(fx.transcript(u), &twin).unwrap();
    set_mtime_days(&twin, 200);

    fx.adopt_env();
    let env = Env::resolve(Some(&fx.yomi_home), None).unwrap();
    let cfg = env.config.gc.clone();
    let cat = catalog::open_env(&env).unwrap();
    let bl = Blacklist::compile(&env).unwrap();
    let roots = SourceRoots::resolve().unwrap();
    let live = ProcLiveness::resolve(&roots, cfg.active_window.0);

    let plan = gc::plan(
        &env,
        &cfg,
        &[Target::Transcripts],
        &cat,
        &bl,
        &live,
        None,
        ScratchMode::Aged,
    )
    .unwrap();
    assert_eq!(deletable(&plan), 1, "fixture produced no delete plan");

    // --- the window ---
    let projects_root = fx.home.join(".claude/projects");
    std::fs::remove_dir_all(&projects_root).unwrap();
    std::os::unix::fs::symlink(&outside, &projects_root).unwrap();

    let report = gc::commit(&env, &cfg, &plan, &cat, &bl, &live, None, ScratchMode::Aged).unwrap();

    assert!(
        twin.exists(),
        "gc::commit unlinked {}, a file outside every source root, because a \
         non-final path component became a symlink after the plan was built. \
         `under_allowed` runs at plan time only; commit re-runs the gates but \
         never re-checks containment. (report: deleted={}, flipped_unverified={})",
        twin.display(),
        report.deleted,
        report.flipped_unverified
    );
    // The escape is stopped, but NOT by containment — commit never re-runs
    // `under_allowed`. It is stopped by gate 1: `canonical_key` resolves the
    // swapped path to the out-of-roots location, which matches no catalog row.
    // The defence is incidental, so record which one actually fired.
    assert_eq!(report.deleted, 0, "nothing may be deleted after the swap");
    assert_eq!(
        report.flipped_unverified, 1,
        "the swapped candidate should flip to Unverified at the commit re-check"
    );
    let reasons: Vec<String> = std::fs::read_to_string(fx.yomi_home.join("gc.log"))
        .unwrap()
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v["reason"].as_str().map(str::to_string))
        .collect();
    assert!(
        reasons.iter().any(|r| r == "NoCatalogRow"),
        "expected the canonical-key gate to be the thing that refused; got {reasons:?}"
    );
}

/// Same window, aimed at the scratch janitor: after the plan is built the whole
/// session tree is replaced by a symlink at an out-of-roots directory.
/// `remove_tree_guarded` walks and then `remove_dir_all`s whatever the name
/// resolves to at commit time.
#[test]
fn p4t_scratch_tree_swapped_for_symlink_after_plan() {
    let _g = env_lock();
    let fx = Fx::new("scratch");
    let u = "bbbbbbbb-1111-2222-3333-444444444444";
    let sess = fx.tmp_root.join(&fx.slug).join(u);
    std::fs::create_dir_all(sess.join("scratchpad")).unwrap();
    std::fs::write(sess.join("scratchpad/notes.md"), b"work\n").unwrap();
    fx.archive_with(&["archive", "--all", "--include", "scratch"]);
    set_mtime_days(&sess.join("scratchpad/notes.md"), 200);

    let outside = fx.base.join("precious");
    std::fs::create_dir_all(outside.join("scratchpad")).unwrap();
    std::fs::write(outside.join("scratchpad/notes.md"), b"work\n").unwrap();
    set_mtime_days(&outside.join("scratchpad/notes.md"), 200);

    fx.adopt_env();
    let env = Env::resolve(Some(&fx.yomi_home), None).unwrap();
    let cfg = env.config.gc.clone();
    let cat = catalog::open_env(&env).unwrap();
    let bl = Blacklist::compile(&env).unwrap();
    let roots = SourceRoots::resolve().unwrap();
    let live = ProcLiveness::resolve(&roots, cfg.active_window.0);

    let plan = gc::plan(
        &env,
        &cfg,
        &[Target::Scratch],
        &cat,
        &bl,
        &live,
        None,
        ScratchMode::Aged,
    )
    .unwrap();
    assert_eq!(
        deletable(&plan),
        1,
        "fixture produced no scratch delete plan"
    );

    // --- the window ---
    std::fs::remove_dir_all(&sess).unwrap();
    std::os::unix::fs::symlink(&outside, &sess).unwrap();

    let _ = gc::commit(&env, &cfg, &plan, &cat, &bl, &live, None, ScratchMode::Aged).unwrap();
    assert!(
        outside.join("scratchpad/notes.md").exists(),
        "the scratch janitor deleted {} through a symlink planted after the plan",
        outside.display()
    );
}

/// Content-level TOCTOU: the source is rewritten between plan and commit. The
/// gates are re-run at commit, so the drifted file must flip to Unverified and
/// survive. This is the defence that is supposed to make the stale plan safe.
#[test]
fn p4t_content_drift_between_plan_and_commit_is_caught() {
    let _g = env_lock();
    let fx = Fx::new("drift");
    let u = "cccccccc-1111-2222-3333-444444444444";
    fx.write_transcript(u, &["alpha"]);
    fx.archive();
    set_mtime_days(&fx.transcript(u), 200);

    fx.adopt_env();
    let env = Env::resolve(Some(&fx.yomi_home), None).unwrap();
    let cfg = env.config.gc.clone();
    let cat = catalog::open_env(&env).unwrap();
    let bl = Blacklist::compile(&env).unwrap();
    let roots = SourceRoots::resolve().unwrap();
    let live = ProcLiveness::resolve(&roots, cfg.active_window.0);

    let plan = gc::plan(
        &env,
        &cfg,
        &[Target::Transcripts],
        &cat,
        &bl,
        &live,
        None,
        ScratchMode::Aged,
    )
    .unwrap();
    assert_eq!(deletable(&plan), 1);

    // --- the window: new, unarchived content lands in the source ---
    let mut body = std::fs::read_to_string(fx.transcript(u)).unwrap();
    body.push_str(&user_line(u, "UNARCHIVED — must not be lost"));
    body.push('\n');
    std::fs::write(fx.transcript(u), &body).unwrap();
    set_mtime_days(&fx.transcript(u), 200);

    let report = gc::commit(&env, &cfg, &plan, &cat, &bl, &live, None, ScratchMode::Aged).unwrap();
    assert_eq!(report.deleted, 0, "drifted source was deleted");
    assert_eq!(report.flipped_unverified, 1);
    assert!(fx.transcript(u).exists());
    assert!(
        std::fs::read_to_string(fx.transcript(u))
            .unwrap()
            .contains("UNARCHIVED"),
        "unarchived data was destroyed"
    );
}

/// The source becomes a hardlink to a credential between plan and commit. Gate 0
/// re-runs at commit and must refuse by inode.
#[test]
fn p4t_credential_hardlink_planted_after_plan_is_refused() {
    let _g = env_lock();
    let fx = Fx::new("cred");
    let u = "dddddddd-1111-2222-3333-444444444444";
    fx.write_transcript(u, &["alpha"]);
    fx.archive();
    set_mtime_days(&fx.transcript(u), 200);

    fx.adopt_env();
    let env = Env::resolve(Some(&fx.yomi_home), None).unwrap();
    let cfg = env.config.gc.clone();
    let cat = catalog::open_env(&env).unwrap();
    let bl = Blacklist::compile(&env).unwrap();
    let roots = SourceRoots::resolve().unwrap();
    let live = ProcLiveness::resolve(&roots, cfg.active_window.0);

    let plan = gc::plan(
        &env,
        &cfg,
        &[Target::Transcripts],
        &cat,
        &bl,
        &live,
        None,
        ScratchMode::Aged,
    )
    .unwrap();
    assert_eq!(deletable(&plan), 1);

    // --- the window: the candidate name now points at the credential inode ---
    let cred = fx.home.join(".claude/.credentials.json");
    std::fs::write(&cred, b"{\"accessToken\":\"FAKE-NOT-REAL\"}").unwrap();
    std::fs::remove_file(fx.transcript(u)).unwrap();
    std::fs::hard_link(&cred, fx.transcript(u)).unwrap();

    let report = gc::commit(&env, &cfg, &plan, &cat, &bl, &live, None, ScratchMode::Aged).unwrap();
    assert_eq!(report.deleted, 0, "a credential hardlink was unlinked");
    assert!(cred.exists(), "the credential inode lost a link");
    assert!(
        fx.transcript(u).exists(),
        "the planted hardlink was unlinked"
    );
}

/// A live session appearing between plan and commit must protect the source.
#[test]
fn p4t_session_going_live_between_plan_and_commit_protects() {
    let _g = env_lock();
    let fx = Fx::new("live");
    let u = "eeeeeeee-1111-2222-3333-444444444444";
    fx.write_transcript(u, &["alpha"]);
    fx.archive();
    set_mtime_days(&fx.transcript(u), 200);

    fx.adopt_env();
    let env = Env::resolve(Some(&fx.yomi_home), None).unwrap();
    let cfg = env.config.gc.clone();
    let cat = catalog::open_env(&env).unwrap();
    let bl = Blacklist::compile(&env).unwrap();
    let roots = SourceRoots::resolve().unwrap();

    let live = ProcLiveness::resolve(&roots, cfg.active_window.0);
    let plan = gc::plan(
        &env,
        &cfg,
        &[Target::Transcripts],
        &cat,
        &bl,
        &live,
        None,
        ScratchMode::Aged,
    )
    .unwrap();
    assert_eq!(deletable(&plan), 1);

    // --- the window: the session comes back to life ---
    let pid = 424242u32;
    std::fs::create_dir_all(fx.proc_root.join(pid.to_string())).unwrap();
    std::fs::create_dir_all(fx.home.join(".claude/sessions")).unwrap();
    std::fs::write(
        fx.home.join(".claude/sessions").join(format!("{pid}.json")),
        serde_json::json!({"sessionId": u, "cwd": "/home/test"}).to_string(),
    )
    .unwrap();

    // `commit` takes its own liveness snapshot from the oracle it is handed.
    let live2 = ProcLiveness::resolve(&roots, cfg.active_window.0);
    let report = gc::commit(
        &env,
        &cfg,
        &plan,
        &cat,
        &bl,
        &live2,
        None,
        ScratchMode::Aged,
    )
    .unwrap();
    assert_eq!(
        report.deleted, 0,
        "a session that went live between plan and commit was wiped"
    );
    assert!(fx.transcript(u).exists());
}
