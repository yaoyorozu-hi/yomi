//! P21 break tests: `gc --full`.
//!
//! `--full` is the second of `clear`'s three levels (decision #11). It claims a
//! narrow, stated set — **a scratch tree whose ledger was written by a caps-lifted
//! `archive --full` run and whose captured set is empty** — and it reaches that set
//! by relaxing the age policy, never by weakening a gate. Most of this file is
//! about what it must *not* do:
//!
//! * **the default `gc` is byte-for-byte the same verb.** Every existing gc test
//!   still passes, and a run without `--full` must never produce `Captured` or
//!   `NotFullyArchived` — the two reasons only `--full` can reach.
//! * **the floor does not go to zero.** It relaxes to `[gc] active_window` (1h) and
//!   stops there. Zero would leave the tree of the session running the command
//!   guarded only by the uuid liveness set, which has three silent paths to empty
//!   and whose lock leg is already dead on this host (issue #37). `--min-age` still
//!   raises and never lowers.
//! * **no coverage check is skipped.** A tree with no verifiable ledger is refused
//!   exactly as it is by default, and a tree that holds captured content is held at
//!   `Captured`.
//!
//! And one thing it must do beyond deleting: **say what an operator has to run
//! first.** On a host where nothing has been archived, `gc --full` correctly deletes
//! nothing; without a line naming the cause that is indistinguishable from a broken
//! flag.
//!
//! Every fixture is fabricated under `CARGO_TARGET_TMPDIR` and removed when the
//! fixture drops. No real Claude Code data, no `~/.yomi`, no `/tmp` (issue #48).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

const BIN: &str = env!("CARGO_BIN_EXE_yomi");

/// Not matched by any `[scratch]` allow glob, so it is manifested and never stored
/// whatever the caps say — which is how a tree gets a caps-lifted ledger with an
/// empty captured set.
const UNSTORED: (&str, &[u8]) = ("data.dat", b"build output, nobody wants a copy\n");

/// Matched by `*.md`, so a caps-lifted run stores it and the tree's captured set is
/// non-empty.
const STORED: (&str, &[u8]) = ("scratchpad/keep.md", b"notes worth keeping\n");

/// Which ledger a fixture tree should have when gc meets it.
enum Ledger {
    /// Never archived.
    None,
    /// Archived with the `[scratch]` caps in force.
    Capped,
    /// Archived by `archive --full`.
    CapsLifted,
}

fn unique() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
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

/// The fixture removes its own tree. A `remove_dir_all` placed *before* the fixture
/// is built is a no-op that leaves every run's directories behind (issue #48).
impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

impl Fx {
    fn new(tag: &str) -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "p21-{tag}-{}-{}",
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
        std::fs::create_dir_all(fx.home.join(".claude/projects").join(&fx.slug)).unwrap();
        for d in [
            &fx.tmp_root,
            &fx.cache_home,
            &fx.proc_root,
            &fx.yomi_home,
            &fx.base.join("homes"),
            &fx.base.join("tmpbase"),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        // `ensure_layout` refuses a store looser than 700, and the mode this dir
        // gets otherwise depends on the harness umask.
        std::fs::set_permissions(
            &fx.yomi_home,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        fx
    }

    fn session_dir(&self, uuid: &str) -> PathBuf {
        self.tmp_root.join(&self.slug).join(uuid)
    }

    fn key(&self, uuid: &str) -> String {
        format!("{}--{}", self.slug, uuid)
    }

    fn store_dir(&self, uuid: &str) -> PathBuf {
        self.yomi_home.join("archive/_scratch").join(self.key(uuid))
    }

    fn manifest(&self, uuid: &str) -> serde_json::Value {
        let p = self.store_dir(uuid).join("manifest.json");
        let txt = std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("no manifest at {}: {e}", p.display()));
        serde_json::from_str(&txt).expect("manifest json")
    }

    /// A private root holding one tree, so an `archive` run there decides about that
    /// tree and no other. The tree is moved into the shared `tmp_root` afterwards:
    /// the store key and the recorded identity are both derived from the last two
    /// path components (`<slug>/<uuid>`), so a move between roots keeps both.
    fn stage_dir(&self, uuid: &str) -> PathBuf {
        self.base
            .join(format!("stage-{uuid}"))
            .join(&self.slug)
            .join(uuid)
    }

    fn write_at(&self, dir: &Path, rel: &str, bytes: &[u8]) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
    }

    fn stage_root(&self, uuid: &str) -> PathBuf {
        self.base.join(format!("stage-{uuid}"))
    }

    /// Move a staged tree into the shared `tmp_root`, where gc will find it.
    fn promote(&self, uuid: &str) {
        let dest = self.tmp_root.join(&self.slug);
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::rename(self.stage_dir(uuid), dest.join(uuid)).unwrap();
    }

    /// Build one tree, give it the ledger asked for, and place it under `tmp_root`.
    fn tree(&self, uuid: &str, files: &[(&str, &[u8])], ledger: Ledger) {
        let staged = self.stage_dir(uuid);
        for (rel, bytes) in files {
            self.write_at(&staged, rel, bytes);
        }
        match ledger {
            Ledger::None => {}
            Ledger::Capped => self.archive_at(uuid, &["--include", "scratch"]),
            Ledger::CapsLifted => self.archive_at(uuid, &["--full", "--include", "scratch"]),
        }
        self.promote(uuid);
    }

    /// Set every file's mtime in a promoted tree to `age` ago. Scratch age is the
    /// newest **file** mtime, so this is the whole of the tree's apparent age.
    fn age_tree(&self, uuid: &str, age: Duration) {
        let when = filetime::FileTime::from_system_time(SystemTime::now() - age);
        for e in walk(&self.session_dir(uuid)) {
            filetime::set_file_mtime(&e, when).unwrap();
        }
    }

    fn command(&self, tmp_root: &Path, args: &[&str]) -> Command {
        let mut c = Command::new(BIN);
        c.args(args)
            .arg("--home")
            .arg(&self.yomi_home)
            .env("HOME", &self.home)
            .env("YOMI_TMP_ROOT", tmp_root)
            .env("YOMI_CACHE_HOME", &self.cache_home)
            .env("YOMI_PROC_ROOT", &self.proc_root)
            // Cross-user discovery must never walk the real /home or /tmp.
            .env("YOMI_HOME_BASE", self.base.join("homes"))
            .env("YOMI_TMP_BASE", self.base.join("tmpbase"))
            .env_remove("YOMI_HOME")
            .env_remove("YOMI_CLAUDE_HOME");
        c
    }

    fn run_at(&self, tmp_root: &Path, args: &[&str]) -> Out {
        let o = self.command(tmp_root, args).output().expect("run yomi");
        Out {
            code: o.status.code().unwrap(),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }

    fn run(&self, args: &[&str]) -> Out {
        self.run_at(&self.tmp_root, args)
    }

    /// Archive against one tree's private staging root.
    fn archive_at(&self, uuid: &str, args: &[&str]) {
        let mut v = vec!["archive"];
        v.extend_from_slice(args);
        let out = self.run_at(&self.stage_root(uuid), &v);
        assert_eq!(out.code, 0, "archive {args:?} failed: {}", out.summary());
    }

    /// A transcript plus its archive, so a `File` candidate exists with a verified
    /// catalog row behind it.
    fn archived_transcript(&self, uuid: &str) -> PathBuf {
        let p = self
            .home
            .join(".claude/projects")
            .join(&self.slug)
            .join(format!("{uuid}.jsonl"));
        std::fs::write(
            &p,
            serde_json::json!({"type": "user", "message": {"role": "user", "content": "hi"}})
                .to_string()
                + "\n",
        )
        .unwrap();
        let out = self.run(&["archive", "--all", "--include", "transcript"]);
        assert_eq!(out.code, 0, "archive failed: {}", out.summary());
        p
    }

    /// `gc` with `--json`, as a parsed report.
    fn gc_json(&self, args: &[&str]) -> serde_json::Value {
        let mut v = vec!["gc"];
        v.extend_from_slice(args);
        v.push("--json");
        let out = self.run(&v);
        assert!(
            out.code == 0 || out.code == 2,
            "gc {args:?} failed: {}",
            out.summary()
        );
        out.json()
    }

    fn gc_log(&self) -> Vec<serde_json::Value> {
        let Ok(text) = std::fs::read_to_string(self.yomi_home.join("gc.log")) else {
            return Vec::new();
        };
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(self.stdout.trim())
            .unwrap_or_else(|e| panic!("gc --json unparseable ({e}): {}", self.summary()))
    }
    fn summary(&self) -> String {
        format!(
            "exit={} stdout={:?} stderr={:?}",
            self.code,
            self.stdout.trim(),
            self.stderr.trim()
        )
    }
}

fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out
}

/// The plan item for one source path.
fn item<'a>(plan: &'a serde_json::Value, source: &Path) -> &'a serde_json::Value {
    plan["items"]
        .as_array()
        .expect("items array")
        .iter()
        .find(|it| it["source"].as_str() == Some(&source.to_string_lossy()))
        .unwrap_or_else(|| panic!("no plan item for {}; plan={plan:#}", source.display()))
}

fn verdict_of(plan: &serde_json::Value, source: &Path) -> (String, String) {
    let it = item(plan, source);
    (
        it["verdict"].as_str().unwrap_or_default().to_string(),
        it["reason"].as_str().unwrap_or_default().to_string(),
    )
}

/// The three ledger states section A puts in front of one default run.
fn trees() -> [&'static str; 3] {
    [
        "aaaa0001-0000-0000-0000-000000000001",
        "aaaa0002-0000-0000-0000-000000000002",
        "aaaa0003-0000-0000-0000-000000000003",
    ]
}

const AGED: Duration = Duration::from_secs(2 * 3_600);
const FRESH: Duration = Duration::from_secs(600);

// ---------------------------------------------------------------------------
// A. What `--full` must not change.
// ---------------------------------------------------------------------------

/// **The regression that matters most.** The default verb is the one in production
/// use, and the two reasons `--full` introduces must be unreachable without it — in
/// the plan, in `--json` and in `gc.log`. A tree aged past `active_window` but under
/// the 7d floor is `TooYoung` exactly as it was, whatever its ledger says.
#[test]
fn p21_a_default_gc_never_reaches_the_full_reasons() {
    let fx = Fx::new("default-vocab");
    fx.tree(
        "aaaa0001-0000-0000-0000-000000000001",
        &[UNSTORED],
        Ledger::CapsLifted,
    );
    fx.tree(
        "aaaa0002-0000-0000-0000-000000000002",
        &[STORED],
        Ledger::CapsLifted,
    );
    fx.tree(
        "aaaa0003-0000-0000-0000-000000000003",
        &[UNSTORED],
        Ledger::Capped,
    );
    for uuid in trees() {
        fx.age_tree(uuid, AGED);
    }

    let plan = fx.gc_json(&["--targets", "scratch"]);
    assert_eq!(plan["deletable"], 0, "default gc claimed a tree: {plan:#}");
    for uuid in trees() {
        let (verdict, reason) = verdict_of(&plan, &fx.session_dir(uuid));
        assert_eq!(verdict, "protected", "{uuid}: {plan:#}");
        assert_eq!(
            reason, "TooYoung",
            "default gc reported a --full reason for {uuid}: {plan:#}"
        );
    }
    assert_eq!(plan["scratch_not_fully_archived"], 0);

    // The same through the commit path, which is where `gc.log` is written.
    let out = fx.run(&["gc", "--targets", "scratch", "--commit"]);
    assert_eq!(out.code, 0, "{}", out.summary());
    for uuid in trees() {
        assert!(fx.session_dir(uuid).exists(), "default gc deleted {uuid}");
    }
    for rec in fx.gc_log() {
        let reason = rec["reason"].as_str().unwrap_or_default();
        assert!(
            reason != "Captured" && reason != "NotFullyArchived",
            "a --full reason reached gc.log from a default run: {rec}"
        );
    }
    assert!(
        !out.stdout.contains("archive --all --full"),
        "the --full advice leaked into a default run: {}",
        out.summary()
    );
}

/// The aged path itself still deletes. Without this the test above passes trivially
/// on a gc that refuses everything.
#[test]
fn p21_a_default_gc_still_takes_an_aged_archived_tree() {
    let fx = Fx::new("default-deletes");
    let uuid = "aaaa0010-0000-0000-0000-000000000010";
    fx.tree(uuid, &[STORED, UNSTORED], Ledger::CapsLifted);
    // Past both the 7d floor and `scratch_retain`.
    fx.age_tree(uuid, Duration::from_secs(8 * 86_400));

    let out = fx.run(&["gc", "--targets", "scratch", "--commit"]);
    assert_eq!(out.code, 0, "{}", out.summary());
    assert!(
        !fx.session_dir(uuid).exists(),
        "the aged path stopped deleting: {}",
        out.summary()
    );
}

// ---------------------------------------------------------------------------
// B. What `--full` claims, and what it holds.
// ---------------------------------------------------------------------------

/// The set `--full` exists for: a caps-lifted ledger, an empty captured set, and an
/// age the default floor would refuse.
#[test]
fn p21_b_full_takes_a_caps_lifted_tree_with_an_empty_captured_set() {
    let fx = Fx::new("takes");
    let uuid = "bbbb0001-0000-0000-0000-000000000001";
    fx.tree(uuid, &[UNSTORED], Ledger::CapsLifted);
    fx.age_tree(uuid, AGED);
    let mf = fx.manifest(uuid);
    assert_eq!(mf["caps_lifted"], true, "the fixture did not run --full");
    assert!(
        mf["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["stored"] == false),
        "the fixture's captured set is not empty: {mf:#}"
    );

    let plan = fx.gc_json(&["--full", "--targets", "scratch"]);
    assert_eq!(
        plan["deletable"], 1,
        "--full did not claim the tree: {plan:#}"
    );
    assert_eq!(verdict_of(&plan, &fx.session_dir(uuid)).0, "delete");

    let out = fx.run(&["gc", "--full", "--targets", "scratch", "--commit"]);
    assert_eq!(out.code, 0, "{}", out.summary());
    assert!(
        !fx.session_dir(uuid).exists(),
        "--full did not delete the tree: {}",
        out.summary()
    );
    // The ledger and the store are untouched by a reclaim.
    assert!(fx.store_dir(uuid).join("manifest.json").exists());
}

/// A tree that holds captured content is held at `Captured`. `--full` reclaims what
/// nothing has a copy of; deciding the fate of archived content is the age policy's
/// job, or `--wipe`'s.
#[test]
fn p21_b_full_holds_a_tree_whose_captured_set_is_not_empty() {
    let fx = Fx::new("captured");
    let uuid = "bbbb0002-0000-0000-0000-000000000002";
    fx.tree(uuid, &[STORED, UNSTORED], Ledger::CapsLifted);
    fx.age_tree(uuid, AGED);

    let plan = fx.gc_json(&["--full", "--targets", "scratch"]);
    assert_eq!(
        verdict_of(&plan, &fx.session_dir(uuid)),
        ("protected".to_string(), "Captured".to_string()),
        "{plan:#}"
    );

    let out = fx.run(&["gc", "--full", "--targets", "scratch", "--commit"]);
    assert_eq!(out.code, 0, "{}", out.summary());
    assert!(
        fx.session_dir(uuid).exists(),
        "--full deleted a tree with captured content: {}",
        out.summary()
    );
    assert!(
        fx.gc_log()
            .iter()
            .any(|r| r["action"] == "protect" && r["reason"] == "Captured"),
        "gc.log did not record the reason: {:?}",
        fx.gc_log()
    );
}

/// A ledger written with the caps in force does not establish what the tree holds
/// under `--full` policy, so `--full` does not act on it — and says which command
/// settles the question.
#[test]
fn p21_b_full_holds_a_capped_ledger_at_not_fully_archived() {
    let fx = Fx::new("capped");
    let uuid = "bbbb0003-0000-0000-0000-000000000003";
    fx.tree(uuid, &[UNSTORED], Ledger::Capped);
    fx.age_tree(uuid, AGED);
    assert!(
        fx.manifest(uuid).get("caps_lifted").is_none(),
        "the fixture recorded lifted caps"
    );

    let plan = fx.gc_json(&["--full", "--targets", "scratch"]);
    assert_eq!(
        verdict_of(&plan, &fx.session_dir(uuid)),
        ("protected".to_string(), "NotFullyArchived".to_string()),
        "{plan:#}"
    );
    assert_eq!(plan["scratch_not_fully_archived"], 1, "{plan:#}");

    let human = fx.run(&["gc", "--full", "--targets", "scratch"]);
    assert!(
        human.stdout.contains("caps in force")
            && human.stdout.contains("yomi archive --all --full"),
        "the plan did not name the remedy: {}",
        human.summary()
    );

    let out = fx.run(&["gc", "--full", "--targets", "scratch", "--commit"]);
    assert!(
        fx.session_dir(uuid).exists(),
        "--full deleted a tree on a capped ledger: {}",
        out.summary()
    );
}

/// **A manifest-less tree is refused, and that is the feature.** "The captured set
/// is empty" and "nothing ever tried to capture this" are different statements, and
/// only the first licenses a delete — so on a host where nothing has been archived,
/// `gc --full` reclaims nothing until `archive --all --full` has run. What must not
/// happen is silence: the plan has to say so, or the operator sees only "0
/// deletable".
#[test]
fn p21_b_full_refuses_an_unarchived_tree_and_says_to_archive_first() {
    let fx = Fx::new("no-ledger");
    let uuid = "bbbb0004-0000-0000-0000-000000000004";
    fx.tree(uuid, &[UNSTORED], Ledger::None);
    fx.age_tree(uuid, AGED);

    let plan = fx.gc_json(&["--full", "--targets", "scratch"]);
    assert_eq!(plan["deletable"], 0, "{plan:#}");
    assert_eq!(
        verdict_of(&plan, &fx.session_dir(uuid)),
        ("unverified".to_string(), "NoCatalogRow".to_string()),
        "{plan:#}"
    );
    assert_eq!(plan["scratch_no_ledger"], 1, "{plan:#}");

    let human = fx.run(&["gc", "--full", "--targets", "scratch"]);
    assert!(
        human.stdout.contains("yomi archive --all --full"),
        "the plan did not tell the operator to archive first: {}",
        human.summary()
    );

    let out = fx.run(&["gc", "--full", "--targets", "scratch", "--commit"]);
    assert_eq!(
        out.code,
        2,
        "an unverified item is a partial run: {}",
        out.summary()
    );
    assert!(
        fx.session_dir(uuid).exists(),
        "--full deleted a tree with no ledger: {}",
        out.summary()
    );
}

/// A retained entry (`present: false`) describes a file that has **already left the
/// tree**, so deleting the tree loses nothing it names — and it must not veto
/// `--full`. Letting it would put a tree permanently out of reach in exchange for
/// protecting nothing, since a retained entry is never reconciled away.
#[test]
fn p21_b_a_retained_entry_does_not_veto_full() {
    let fx = Fx::new("retained");
    let uuid = "bbbb0005-0000-0000-0000-000000000005";
    let staged = fx.stage_dir(uuid);
    fx.write_at(&staged, STORED.0, STORED.1);
    fx.write_at(&staged, UNSTORED.0, UNSTORED.1);
    fx.archive_at(uuid, &["--full", "--include", "scratch"]);
    // The live file goes; the second run retains its entry and its `.zst`, because
    // that artifact is now the only copy.
    std::fs::remove_file(staged.join(STORED.0)).unwrap();
    fx.archive_at(uuid, &["--full", "--include", "scratch"]);
    fx.promote(uuid);
    fx.age_tree(uuid, AGED);

    let entry = fx.manifest(uuid)["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["path"] == STORED.0)
        .expect("the retained entry was reconciled away")
        .clone();
    assert_eq!(
        entry["present"], false,
        "the fixture did not retain: {entry}"
    );
    assert_eq!(
        entry["stored"], true,
        "the fixture retained nothing: {entry}"
    );
    let zst = fx.store_dir(uuid).join(format!("{}.zst", STORED.0));
    assert!(zst.exists(), "the retained artifact is gone");

    let plan = fx.gc_json(&["--full", "--targets", "scratch"]);
    assert_eq!(
        verdict_of(&plan, &fx.session_dir(uuid)).0,
        "delete",
        "a retained entry vetoed --full: {plan:#}"
    );
    // It describes no live byte, so it counts on neither side of the split.
    assert_eq!(plan["reclaimable_archived_bytes"], 0, "{plan:#}");
    assert_eq!(
        plan["reclaimable_unarchived_bytes"],
        UNSTORED.1.len(),
        "{plan:#}"
    );

    let out = fx.run(&["gc", "--full", "--targets", "scratch", "--commit"]);
    assert_eq!(out.code, 0, "{}", out.summary());
    assert!(!fx.session_dir(uuid).exists(), "{}", out.summary());
    assert!(
        zst.exists(),
        "the reclaim destroyed the only remaining copy"
    );
}

/// `--full` adds a gate; it removes none. A live file the ledger does not mention is
/// unarchived data, and the coverage check refuses the tree under `--full` exactly as
/// it does by default.
#[test]
fn p21_b_full_does_not_bypass_the_coverage_gate() {
    let fx = Fx::new("coverage");
    let uuid = "bbbb0006-0000-0000-0000-000000000006";
    fx.tree(uuid, &[UNSTORED], Ledger::CapsLifted);
    // Created after the archive, so no manifest entry names it.
    fx.write_at(&fx.session_dir(uuid), "later.txt", b"never captured\n");
    fx.age_tree(uuid, AGED);

    let plan = fx.gc_json(&["--full", "--targets", "scratch"]);
    assert_eq!(
        verdict_of(&plan, &fx.session_dir(uuid)),
        ("unverified".to_string(), "NoCatalogRow".to_string()),
        "--full skipped the coverage check: {plan:#}"
    );

    let out = fx.run(&["gc", "--full", "--targets", "scratch", "--commit"]);
    assert!(
        fx.session_dir(uuid).exists(),
        "--full deleted a tree holding unarchived data: {}",
        out.summary()
    );
}

// ---------------------------------------------------------------------------
// C. The floor.
// ---------------------------------------------------------------------------

/// `--full` relaxes the floor to `[gc] active_window` and **not below it**. This is
/// what makes the flag safe to run from inside a Claude Code session: that session's
/// own tree is written continuously, so its newest mtime is seconds old and the
/// floor holds it back without consulting any liveness oracle.
#[test]
fn p21_c_full_keeps_the_active_window_floor() {
    let fx = Fx::new("floor");
    let uuid = "cccc0001-0000-0000-0000-000000000001";
    fx.tree(uuid, &[UNSTORED], Ledger::CapsLifted);
    fx.age_tree(uuid, FRESH);

    let plan = fx.gc_json(&["--full", "--targets", "scratch"]);
    assert_eq!(
        verdict_of(&plan, &fx.session_dir(uuid)),
        ("protected".to_string(), "TooYoung".to_string()),
        "--full took a tree inside the active window: {plan:#}"
    );

    let out = fx.run(&["gc", "--full", "--targets", "scratch", "--commit"]);
    assert!(
        fx.session_dir(uuid).exists(),
        "--full deleted a tree inside the active window: {}",
        out.summary()
    );
}

/// `--full` is a level, not a target filter: the age policy relaxes for every
/// family. A transcript with a re-verified store copy, aged past the relaxed floor
/// but inside both the 7d `min_age` and the 90d `transcript_retain`, is `TooYoung`
/// by default and in scope under `--full`. Every archive gate still applies to it.
#[test]
fn p21_c_full_relaxes_the_age_policy_for_every_family() {
    let fx = Fx::new("families");
    let uuid = "cccc0004-0000-0000-0000-000000000004";
    let transcript = fx.archived_transcript(uuid);
    filetime::set_file_mtime(
        &transcript,
        filetime::FileTime::from_system_time(SystemTime::now() - AGED),
    )
    .unwrap();

    let plan = fx.gc_json(&["--targets", "transcripts"]);
    assert_eq!(
        verdict_of(&plan, &transcript),
        ("protected".to_string(), "TooYoung".to_string()),
        "the default floor moved: {plan:#}"
    );

    let plan = fx.gc_json(&["--full", "--targets", "transcripts"]);
    assert_eq!(
        verdict_of(&plan, &transcript).0,
        "delete",
        "--full left an archived transcript out of scope: {plan:#}"
    );
    // The relaxation is of the age policy alone: these bytes are archived, and the
    // scratch advice counts nothing from a `File` candidate.
    assert_eq!(
        plan["reclaimable_archived_bytes"],
        std::fs::metadata(&transcript).unwrap().len(),
        "{plan:#}"
    );
    assert_eq!(plan["scratch_no_ledger"], 0, "{plan:#}");

    let out = fx.run(&["gc", "--full", "--targets", "transcripts", "--commit"]);
    assert_eq!(out.code, 0, "{}", out.summary());
    assert!(!transcript.exists(), "{}", out.summary());
}

/// `--min-age` raises whichever floor is in force and can never lower it — the same
/// law under `--full` as under the aged policy.
#[test]
fn p21_c_min_age_raises_the_relaxed_floor_and_cannot_lower_it() {
    let fx = Fx::new("min-age");
    let aged = "cccc0002-0000-0000-0000-000000000002";
    let fresh = "cccc0003-0000-0000-0000-000000000003";
    fx.tree(aged, &[UNSTORED], Ledger::CapsLifted);
    fx.tree(fresh, &[UNSTORED], Ledger::CapsLifted);
    fx.age_tree(aged, AGED);
    fx.age_tree(fresh, FRESH);

    // Without an override, --full takes the 2h tree and leaves the 10m one.
    let plan = fx.gc_json(&["--full", "--targets", "scratch"]);
    assert_eq!(
        verdict_of(&plan, &fx.session_dir(aged)).0,
        "delete",
        "{plan:#}"
    );
    assert_eq!(
        verdict_of(&plan, &fx.session_dir(fresh)).0,
        "protected",
        "{plan:#}"
    );

    // Raised to 3d, it takes neither.
    let plan = fx.gc_json(&["--full", "--targets", "scratch", "--min-age", "3d"]);
    assert_eq!(
        plan["deletable"], 0,
        "--min-age did not raise the floor: {plan:#}"
    );

    // Lowered to a minute — and to zero, the value an operator reaches for to mean
    // "no floor" — the 10m tree is still out of reach.
    for low in ["1m", "0s"] {
        let plan = fx.gc_json(&["--full", "--targets", "scratch", "--min-age", low]);
        assert_eq!(
            verdict_of(&plan, &fx.session_dir(fresh)),
            ("protected".to_string(), "TooYoung".to_string()),
            "--min-age {low} lowered the relaxed floor: {plan:#}"
        );
        assert_eq!(
            plan["deletable"], 1,
            "--min-age {low} changed what --full claims: {plan:#}"
        );
    }
}

// ---------------------------------------------------------------------------
// D. The byte split.
// ---------------------------------------------------------------------------

/// A total says how much a run reclaims; only the split says how much of it exists
/// nowhere else afterwards. Under `--full` the archived side is **structurally zero**
/// — the verb only takes trees with an empty captured set — and both emitters,
/// human and `--json`, carry it.
#[test]
fn p21_d_the_split_reaches_both_emitters_and_is_zero_archived_under_full() {
    let fx = Fx::new("split-full");
    let uuid = "dddd0001-0000-0000-0000-000000000001";
    fx.tree(uuid, &[UNSTORED], Ledger::CapsLifted);
    fx.age_tree(uuid, AGED);
    let bytes = UNSTORED.1.len();

    let plan = fx.gc_json(&["--full", "--targets", "scratch"]);
    assert_eq!(plan["reclaimable_archived_bytes"], 0, "{plan:#}");
    assert_eq!(plan["reclaimable_unarchived_bytes"], bytes, "{plan:#}");
    let it = item(&plan, &fx.session_dir(uuid));
    assert_eq!(it["archived_bytes"], 0, "{plan:#}");
    assert_eq!(it["unarchived_bytes"], bytes, "{plan:#}");

    let human = fx.run(&["gc", "--full", "--targets", "scratch"]);
    assert!(
        human.stdout.contains(&format!(
            "Of the reclaimable bytes: 0 archived, {bytes} with no archived copy."
        )),
        "the human plan does not carry the split: {}",
        human.summary()
    );

    let out = fx.run(&["gc", "--full", "--targets", "scratch", "--commit"]);
    assert_eq!(out.code, 0, "{}", out.summary());
    assert!(
        out.stdout.contains(&format!(
            "Of the reclaimed bytes: 0 archived, {bytes} with no archived copy."
        )),
        "the human commit report does not carry the split: {}",
        out.summary()
    );

    let fx2 = Fx::new("split-full-json");
    let uuid2 = "dddd0002-0000-0000-0000-000000000002";
    fx2.tree(uuid2, &[UNSTORED], Ledger::CapsLifted);
    fx2.age_tree(uuid2, AGED);
    let report = fx2.gc_json(&["--full", "--targets", "scratch", "--commit"]);
    assert_eq!(report["reclaimed_archived_bytes"], 0, "{report:#}");
    assert_eq!(report["reclaimed_unarchived_bytes"], bytes, "{report:#}");
}

/// And the archived side is really computed: a transcript with a re-verified store
/// copy counts entirely as archived. Without this the assertion above passes on a
/// split hardcoded to `unarchived`.
#[test]
fn p21_d_a_verified_transcript_counts_as_archived_bytes() {
    let fx = Fx::new("split-file");
    let uuid = "dddd0003-0000-0000-0000-000000000003";
    let transcript = fx.archived_transcript(uuid);
    let bytes = std::fs::metadata(&transcript).unwrap().len();
    // Past the 7d floor and the 90d transcript retain window.
    filetime::set_file_mtime(
        &transcript,
        filetime::FileTime::from_system_time(SystemTime::now() - Duration::from_secs(100 * 86_400)),
    )
    .unwrap();

    let plan = fx.gc_json(&["--targets", "transcripts"]);
    assert_eq!(plan["deletable"], 1, "{plan:#}");
    assert_eq!(plan["reclaimable_archived_bytes"], bytes, "{plan:#}");
    assert_eq!(plan["reclaimable_unarchived_bytes"], 0, "{plan:#}");

    // An unarchived transcript is the other side of the same claim: no verified
    // copy, so none of its bytes are archived.
    let bare = fx
        .home
        .join(".claude/projects")
        .join(&fx.slug)
        .join("dddd0004-0000-0000-0000-000000000004.jsonl");
    std::fs::write(&bare, "{\"type\":\"user\"}\n").unwrap();
    let plan = fx.gc_json(&["--targets", "transcripts"]);
    let it = item(&plan, &bare);
    assert_eq!(it["reason"], "NoCatalogRow", "{plan:#}");
    assert_eq!(it["archived_bytes"], 0, "{plan:#}");
    assert_eq!(
        it["unarchived_bytes"],
        std::fs::metadata(&bare).unwrap().len(),
        "{plan:#}"
    );
    // `NoCatalogRow` on a `File` candidate says nothing about a scratch ledger, and
    // must not reach the count that sends an operator to `archive --all --full`.
    assert_eq!(plan["scratch_no_ledger"], 0, "{plan:#}");
}

// ---------------------------------------------------------------------------
// E. Flag surface.
// ---------------------------------------------------------------------------

/// `--discover-all-users` returns before a target is parsed and cannot delete
/// anything; `candidates()` refuses a foreign root anyway. The pair can only
/// mislead about what the run did, so it is refused at parse time — the cheapest
/// correct answer, and one that cannot drift from the code.
#[test]
fn p21_e_full_and_discover_all_users_is_a_parse_error() {
    let fx = Fx::new("conflict");
    let out = fx.run(&["gc", "--full", "--discover-all-users"]);
    assert_eq!(out.code, 2, "the flag pair was accepted: {}", out.summary());
    assert!(
        out.stderr.contains("cannot be used with"),
        "clap did not report the conflict: {}",
        out.summary()
    );
    assert!(
        out.stdout.trim().is_empty(),
        "a refused parse produced a report: {}",
        out.summary()
    );
}
