//! P24 break tests: `gc --wipe`.
//!
//! `--wipe` is the third of `clear`'s three levels (decision #11), and the only one
//! that can destroy a working tree yomi holds no copy of. It bypasses **exactly one**
//! thing — the scratch coverage pass — and the whole of this file is about the
//! boundary of that one thing:
//!
//! * **what it claims.** A tree with no ledger, an illegible ledger, or a captured
//!   set that is not empty. The first is refused by both other levels, the third is
//!   held at `Captured` by `--full`; `--wipe` takes all three, because its
//!   authorization is the flag and not any fact read from the store.
//! * **what it does not touch.** Root ownership, containment, the blacklist scan
//!   inside the tree removal, both liveness legs, the relaxed floor, `--commit`, the
//!   commit-time re-evaluation — and every one of the `File` gates. That last one is
//!   the load-bearing asymmetry: the scratch gate demands coverage of data archive
//!   deliberately declines to store, which no run can supply, while a `File` gate
//!   demands coverage of data archive *does* store, which one `yomi archive` run
//!   always supplies. There is nothing to bypass for, and bypassing it would be the
//!   only way to lose a transcript irrecoverably.
//! * **what it reports.** Everything not proved archived counts as unarchived, so
//!   `archived + unarchived` equals the tree's live size exactly and the figure an
//!   operator reads as "this exists in no other copy" cannot understate. Plus the
//!   `gc.log` run header and the pre-unlink stdout line, which are decision #6's
//!   answer to "why no second confirmation gate".
//!
//! Every fixture is fabricated under `CARGO_TARGET_TMPDIR` and removed when the
//! fixture drops. The store sits at `<home>/.yomi`, as it does in production, so
//! "`--wipe` never reaches the store" is asserted against the real layout rather
//! than against a fixture that puts the store out of reach by accident. No real
//! Claude Code data, no real `~/.yomi`, no `/tmp` (issue #48).

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

const BIN: &str = env!("CARGO_BIN_EXE_yomi");

/// Not matched by any `[scratch]` allow glob: manifested, never stored, whatever the
/// caps say.
const UNSTORED: (&str, &[u8]) = ("data.dat", b"build output, nobody wants a copy\n");

/// Matched by `*.md`, so a caps-lifted run stores it and the captured set is not
/// empty — the state `--full` holds at `Captured` and `--wipe` takes.
const STORED: (&str, &[u8]) = ("scratchpad/keep.md", b"notes worth keeping\n");

/// Past the relaxed floor (`[gc] active_window`, 1h) and under the 7d default floor,
/// so the same tree is `TooYoung` by default and in scope under `--wipe`.
const AGED: Duration = Duration::from_secs(2 * 3_600);
/// Inside the relaxed floor.
const FRESH: Duration = Duration::from_secs(600);

/// Which ledger a fixture tree should have when gc meets it.
enum Ledger {
    /// Never archived — no manifest at all.
    None,
    /// Archived by `archive --full`.
    CapsLifted,
}

fn unique() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// This process's uid, read off a file it just created rather than from a syscall
/// crate the test target does not depend on.
fn euid() -> u32 {
    static UID: OnceLock<u32> = OnceLock::new();
    *UID.get_or_init(|| {
        let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("p24-uid-{}", unique()));
        std::fs::write(&p, b"").unwrap();
        let uid = std::fs::metadata(&p).unwrap().uid();
        let _ = std::fs::remove_file(&p);
        uid
    })
}

/// A real directory on this host owned by another uid, standing in for a poisoned
/// `YOMI_TMP_ROOT`. `None` only when this process is root: nothing is foreign to uid
/// 0, so there is no guard to exercise. A non-root host with no such directory fails
/// loudly rather than passing while proving nothing (p19's rule).
fn foreign_root() -> Option<PathBuf> {
    if euid() == 0 {
        return None;
    }
    let found = ["/var/empty", "/root", "/usr"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| {
            std::fs::metadata(p)
                .map(|md| md.is_dir() && md.uid() != euid())
                .unwrap_or(false)
        });
    assert!(
        found.is_some(),
        "no foreign-owned directory found on this host; nothing here can be proven"
    );
    found
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
            "p24-{tag}-{}-{}",
            std::process::id(),
            unique()
        ));
        let home = base.join("home");
        let fx = Fx {
            // The production position: the store is a sibling of `.claude` inside
            // $HOME, and $HOME is not one of the three source roots. Nothing in this
            // file may reach it.
            yomi_home: home.join(".yomi"),
            home,
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

    /// A private root holding one tree, so an `archive` run there decides about that
    /// tree and no other. The tree is moved into the shared `tmp_root` afterwards:
    /// the store key and the recorded identity both derive from the last two path
    /// components (`<slug>/<uuid>`), so the move keeps them.
    fn stage_root(&self, uuid: &str) -> PathBuf {
        self.base.join(format!("stage-{uuid}"))
    }

    fn stage_dir(&self, uuid: &str) -> PathBuf {
        self.stage_root(uuid).join(&self.slug).join(uuid)
    }

    fn write_at(&self, dir: &Path, rel: &str, bytes: &[u8]) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
    }

    fn promote(&self, uuid: &str) {
        let dest = self.tmp_root.join(&self.slug);
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::rename(self.stage_dir(uuid), dest.join(uuid)).unwrap();
    }

    /// Build one tree, give it the ledger asked for, and place it under `tmp_root`.
    fn tree(&self, uuid: &str, files: &[(&str, &[u8])], ledger: Ledger) {
        let staged = self.stage_dir(uuid);
        std::fs::create_dir_all(&staged).unwrap();
        for (rel, bytes) in files {
            self.write_at(&staged, rel, bytes);
        }
        match ledger {
            Ledger::None => {}
            Ledger::CapsLifted => {
                let out = self.run_at(
                    &self.stage_root(uuid),
                    &["archive", "--full", "--include", "scratch"],
                );
                assert_eq!(out.code, 0, "archive failed: {}", out.summary());
            }
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

    /// A transcript plus its archive, so a `File` candidate exists with a verified
    /// catalog row behind it. Every transcript already on disk is archived too, so
    /// callers wanting an *un*archived one write it after this returns.
    fn archived_transcript(&self, uuid: &str) -> PathBuf {
        let p = self.transcript(uuid);
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

    fn transcript(&self, uuid: &str) -> PathBuf {
        self.home
            .join(".claude/projects")
            .join(&self.slug)
            .join(format!("{uuid}.jsonl"))
    }

    fn age_file(&self, path: &Path, age: Duration) {
        filetime::set_file_mtime(
            path,
            filetime::FileTime::from_system_time(SystemTime::now() - age),
        )
        .unwrap();
    }

    /// Write `sessions/<pid>.json` linking a pid to a session uuid, and make the pid
    /// look alive — the two halves of the uuid liveness leg.
    fn set_live_session(&self, pid: u32, uuid: &str) {
        let dir = self.home.join(".claude/sessions");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(format!("{pid}.json")),
            serde_json::json!({"sessionId": uuid, "cwd": "/home/test"}).to_string(),
        )
        .unwrap();
        std::fs::create_dir_all(self.proc_root.join(pid.to_string())).unwrap();
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

fn bytes_of(files: &[(&str, &[u8])]) -> u64 {
    files.iter().map(|(_, b)| b.len() as u64).sum()
}

// ---------------------------------------------------------------------------
// A. What `--wipe` claims — the one bypass.
// ---------------------------------------------------------------------------

/// **The feature.** A tree nothing ever archived is `Unverified{NoCatalogRow}` under
/// the default level and under `--full`, and that refusal is correct there: the
/// unknown is not the empty set. `--wipe` is the level that says "delete it anyway",
/// and it must, or the 468MB of build output the design exists to reclaim stays
/// forever out of reach.
#[test]
fn p24_a_wipe_takes_a_tree_with_no_ledger() {
    let fx = Fx::new("no-ledger");
    let uuid = "aaaa0001-0000-0000-0000-000000000001";
    fx.tree(uuid, &[UNSTORED, STORED], Ledger::None);
    fx.age_tree(uuid, AGED);

    // Both other levels refuse it, with the same reason and for the same cause: the
    // coverage pass runs before the age gate, so no ledger means no delete at any age.
    for level in [
        vec!["--targets", "scratch"],
        vec!["--full", "--targets", "scratch"],
    ] {
        let plan = fx.gc_json(&level);
        assert_eq!(
            verdict_of(&plan, &fx.session_dir(uuid)),
            ("unverified".to_string(), "NoCatalogRow".to_string()),
            "{level:?} changed its mind about an unarchived tree: {plan:#}"
        );
        assert_eq!(plan["scratch_no_ledger"], 1, "{level:?}: {plan:#}");
    }

    let plan = fx.gc_json(&["--wipe", "--targets", "scratch"]);
    assert_eq!(plan["deletable"], 1, "--wipe left the tree: {plan:#}");
    assert_eq!(verdict_of(&plan, &fx.session_dir(uuid)).0, "delete");
    // No ledger was consulted, so no ledger-shaped refusal can be counted either.
    assert_eq!(plan["scratch_no_ledger"], 0, "{plan:#}");

    let out = fx.run(&["gc", "--wipe", "--targets", "scratch", "--commit"]);
    assert_eq!(out.code, 0, "{}", out.summary());
    assert!(
        !fx.session_dir(uuid).exists(),
        "--wipe did not delete a tree with no ledger: {}",
        out.summary()
    );
}

/// A tree whose captured set is **not** empty. `--full` holds it at `Captured`
/// because deciding the fate of stored content is not what that level claims;
/// `--wipe` claims it. The `.zst` copies are untouched either way — the store is not
/// a source, and no level of `clear` reaches into it.
#[test]
fn p24_a_wipe_takes_a_tree_whose_captured_set_is_not_empty() {
    let fx = Fx::new("captured");
    let uuid = "aaaa0002-0000-0000-0000-000000000002";
    fx.tree(uuid, &[STORED, UNSTORED], Ledger::CapsLifted);
    fx.age_tree(uuid, AGED);
    let zst = fx.store_dir(uuid).join(format!("{}.zst", STORED.0));
    assert!(zst.exists(), "the fixture stored nothing");

    let plan = fx.gc_json(&["--full", "--targets", "scratch"]);
    assert_eq!(
        verdict_of(&plan, &fx.session_dir(uuid)),
        ("protected".to_string(), "Captured".to_string()),
        "{plan:#}"
    );

    let plan = fx.gc_json(&["--wipe", "--targets", "scratch"]);
    assert_eq!(
        verdict_of(&plan, &fx.session_dir(uuid)).0,
        "delete",
        "--wipe stopped at Captured: {plan:#}"
    );

    let out = fx.run(&["gc", "--wipe", "--targets", "scratch", "--commit"]);
    assert_eq!(out.code, 0, "{}", out.summary());
    assert!(!fx.session_dir(uuid).exists(), "{}", out.summary());
    assert!(zst.exists(), "--wipe destroyed a stored copy");
    assert!(
        fx.store_dir(uuid).join("manifest.json").exists(),
        "--wipe destroyed the ledger it was not consulting"
    );
}

/// A ledger that will not parse. Under the coverage pass this is the same refusal as
/// no ledger at all — nothing may be concluded from an illegible one — and under
/// `--wipe` it is not a refusal at all, because no conclusion is being drawn from it.
/// It costs the report its archived side and costs the verdict nothing.
#[test]
fn p24_a_wipe_takes_a_tree_whose_manifest_will_not_parse() {
    let fx = Fx::new("bad-ledger");
    let uuid = "aaaa0003-0000-0000-0000-000000000003";
    fx.tree(uuid, &[STORED, UNSTORED], Ledger::CapsLifted);
    std::fs::write(fx.store_dir(uuid).join("manifest.json"), b"{ not json").unwrap();
    fx.age_tree(uuid, AGED);
    let live = bytes_of(&[STORED, UNSTORED]);

    let plan = fx.gc_json(&["--full", "--targets", "scratch"]);
    assert_eq!(
        verdict_of(&plan, &fx.session_dir(uuid)),
        ("unverified".to_string(), "NoCatalogRow".to_string()),
        "{plan:#}"
    );

    let plan = fx.gc_json(&["--wipe", "--targets", "scratch"]);
    assert_eq!(
        verdict_of(&plan, &fx.session_dir(uuid)).0,
        "delete",
        "{plan:#}"
    );
    // Nothing is proved, so nothing is claimed: every live byte is unarchived even
    // though a `.zst` for one of them is sitting in the store.
    assert_eq!(plan["reclaimable_archived_bytes"], 0, "{plan:#}");
    assert_eq!(plan["reclaimable_unarchived_bytes"], live, "{plan:#}");

    let out = fx.run(&["gc", "--wipe", "--targets", "scratch", "--commit"]);
    assert_eq!(out.code, 0, "{}", out.summary());
    assert!(!fx.session_dir(uuid).exists(), "{}", out.summary());
}

// ---------------------------------------------------------------------------
// B. What `--wipe` does not touch. One test per guard.
// ---------------------------------------------------------------------------

/// Cross-user hard guard. `candidates()` generates nothing from a root this euid does
/// not own, whatever level is asked for, and `--wipe` is the level where being wrong
/// about it is unrecoverable.
#[test]
fn p24_b_wipe_generates_no_candidate_from_a_foreign_root() {
    let Some(foreign) = foreign_root() else {
        return;
    };
    let fx = Fx::new("foreign-root");
    let uuid = "bbbb0001-0000-0000-0000-000000000001";
    // A tree under the fixture's own root, which is *not* the root the run is
    // pointed at: nothing here may be claimed either.
    fx.tree(uuid, &[UNSTORED], Ledger::None);
    fx.age_tree(uuid, AGED);

    let out = fx.run_at(
        &foreign,
        &["gc", "--wipe", "--targets", "scratch", "--commit"],
    );
    assert!(
        out.code == 0 || out.code == 2,
        "a foreign root ended the run: {}",
        out.summary()
    );
    assert!(
        out.stdout.contains("Deleted 0 items"),
        "--wipe claimed something from a root it does not own ({}): {}",
        foreign.display(),
        out.summary()
    );
    assert!(
        fx.session_dir(uuid).exists(),
        "a tree under the fixture root was deleted by a run pointed elsewhere: {}",
        out.summary()
    );
}

/// Containment. A session directory that is a symlink at a tree outside every source
/// root must not take `--wipe` out of the roots. Two layers stand here and both are
/// in force: `single::scratch` classifies directory entries without following them,
/// so a symlink is never enumerated as a tree, and `under_allowed` canonicalizes any
/// candidate that does get generated before the delete path sees it — a check
/// `plan()` applies with no reference to the level.
#[test]
fn p24_b_a_symlinked_tree_does_not_take_wipe_out_of_the_roots() {
    let fx = Fx::new("containment");
    let real = "bbbb0002-0000-0000-0000-000000000002";
    let linked = "bbbb0003-0000-0000-0000-000000000003";
    fx.tree(real, &[UNSTORED], Ledger::None);
    fx.age_tree(real, AGED);

    let outside = fx.base.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let victim = outside.join("secret.txt");
    std::fs::write(&victim, b"not yomi's to delete\n").unwrap();
    let link = fx.session_dir(linked);
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    let out = fx.run(&["gc", "--wipe", "--targets", "scratch", "--commit"]);
    assert!(
        !fx.session_dir(real).exists(),
        "the fixture proved nothing — the real tree survived: {}",
        out.summary()
    );
    assert!(
        victim.exists() && outside.exists(),
        "--wipe followed a symlinked session dir out of the source roots: {}",
        out.summary()
    );
    assert!(
        link.symlink_metadata().is_ok(),
        "--wipe unlinked a symlink it never enumerated: {}",
        out.summary()
    );
}

/// **The blacklist scan needs no new code, and this pins it.** `perform_delete` takes
/// a scratch tree only when `remove_tree_guarded` reports `Removed`; a credential
/// hardlinked into the tree makes it report `Blacklisted`, which becomes `Ok(false)`
/// → one `flipped_unverified` and a `gc.log` skip. So `--wipe` cannot unlink a
/// credential through a hardlink either, and the run is partial rather than silent.
#[test]
fn p24_b_wipe_does_not_unlink_a_credential_through_a_hardlink() {
    let fx = Fx::new("credential");
    let uuid = "bbbb0004-0000-0000-0000-000000000004";
    let cred = fx.home.join(".claude/.credentials.json");
    std::fs::write(&cred, b"{\"token\":\"x\"}\n").unwrap();

    let staged = fx.stage_dir(uuid);
    fx.write_at(&staged, UNSTORED.0, UNSTORED.1);
    std::fs::hard_link(&cred, staged.join("evil.json")).unwrap();
    fx.promote(uuid);
    fx.age_tree(uuid, AGED);

    let plan = fx.gc_json(&["--wipe", "--targets", "scratch"]);
    assert_eq!(
        verdict_of(&plan, &fx.session_dir(uuid)).0,
        "delete",
        "the fixture never reached the unlink guard: {plan:#}"
    );

    let out = fx.run(&["gc", "--wipe", "--targets", "scratch", "--commit"]);
    assert_eq!(
        out.code,
        2,
        "a refused delete must make the run partial: {}",
        out.summary()
    );
    assert!(
        cred.exists() && std::fs::read(&cred).unwrap() == b"{\"token\":\"x\"}\n",
        "--wipe destroyed a credential through a hardlink: {}",
        out.summary()
    );
    assert!(
        fx.session_dir(uuid).exists(),
        "the tree was removed around a blacklisted inode: {}",
        out.summary()
    );
    assert!(
        fx.gc_log()
            .iter()
            .any(|r| r["action"] == "skip" && r["reason"] == "InodeDriftOrBlacklist"),
        "the refusal left no audit record: {:?}",
        fx.gc_log()
    );
}

/// Liveness leg 1: the tree's uuid is in the active session set. Aged well past the
/// floor, so the floor is not what answers here.
#[test]
fn p24_b_wipe_protects_a_live_session_uuid() {
    let fx = Fx::new("live-uuid");
    let uuid = "bbbb0005-0000-0000-0000-000000000005";
    fx.tree(uuid, &[UNSTORED], Ledger::None);
    fx.age_tree(uuid, Duration::from_secs(30 * 86_400));
    fx.set_live_session(4242, uuid);

    let plan = fx.gc_json(&["--wipe", "--targets", "scratch"]);
    assert_eq!(
        verdict_of(&plan, &fx.session_dir(uuid)),
        ("protected".to_string(), "SessionLive".to_string()),
        "--wipe took a live session's tree: {plan:#}"
    );

    let out = fx.run(&["gc", "--wipe", "--targets", "scratch", "--commit"]);
    assert!(
        fx.session_dir(uuid).exists(),
        "--wipe deleted a live session's tree: {}",
        out.summary()
    );
}

/// The floor, which is liveness leg 2 in practice. A tree written 10 minutes ago is
/// out of `--wipe`'s reach, and that is what makes the level safe to run from inside
/// a Claude Code session: that session's own scratchpad is written continuously, so
/// its newest mtime is seconds old and no oracle has to be consulted to hold it back.
///
/// The reason reported is `TooYoung` rather than `SessionLive`, and under this level
/// it always will be: the relaxed floor *is* `[gc] active_window`, so the newest-mtime
/// window can never be the binding one — clearing the floor means clearing the window.
/// The mtime leg stays in place regardless, since it is the same code all three levels
/// run and the default level's floor sits far above the window.
#[test]
fn p24_b_wipe_keeps_the_relaxed_floor() {
    let fx = Fx::new("floor");
    let uuid = "bbbb0006-0000-0000-0000-000000000006";
    fx.tree(uuid, &[UNSTORED], Ledger::None);
    fx.age_tree(uuid, FRESH);

    let plan = fx.gc_json(&["--wipe", "--targets", "scratch"]);
    assert_eq!(
        verdict_of(&plan, &fx.session_dir(uuid)),
        ("protected".to_string(), "TooYoung".to_string()),
        "--wipe took a tree inside the relaxed floor: {plan:#}"
    );
    assert_eq!(plan["deletable"], 0, "{plan:#}");

    let out = fx.run(&["gc", "--wipe", "--targets", "scratch", "--commit"]);
    assert!(
        fx.session_dir(uuid).exists(),
        "--wipe deleted a tree inside the relaxed floor: {}",
        out.summary()
    );
}

/// `--min-age` raises whichever floor is in force and can never lower it — the same
/// law under `--wipe` as everywhere else, including for the value an operator reaches
/// for to mean "no floor at all".
#[test]
fn p24_b_min_age_raises_the_wipe_floor_and_cannot_lower_it() {
    let fx = Fx::new("min-age");
    let aged = "bbbb0007-0000-0000-0000-000000000007";
    let fresh = "bbbb0008-0000-0000-0000-000000000008";
    fx.tree(aged, &[UNSTORED], Ledger::None);
    fx.tree(fresh, &[UNSTORED], Ledger::None);
    fx.age_tree(aged, AGED);
    fx.age_tree(fresh, FRESH);

    let plan = fx.gc_json(&["--wipe", "--targets", "scratch"]);
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

    let plan = fx.gc_json(&["--wipe", "--targets", "scratch", "--min-age", "3d"]);
    assert_eq!(
        plan["deletable"], 0,
        "--min-age did not raise the floor under --wipe: {plan:#}"
    );

    for low in ["1m", "0s"] {
        let plan = fx.gc_json(&["--wipe", "--targets", "scratch", "--min-age", low]);
        assert_eq!(
            verdict_of(&plan, &fx.session_dir(fresh)),
            ("protected".to_string(), "TooYoung".to_string()),
            "--min-age {low} lowered the floor under --wipe: {plan:#}"
        );
        assert_eq!(
            plan["deletable"], 1,
            "--min-age {low} changed what --wipe claims: {plan:#}"
        );
    }
}

/// **The demonstration of §5's asymmetry.** A transcript with no catalog row survives
/// `--wipe` untouched, because the `File` gates are satisfiable: one `yomi archive`
/// run makes it deletable, so bypassing them would buy nothing and would be the only
/// way in the binary to lose a transcript irrecoverably. The archived twin in the same
/// run *is* taken, so this does not pass on a `--wipe` that refuses every file.
#[test]
fn p24_b_wipe_keeps_every_file_gate() {
    let fx = Fx::new("file-gates");
    let archived = "bbbb0009-0000-0000-0000-000000000009";
    let bare = "bbbb0010-0000-0000-0000-000000000010";
    let archived_path = fx.archived_transcript(archived);
    // Written after the archive run, so no catalog row names it.
    let bare_path = fx.transcript(bare);
    std::fs::write(&bare_path, b"{\"type\":\"user\"}\n").unwrap();
    for p in [&archived_path, &bare_path] {
        fx.age_file(p, AGED);
    }

    let plan = fx.gc_json(&["--wipe", "--targets", "transcripts"]);
    assert_eq!(
        verdict_of(&plan, &bare_path),
        ("unverified".to_string(), "NoCatalogRow".to_string()),
        "--wipe waved a transcript past the catalog gate: {plan:#}"
    );
    assert_eq!(
        verdict_of(&plan, &archived_path).0,
        "delete",
        "the fixture proved nothing — no file was in scope at all: {plan:#}"
    );

    let out = fx.run(&["gc", "--wipe", "--targets", "transcripts", "--commit"]);
    assert_eq!(
        out.code,
        2,
        "an unverified item is a partial run: {}",
        out.summary()
    );
    assert!(
        bare_path.exists(),
        "--wipe deleted an unarchived transcript: {}",
        out.summary()
    );
    assert!(
        !archived_path.exists(),
        "--wipe left an archived transcript: {}",
        out.summary()
    );
}

/// `--commit` is the gate, and it is the only one. Without it a `--wipe` run is a
/// pure read: nothing is deleted and no `gc.log` is opened.
#[test]
fn p24_b_wipe_without_commit_deletes_nothing() {
    let fx = Fx::new("dry-run");
    let uuid = "bbbb0011-0000-0000-0000-000000000011";
    fx.tree(uuid, &[UNSTORED], Ledger::None);
    fx.age_tree(uuid, AGED);

    let out = fx.run(&["gc", "--wipe", "--targets", "scratch"]);
    assert_eq!(out.code, 0, "{}", out.summary());
    assert!(
        fx.session_dir(uuid).exists(),
        "a dry run deleted: {}",
        out.summary()
    );
    assert!(
        !fx.yomi_home.join("gc.log").exists(),
        "a dry run wrote gc.log"
    );
    assert!(
        out.stdout.contains("Run with --commit to apply."),
        "{}",
        out.summary()
    );
    assert!(
        out.stdout.contains("--wipe consults no ledger"),
        "the dry run did not say what --wipe claims: {}",
        out.summary()
    );
}

/// `--wipe` never reaches `~/.yomi`. `gc`'s candidates are defined over the three
/// **source** roots; the store is a destination, and admitting it would widen the
/// containment guard for every candidate generator that follows. The store also holds
/// `quarantine/`, whose unredacted originals are the last copy of what redaction took
/// out. Asserted with the store at its production position — a sibling of `.claude`
/// inside $HOME — and against a run with the default target set, which is every
/// family.
#[test]
fn p24_b_wipe_does_not_touch_the_store() {
    let fx = Fx::new("store");
    let uuid = "bbbb0012-0000-0000-0000-000000000012";
    fx.tree(uuid, &[STORED, UNSTORED], Ledger::CapsLifted);
    fx.age_tree(uuid, AGED);
    // A quarantine artifact standing in for an unredacted original.
    let q = fx.yomi_home.join("quarantine/keepsafe.jsonl");
    std::fs::create_dir_all(q.parent().unwrap()).unwrap();
    std::fs::write(&q, b"unredacted\n").unwrap();

    let out = fx.run(&["gc", "--wipe", "--commit"]);
    assert!(
        out.code == 0 || out.code == 2,
        "the run failed: {}",
        out.summary()
    );
    assert!(
        !fx.session_dir(uuid).exists(),
        "the fixture proved nothing — nothing was wiped at all: {}",
        out.summary()
    );
    for p in [
        fx.yomi_home.clone(),
        fx.yomi_home.join(".yomi-store"),
        fx.yomi_home.join("archive/_scratch").join(fx.key(uuid)),
        fx.store_dir(uuid).join("manifest.json"),
        fx.store_dir(uuid).join(format!("{}.zst", STORED.0)),
        fx.yomi_home.join("state/catalog.db"),
        q.clone(),
    ] {
        assert!(
            p.exists(),
            "--wipe removed {} from the store: {}",
            p.display(),
            out.summary()
        );
    }
}

// ---------------------------------------------------------------------------
// C. What `--wipe` reports.
// ---------------------------------------------------------------------------

/// **Everything not proved archived is counted unarchived**, and `archived +
/// unarchived` equals the tree's live size exactly. Three states in one run:
///
/// * no ledger — every byte unarchived;
/// * a caps-lifted ledger with one stored file — that file's bytes archived, the rest
///   not;
/// * the same, plus a file written after the capture. No ledger names it, and under
///   the coverage pass it cannot exist (check 1 refuses the tree), so counting it is
///   `--wipe`'s own problem. Left out, the one figure an operator reads as "this
///   exists in no other copy" would understate on the one level that can destroy it.
#[test]
fn p24_c_the_split_counts_everything_unproved_as_unarchived() {
    let fx = Fx::new("split");
    let bare = "cccc0001-0000-0000-0000-000000000001";
    let captured = "cccc0002-0000-0000-0000-000000000002";
    let delta = "cccc0003-0000-0000-0000-000000000003";
    const LATER: (&str, &[u8]) = ("later.txt", b"written after the capture\n");

    fx.tree(bare, &[STORED, UNSTORED], Ledger::None);
    fx.tree(captured, &[STORED, UNSTORED], Ledger::CapsLifted);
    fx.tree(delta, &[STORED], Ledger::CapsLifted);
    fx.write_at(&fx.session_dir(delta), LATER.0, LATER.1);
    for uuid in [bare, captured, delta] {
        fx.age_tree(uuid, AGED);
    }

    let stored = bytes_of(&[STORED]);
    let unstored = bytes_of(&[UNSTORED]);
    let later = bytes_of(&[LATER]);
    let expected = [
        (bare, 0, stored + unstored),
        (captured, stored, unstored),
        (delta, stored, later),
    ];

    let plan = fx.gc_json(&["--wipe", "--targets", "scratch"]);
    assert_eq!(plan["deletable"], 3, "{plan:#}");
    for (uuid, archived, unarchived) in expected {
        let it = item(&plan, &fx.session_dir(uuid));
        assert_eq!(it["archived_bytes"], archived, "{uuid}: {plan:#}");
        assert_eq!(it["unarchived_bytes"], unarchived, "{uuid}: {plan:#}");
        assert_eq!(
            it["bytes"],
            archived + unarchived,
            "{uuid}: the split does not account for every live byte: {plan:#}"
        );
    }
    let total_archived: u64 = expected.iter().map(|(_, a, _)| a).sum();
    let total_unarchived: u64 = expected.iter().map(|(_, _, u)| u).sum();
    assert_eq!(
        plan["reclaimable_archived_bytes"], total_archived,
        "{plan:#}"
    );
    assert_eq!(
        plan["reclaimable_unarchived_bytes"], total_unarchived,
        "{plan:#}"
    );

    // Both emitters carry it: the human plan, and the human commit report.
    let human = fx.run(&["gc", "--wipe", "--targets", "scratch"]);
    let split_line = format!(
        "Of the reclaimable bytes: {total_archived} archived, {total_unarchived} with no archived copy."
    );
    assert!(
        human.stdout.contains(&split_line),
        "the human plan does not carry the split: {}",
        human.summary()
    );

    let out = fx.run(&["gc", "--wipe", "--targets", "scratch", "--commit"]);
    assert_eq!(out.code, 0, "{}", out.summary());
    assert!(
        out.stdout.contains(&format!(
            "Of the reclaimed bytes: {total_archived} archived, {total_unarchived} with no archived copy."
        )),
        "the human commit report does not carry the split: {}",
        out.summary()
    );
}

/// The `gc.log` run header: what a wipe intended, in one record, **before the first
/// unlink**. Every other line in the log is per-candidate, so without it "who wiped
/// what, and how much of it had no copy" costs a sum over the whole file.
///
/// Its position is the ordering evidence: `commit` writes it before entering the loop
/// that unlinks, so a header anywhere but first would mean it was written after a
/// delete.
#[test]
fn p24_c_the_run_header_records_what_the_wipe_intended() {
    let fx = Fx::new("header");
    let uuid = "cccc0004-0000-0000-0000-000000000004";
    fx.tree(uuid, &[STORED, UNSTORED], Ledger::CapsLifted);
    fx.age_tree(uuid, AGED);

    let out = fx.run(&[
        "gc",
        "--wipe",
        "--targets",
        "scratch,empty-dirs",
        "--commit",
    ]);
    assert_eq!(out.code, 0, "{}", out.summary());
    let log = fx.gc_log();
    let head = log.first().expect("gc.log is empty");
    assert_eq!(
        head["action"], "run",
        "the run header is not the first record: {log:?}"
    );
    assert_eq!(head["verb"], "wipe", "{head}");
    assert_eq!(
        head["targets"],
        serde_json::json!(["scratch", "empty-dirs"]),
        "the header does not name the requested targets: {head}"
    );
    assert_eq!(head["planned_trees"], 1, "{head}");
    assert_eq!(head["planned_deletes"], 1, "{head}");
    assert_eq!(head["archived_bytes"], bytes_of(&[STORED]), "{head}");
    assert_eq!(head["unarchived_bytes"], bytes_of(&[UNSTORED]), "{head}");
    assert_eq!(
        head["min_age_secs"], 3_600,
        "the header does not record the floor in force: {head}"
    );
    assert!(
        log.iter().any(|r| r["action"] == "delete"),
        "no candidate record followed the header: {log:?}"
    );
}

/// The header belongs to `--wipe` alone. The other two levels refuse anything they
/// cannot prove, so the question it answers — how much of what a run destroyed had no
/// copy — has one possible answer there, and a record shaped by the level is worse
/// than no record.
#[test]
fn p24_c_the_other_levels_write_no_run_header() {
    let fx = Fx::new("no-header");
    let uuid = "cccc0005-0000-0000-0000-000000000005";
    fx.tree(uuid, &[UNSTORED], Ledger::CapsLifted);
    fx.age_tree(uuid, AGED);

    for level in [
        vec!["gc", "--targets", "scratch", "--commit"],
        vec!["gc", "--full", "--targets", "scratch", "--commit"],
    ] {
        let out = fx.run(&level);
        assert!(
            out.code == 0 || out.code == 2,
            "{level:?}: {}",
            out.summary()
        );
        assert!(
            !fx.gc_log().iter().any(|r| r["action"] == "run"),
            "{level:?} wrote a run header: {:?}",
            fx.gc_log()
        );
    }
}

/// The pre-unlink stdout line, decision #6's other half. What it must not be is a
/// rendering of what happened: here the one planned delete is refused at commit by
/// the blacklist scan, nothing is deleted, and the line is still printed — because it
/// is emitted from the plan, between the plan and the first unlink. It also precedes
/// the commit report in the stream, so a run killed halfway leaves the numbers in the
/// operator's scrollback.
#[test]
fn p24_c_commit_announces_the_wipe_before_it_starts() {
    let fx = Fx::new("announce");
    let uuid = "cccc0006-0000-0000-0000-000000000006";
    fx.tree(uuid, &[UNSTORED], Ledger::None);
    fx.age_tree(uuid, AGED);

    let out = fx.run(&["gc", "--wipe", "--targets", "scratch", "--commit"]);
    assert_eq!(out.code, 0, "{}", out.summary());
    let announce = out
        .stdout
        .find("wipe: deleting 1 scratch tree(s)")
        .unwrap_or_else(|| panic!("the wipe was not announced: {}", out.summary()));
    let report = out
        .stdout
        .find("Deleted 1 items")
        .unwrap_or_else(|| panic!("no commit report: {}", out.summary()));
    assert!(
        announce < report,
        "the announcement followed the report: {}",
        out.summary()
    );
    assert!(
        out.stdout.contains(&format!(
            "{} bytes — 0 archived, {} with no archived copy anywhere.",
            bytes_of(&[UNSTORED]),
            bytes_of(&[UNSTORED])
        )),
        "the announcement does not carry the split: {}",
        out.summary()
    );

    // A run whose only delete is refused still announces: the line comes from the
    // plan, not from the outcome.
    let fx2 = Fx::new("announce-refused");
    let uuid2 = "cccc0007-0000-0000-0000-000000000007";
    let cred = fx2.home.join(".claude/.credentials.json");
    std::fs::write(&cred, b"{\"token\":\"x\"}\n").unwrap();
    let staged = fx2.stage_dir(uuid2);
    fx2.write_at(&staged, UNSTORED.0, UNSTORED.1);
    std::fs::hard_link(&cred, staged.join("evil.json")).unwrap();
    fx2.promote(uuid2);
    fx2.age_tree(uuid2, AGED);

    let out = fx2.run(&["gc", "--wipe", "--targets", "scratch", "--commit"]);
    assert_eq!(out.code, 2, "{}", out.summary());
    assert!(
        out.stdout.contains("wipe: deleting 1 scratch tree(s)"),
        "the announcement was derived from the outcome: {}",
        out.summary()
    );
    assert!(
        out.stdout.contains("Deleted 0 items"),
        "the fixture deleted something: {}",
        out.summary()
    );
}

/// Under `--json` the announcement goes to stderr. A human line on stdout would make
/// the report unparseable, and the report is the one thing a caller must be able to
/// read; the numbers are in it and in the `gc.log` header either way.
#[test]
fn p24_c_the_announcement_never_corrupts_the_json_report() {
    let fx = Fx::new("announce-json");
    let uuid = "cccc0008-0000-0000-0000-000000000008";
    fx.tree(uuid, &[UNSTORED], Ledger::None);
    fx.age_tree(uuid, AGED);

    let out = fx.run(&["gc", "--wipe", "--targets", "scratch", "--commit", "--json"]);
    assert_eq!(out.code, 0, "{}", out.summary());
    let report = out.json();
    assert_eq!(report["deleted"], 1, "{report:#}");
    assert_eq!(
        report["reclaimed_unarchived_bytes"],
        bytes_of(&[UNSTORED]),
        "{report:#}"
    );
    assert!(
        out.stderr.contains("wipe: deleting 1 scratch tree(s)"),
        "the announcement was dropped under --json: {}",
        out.summary()
    );
}

// ---------------------------------------------------------------------------
// D. Flag surface.
// ---------------------------------------------------------------------------

/// `--wipe --full` is refused at parse time rather than resolved to the wider level.
/// The two flags name two predicates, and honouring one of a pair the operator typed
/// is the failure mode this CLI refuses elsewhere. The asymmetry decides it: under a
/// wipe-wins rule, an operator who believed `--full` narrowed the run has just
/// deleted every captured tree in scope.
#[test]
fn p24_d_wipe_and_full_is_a_parse_error() {
    let fx = Fx::new("conflict-full");
    let uuid = "dddd0001-0000-0000-0000-000000000001";
    fx.tree(uuid, &[UNSTORED], Ledger::None);
    fx.age_tree(uuid, AGED);

    let out = fx.run(&["gc", "--wipe", "--full", "--targets", "scratch", "--commit"]);
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
    assert!(
        fx.session_dir(uuid).exists(),
        "a refused parse deleted a tree: {}",
        out.summary()
    );
}

/// Same standard as `--full --discover-all-users`: discovery is read-only and returns
/// before a target is parsed, so the pair can only mislead about what the run did.
#[test]
fn p24_d_wipe_and_discover_all_users_is_a_parse_error() {
    let fx = Fx::new("conflict-discover");
    let out = fx.run(&["gc", "--wipe", "--discover-all-users"]);
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
