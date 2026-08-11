//! P19: `archive` against a scratch **source root** that is not this user's.
//!
//! `gc` has refused foreign roots since 須佐P2 — it will not generate a wipe
//! candidate from a root it cannot prove it owns. `archive` looked at no uid at
//! all, and the default source paths never reach `tmp_root`, so the hole was
//! latent rather than absent: the first caller to walk `tmp_root` makes it real.
//!
//! **The hazard is not disclosure.** `/tmp/claude-<uid>` is mode 700, so a
//! cross-uid read fails EACCES and lands as a skipped source — *unreadable*. It
//! is a **poisoned root**: a `YOMI_TMP_ROOT` pointing at a foreign (or merely
//! attacker-writable) tree makes every path under it archivable, each landing in
//! this user's store under a key derived from a foreign directory name, with the
//! scanner collecting whatever secrets it finds into this user's `quarantine/`.
//!
//! So the load-bearing assertion here is not "nothing was archived" — an empty
//! foreign directory gives that for free. It is that **"I cannot read this" and
//! "this is not yours" reach the operator as different facts**, because they call
//! for different actions: fix a permission, versus fix what `YOMI_TMP_ROOT`
//! points at. A refusal reported as unreadable is a refusal nobody acts on.
//!
//! Fabricating a foreign-owned directory needs root, so these tests borrow paths
//! the host already has — `/var/empty` (root-owned, world-readable, empty) and
//! `/root` (root-owned, mode 700). Everything written lives under
//! `CARGO_TARGET_TMPDIR` and is removed when the fixture drops.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const BIN: &str = env!("CARGO_BIN_EXE_yomi");

/// The refusal under test: the scratch source root is not this user's.
const ROOT_REFUSED: &str = "scratch source root is not owned by this user";
/// The register it must never be conflated with: a source that could not be read.
const UNREADABLE: &str = "skip unreadable source";

fn unique() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn euid() -> u32 {
    static UID: OnceLock<u32> = OnceLock::new();
    *UID.get_or_init(|| {
        let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("p19-uid-{}", unique()));
        std::fs::write(&p, b"").unwrap();
        let uid = std::fs::metadata(&p).unwrap().uid();
        let _ = std::fs::remove_file(&p);
        uid
    })
}

/// Real directories on this host owned by another uid, to stand in for a poisoned
/// `YOMI_TMP_ROOT`. Both shapes matter and are asserted alike: `/var/empty` can be
/// listed and simply has nothing in it, `/root` cannot be listed at all. The
/// second is the one that would come back as a bare `Permission denied` at exit 1
/// if the ownership check sat *after* the first `read_dir` instead of before it.
///
/// `None` only when this process is root: nothing is foreign to uid 0, so there is
/// no guard to exercise and the caller stops. A **non-root** host with no such
/// directory is a different thing and fails loudly — the alternative is a test
/// that passes while verifying nothing.
fn foreign_roots() -> Option<Vec<PathBuf>> {
    let me = euid();
    if me == 0 {
        return None;
    }
    let roots: Vec<PathBuf> = ["/var/empty", "/root"]
        .into_iter()
        .map(PathBuf::from)
        .filter(|p| {
            std::fs::metadata(p)
                .map(|md| md.is_dir() && md.uid() != me)
                .unwrap_or(false)
        })
        .collect();
    assert!(
        !roots.is_empty(),
        "no foreign-owned directory found on this host; nothing here can be proven"
    );
    Some(roots)
}

struct Fx {
    base: PathBuf,
    home: PathBuf,
    yomi_home: PathBuf,
    tmp_root: PathBuf,
    cache_home: PathBuf,
    proc_root: PathBuf,
    slug: String,
    uuid: String,
}

/// The fixture removes its own tree. A `remove_dir_all` placed *before* the
/// fixture is built — the shape elsewhere in this suite — is a no-op that leaves
/// every run's directories behind (issue #48).
impl Drop for Fx {
    fn drop(&mut self) {
        // The unreadable-file cases leave a mode-000 file behind, which its own
        // parent directory cannot unlink until it is readable again.
        for p in walk_dirs(&self.base) {
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

impl Fx {
    fn new(tag: &str) -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "p19-{tag}-{}-{}",
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
            uuid: "aaaa1111-2222-3333-4444-555555555555".to_string(),
            base,
        };
        std::fs::create_dir_all(fx.home.join(".claude/projects").join(&fx.slug)).unwrap();
        for d in [&fx.tmp_root, &fx.cache_home, &fx.proc_root, &fx.yomi_home] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::set_permissions(&fx.yomi_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        fx
    }

    /// A transcript, so `--include transcript` has real work to do and the run can
    /// be shown to have continued past the scratch family.
    fn write_transcript(&self) {
        let p = self
            .home
            .join(".claude/projects")
            .join(&self.slug)
            .join(format!("{}.jsonl", self.uuid));
        std::fs::write(
            &p,
            serde_json::json!({"type": "user", "message": {"role": "user", "content": "hello"}})
                .to_string()
                + "\n",
        )
        .unwrap();
    }

    /// A scratch tree at `<tmp_root>/<slug>/<uuid>/scratchpad/n.md`.
    fn write_tree(&self) {
        let d = self.tmp_root.join(&self.slug).join(&self.uuid);
        std::fs::create_dir_all(d.join("scratchpad")).unwrap();
        std::fs::write(d.join("scratchpad/n.md"), b"scratch payload\n").unwrap();
    }

    fn key(&self) -> String {
        format!("{}--{}", self.slug, self.uuid)
    }

    fn store_root(&self) -> PathBuf {
        self.yomi_home.join("archive/_scratch")
    }

    fn keys(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.store_root())
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }

    fn entry(&self, rel: &str) -> serde_json::Value {
        let p = self.store_root().join(self.key()).join("manifest.json");
        let txt = std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("no manifest at {}: {e}", p.display()));
        let mf: serde_json::Value = serde_json::from_str(&txt).expect("manifest json");
        mf["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .find(|e| e["path"] == rel)
            .unwrap_or_else(|| panic!("no entry for {rel}: {mf:#}"))
            .clone()
    }

    /// Archive with `YOMI_TMP_ROOT` pointed wherever the caller says, which is the
    /// whole point: the poisoned root is an environment value, not a fixture.
    fn archive_with_root(&self, tmp_root: &Path, include: &str) -> Out {
        let o = Command::new(BIN)
            .args(["archive", "--all", "--include", include, "--json"])
            .arg("--home")
            .arg(&self.yomi_home)
            .env("HOME", &self.home)
            .env("YOMI_TMP_ROOT", tmp_root)
            .env("YOMI_CACHE_HOME", &self.cache_home)
            .env("YOMI_PROC_ROOT", &self.proc_root)
            .env_remove("YOMI_HOME")
            .env_remove("YOMI_CLAUDE_HOME")
            .output()
            .expect("run yomi");
        Out {
            code: o.status.code().unwrap(),
            stdout: o.stdout,
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }

    fn archive(&self, include: &str) -> Out {
        self.archive_with_root(&self.tmp_root, include)
    }
}

struct Out {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
}

impl Out {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.stdout)
            .unwrap_or_else(|e| panic!("archive --json unparseable ({e}): {}", self.summary()))
    }
    fn summary(&self) -> String {
        format!(
            "exit={} stdout={:?} stderr={:?}",
            self.code,
            String::from_utf8_lossy(&self.stdout).trim(),
            self.stderr.trim()
        )
    }
}

fn walk_dirs(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                stack.push(e.path());
            }
        }
        out.push(d);
    }
    out
}

// ---------------------------------------------------------------------------
// A. The refusal, and what it is not.
// ---------------------------------------------------------------------------

/// A foreign `tmp_root` archives no scratch, and says so in terms an operator can
/// act on — for a root that lists empty and for one that cannot be listed at all.
///
/// The second case also pins the check's *position*: it runs before the first
/// `read_dir`, so a mode-700 foreign root is refused as foreign rather than
/// escaping as an EACCES from the walk.
#[test]
fn p19_a_foreign_source_root_archives_no_scratch_and_says_why() {
    let Some(roots) = foreign_roots() else {
        return;
    };

    for foreign in roots {
        let fx = Fx::new("foreign");
        fx.write_transcript();
        // A tree under the fixture's own root, which is *not* the root passed to
        // the run: nothing here may be archived either, so a store key of any
        // name is a failure.
        fx.write_tree();

        let out = fx.archive_with_root(&foreign, "transcript,scratch");
        assert_eq!(
            out.code,
            0,
            "a foreign root ended the run for {}: {}",
            foreign.display(),
            out.summary()
        );
        assert!(
            out.stderr.contains(ROOT_REFUSED),
            "the refusal was not reported for {}: {}",
            foreign.display(),
            out.summary()
        );
        assert!(
            !out.stderr.contains(UNREADABLE),
            "a foreign root was reported as an unreadable source for {}: {}",
            foreign.display(),
            out.summary()
        );
        assert!(
            !out.stderr.contains("error:"),
            "the refusal escaped as an error for {}: {}",
            foreign.display(),
            out.summary()
        );
        assert!(
            fx.keys().is_empty(),
            "a foreign root produced store keys {:?} for {}",
            fx.keys(),
            foreign.display()
        );

        // Only the scratch family stopped: the transcript came off `claude_home`
        // and has nothing to do with where `tmp_root` points.
        assert_eq!(
            out.json()["sessions"],
            1,
            "the session sources were dropped along with scratch: {}",
            out.summary()
        );
        assert!(
            out.json()["artifacts_written"].as_u64().unwrap_or(0) >= 1,
            "nothing was archived at all: {}",
            out.summary()
        );
    }
}

/// A `tmp_root` symlinked at a foreign tree is the same refusal. Ownership is read
/// through `metadata`, which follows the link, so the target's real owner decides
/// — a link is not a way to launder a root.
#[test]
fn p19_a_source_root_symlinked_at_a_foreign_tree_is_refused() {
    let Some(foreign) = foreign_roots().and_then(|r| r.into_iter().next()) else {
        return;
    };
    let fx = Fx::new("symlink");
    fx.write_transcript();
    let link = fx.base.join("tmp-link");
    std::os::unix::fs::symlink(&foreign, &link).unwrap();

    let out = fx.archive_with_root(&link, "transcript,scratch");
    assert_eq!(out.code, 0, "{}", out.summary());
    assert!(
        out.stderr.contains(ROOT_REFUSED),
        "a link to a foreign root was accepted: {}",
        out.summary()
    );
    assert!(fx.keys().is_empty(), "keys: {:?}", fx.keys());
}

/// The distinction the whole PR turns on, measured in one place: an unreadable
/// *file* inside a root this user owns is a skipped source and the tree is still
/// archived with the gap recorded, while a foreign *root* archives nothing and
/// says something else. Same command, same fixture shape, two different registers
/// and two different outcomes.
#[test]
fn p19_an_unreadable_source_is_not_a_foreign_root() {
    // Root reads a mode-000 file and owns everything, so neither half of the
    // comparison exists for uid 0.
    let Some(foreign) = foreign_roots().and_then(|r| r.into_iter().next()) else {
        return;
    };

    // Own root, unreadable file.
    let fx = Fx::new("unreadable");
    fx.write_tree();
    let locked = fx
        .tmp_root
        .join(&fx.slug)
        .join(&fx.uuid)
        .join("scratchpad/n.md");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

    let mine = fx.archive("scratch");
    assert_eq!(mine.code, 0, "{}", mine.summary());
    assert!(
        mine.stderr.contains(UNREADABLE),
        "an unreadable source was not reported as one: {}",
        mine.summary()
    );
    assert!(
        !mine.stderr.contains(ROOT_REFUSED),
        "an unreadable file was reported as a foreign root: {}",
        mine.summary()
    );
    assert_eq!(
        fx.keys(),
        vec![fx.key()],
        "an unreadable file cost the tree its store key"
    );
    assert_eq!(
        fx.entry("scratchpad/n.md")["capture_failed"],
        true,
        "the unread file was not recorded as unread"
    );

    // Foreign root: no key at all, and the other register.
    let other = Fx::new("unreadable-foreign");
    other.write_tree();
    let theirs = other.archive_with_root(&foreign, "scratch");
    assert_eq!(theirs.code, 0, "{}", theirs.summary());
    assert!(
        theirs.stderr.contains(ROOT_REFUSED) && !theirs.stderr.contains(UNREADABLE),
        "a foreign root and an unreadable source are not distinguishable: {}",
        theirs.summary()
    );
    assert!(
        other.keys().is_empty(),
        "a foreign root left store keys {:?}",
        other.keys()
    );
}

// ---------------------------------------------------------------------------
// B. What the guard must not break.
// ---------------------------------------------------------------------------

/// Regression: a `tmp_root` this user owns archives exactly as before.
#[test]
fn p19_an_owned_source_root_still_archives_scratch() {
    let fx = Fx::new("owned");
    fx.write_tree();

    let out = fx.archive("scratch");
    assert_eq!(out.code, 0, "{}", out.summary());
    assert!(
        !out.stderr.contains(ROOT_REFUSED),
        "this user's own root was refused: {}",
        out.summary()
    );
    assert_eq!(fx.keys(), vec![fx.key()], "{}", out.summary());
    assert_eq!(fx.entry("scratchpad/n.md")["stored"], true);
}

/// An absent `tmp_root` is success, not a refusal — most hosts do not have one,
/// and `gc` has always treated `NotFound` as benign. A guard that refused it would
/// warn on every run everywhere.
#[test]
fn p19_a_missing_source_root_is_not_a_refusal() {
    let fx = Fx::new("missing");
    fx.write_transcript();
    std::fs::remove_dir_all(&fx.tmp_root).unwrap();

    let out = fx.archive("transcript,scratch");
    assert_eq!(out.code, 0, "{}", out.summary());
    assert!(
        !out.stderr.contains(ROOT_REFUSED),
        "an absent root was reported as foreign: {}",
        out.summary()
    );
    assert!(
        !out.stderr.contains("error:"),
        "an absent root ended the run: {}",
        out.summary()
    );
    assert!(fx.keys().is_empty());
    assert_eq!(out.json()["sessions"], 1, "{}", out.summary());
}
