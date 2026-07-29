//! P8: what a scratch archive records when it *tries* to store a file and the
//! capture fails — a blacklisted inode swapped in after the walk, an I/O or
//! permission error, or a file that outgrew the read bound between stat and read.
//!
//! Two claims are easy to conflate and must not be:
//!
//! * `stored: false` alone — **policy declined** to hoard these bytes (a deny
//!   glob, an over-cap tree). Presence + size is then the intended assurance and
//!   the tree is reclaimable; design §3, decision #4.
//! * `capture_failed: true` — **nothing was read.** No decision was made, so
//!   presence + size assures nothing about content nobody has seen, and the gate
//!   refuses the tree rather than delete a file yomi meant to archive and could
//!   not.
//!
//! The refusal is bounded by the condition that caused it, which is what
//! separates it from the `#9` failure mode: `#9` regenerated an identical broken
//! manifest on every run and no number of cycles helped. Here the first archive
//! that can read the file stores it and the refusal is gone. `p8_capture_failure_
//! clears_when_the_file_becomes_readable` is that proof.
//!
//! Every fixture is fabricated under `CARGO_TARGET_TMPDIR`.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const BIN: &str = env!("CARGO_BIN_EXE_yomi");

fn unique() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// Every test here turns on a file being unreadable, which root ignores.
fn is_root() -> bool {
    static ROOT: OnceLock<bool> = OnceLock::new();
    *ROOT.get_or_init(|| {
        let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("p8-uid-{}", unique()));
        std::fs::write(&p, b"").unwrap();
        let uid = std::fs::metadata(&p).unwrap().uid();
        let _ = std::fs::remove_file(&p);
        uid == 0
    })
}

struct Fx {
    home: PathBuf,
    yomi_home: PathBuf,
    tmp_root: PathBuf,
    cache_home: PathBuf,
    proc_root: PathBuf,
    slug: String,
    uuid: String,
}

impl Fx {
    fn new(tag: &str) -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "p8-{tag}-{}-{}",
            std::process::id(),
            unique()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let fx = Fx {
            home: base.join("home"),
            yomi_home: base.join("yomi"),
            tmp_root: base.join("tmp"),
            cache_home: base.join("cache"),
            proc_root: base.join("proc"),
            slug: "-home-test".to_string(),
            uuid: "aaaa1111-2222-3333-4444-555555555555".to_string(),
        };
        std::fs::create_dir_all(fx.home.join(".claude/projects").join(&fx.slug)).unwrap();
        for d in [&fx.tmp_root, &fx.cache_home, &fx.proc_root, &fx.yomi_home] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::set_permissions(&fx.yomi_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            fx.yomi_home.join("config.toml"),
            "[scratch]\ntotal_cap = \"1MB\"\n",
        )
        .unwrap();
        fx
    }

    fn session_dir(&self) -> PathBuf {
        self.tmp_root.join(&self.slug).join(&self.uuid)
    }

    fn store_dir(&self) -> PathBuf {
        self.yomi_home
            .join("archive/_scratch")
            .join(format!("{}--{}", self.slug, self.uuid))
    }

    fn write(&self, rel: &str, bytes: &[u8]) -> PathBuf {
        let p = self.session_dir().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(BIN)
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
            .expect("run yomi")
    }

    fn archive(&self) {
        let out = self.run(&["archive", "--all", "--include", "scratch"]);
        assert!(
            out.status.success(),
            "archive failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn manifest(&self) -> serde_json::Value {
        let p = self.store_dir().join("manifest.json");
        let txt = std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("no manifest at {}: {e}", p.display()));
        serde_json::from_str(&txt).expect("manifest json")
    }

    fn entry(&self, path: &str) -> serde_json::Value {
        let mf = self.manifest();
        mf["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .find(|e| e["path"] == path)
            .unwrap_or_else(|| panic!("no entry for {path}: {mf:#}"))
            .clone()
    }

    fn stored_zst(&self) -> Vec<String> {
        let root = self.store_dir();
        let mut out = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(p) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&p) else {
                continue;
            };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().and_then(|x| x.to_str()) == Some("zst") {
                    out.push(
                        p.strip_prefix(&root)
                            .unwrap()
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
            }
        }
        out.sort();
        out
    }

    fn age_tree(&self) {
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(200 * 86_400);
        let mut stack = vec![self.session_dir()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    let _ =
                        filetime::set_file_mtime(&p, filetime::FileTime::from_system_time(when));
                }
            }
        }
    }

    /// Every `reason` recorded in `gc.log`, in order.
    fn gc_reasons(&self) -> Vec<String> {
        std::fs::read_to_string(self.yomi_home.join("gc.log"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|v| v["reason"].as_str().map(str::to_string))
            .collect()
    }

    /// Replace this key's store directory with a symlink at `target`, moving the
    /// real store there. The link then points at a **valid** store for this very
    /// tree: if any layer followed it, the evidence it found would authorize the
    /// delete.
    fn relocate_store_behind_symlink(&self, target: &Path) {
        std::fs::rename(self.store_dir(), target).unwrap();
        std::os::unix::fs::symlink(target, self.store_dir()).unwrap();
    }

    fn gc_deleted(&self) -> u64 {
        let out = self.run(&["gc", "--targets", "scratch", "--commit", "--json"]);
        let txt = String::from_utf8_lossy(&out.stdout);
        serde_json::from_str::<serde_json::Value>(txt.trim())
            .unwrap_or_else(|e| panic!("gc --json unparseable ({e}): {txt:?}"))["deleted"]
            .as_u64()
            .expect("deleted")
    }
}

/// Law S against the fixture's own store.
fn assert_law_s(fx: &Fx) {
    let mf = fx.manifest();
    let mut claimed: Vec<String> = mf["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["stored"] == true)
        .map(|e| format!("{}.zst", e["path"].as_str().unwrap()))
        .collect();
    claimed.sort();
    assert_eq!(
        fx.stored_zst(),
        claimed,
        "store law S violated; manifest={mf:#}"
    );
}

/// A file that has never been readable was never captured, so the entry records
/// exactly that: not stored, no hashes, and `capture_failed` to distinguish it
/// from the deliberate non-storage that `stored: false` means on its own.
#[test]
fn p8_uncapturable_file_is_recorded_as_uncaptured_not_as_policy() {
    if is_root() {
        return;
    }
    let fx = Fx::new("uncaptured");
    fx.write("scratchpad/ok.md", b"readable\n");
    let locked = fx.write("scratchpad/locked.md", b"never-read\n");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

    fx.archive();
    let e = fx.entry("scratchpad/locked.md");
    let ok = fx.entry("scratchpad/ok.md");
    let zst = fx.stored_zst();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(e["stored"], false, "an unread file was claimed stored: {e}");
    assert!(
        e["source_sha256"].is_null() && e["content_sha256"].is_null(),
        "hashes appeared for a file that was never read: {e}"
    );
    assert_eq!(
        e["capture_failed"], true,
        "the failure was recorded as a policy decision, which would let the gate \
         accept presence+size as assurance for bytes nobody read: {e}"
    );
    // A file policy simply stored carries no such flag.
    assert!(
        ok.get("capture_failed").is_none(),
        "an ordinary entry gained the flag: {ok}"
    );
    assert_eq!(zst, vec!["scratchpad/ok.md.zst"]);
    assert_law_s(&fx);
}

/// The gate must refuse a tree holding an uncaptured file: deleting it would
/// destroy a source yomi intended to archive and could not, which is the one
/// thing archive-verify-then-delete forbids.
#[test]
fn p8_uncaptured_file_refuses_the_tree() {
    if is_root() {
        return;
    }
    let fx = Fx::new("refuse");
    fx.write("scratchpad/ok.md", b"readable\n");
    let locked = fx.write("scratchpad/locked.md", b"never-read\n");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    fx.archive();
    fx.age_tree();

    let deleted = fx.gc_deleted();
    let survived = fx.session_dir().exists();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(
        deleted, 0,
        "a tree holding an uncaptured file was reclaimed"
    );
    assert!(
        survived,
        "the source of a file that was never archived was deleted"
    );
}

/// **The property the refusal above rests on.** It lasts exactly as long as the
/// condition that caused it — unlike the `#9` mode, where re-archiving rebuilt
/// the identical broken manifest and no number of cycles ever helped. One run
/// that can read the file clears the flag and the tree becomes reclaimable.
#[test]
fn p8_capture_failure_clears_when_the_file_becomes_readable() {
    if is_root() {
        return;
    }
    let fx = Fx::new("clears");
    fx.write("scratchpad/ok.md", b"readable\n");
    let locked = fx.write("scratchpad/locked.md", b"was-locked\n");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

    // Repeated cycles while the condition holds change nothing.
    for _ in 0..3 {
        fx.archive();
        fx.age_tree();
        assert_eq!(fx.gc_deleted(), 0);
    }
    assert_eq!(fx.entry("scratchpad/locked.md")["capture_failed"], true);

    // The condition clears.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
    fx.archive();

    let e = fx.entry("scratchpad/locked.md");
    assert!(
        e.get("capture_failed").is_none(),
        "the flag survived a run that could read the file: {e}"
    );
    assert_eq!(e["stored"], true);
    assert!(e["source_sha256"].is_string() && e["content_sha256"].is_string());
    assert_eq!(
        fx.stored_zst(),
        vec!["scratchpad/locked.md.zst", "scratchpad/ok.md.zst"]
    );
    assert_law_s(&fx);

    fx.age_tree();
    assert_eq!(
        fx.gc_deleted(),
        1,
        "the tree stayed unreclaimable after every file became readable and was \
         archived — the refusal is not bounded by its cause"
    );
    assert!(!fx.session_dir().exists());
}

/// A capture that fails must never discard an earlier one. The `.zst` from the
/// run that could read the file is the last copy of those bytes; dropping the
/// claim would make reconciliation treat it as unclaimed and delete it — losing
/// a good archive over a permission bit.
#[test]
fn p8_capture_failure_keeps_an_earlier_capture() {
    if is_root() {
        return;
    }
    let fx = Fx::new("salvage");
    let a = fx.write("scratchpad/a.md", b"valuable-content\n");
    fx.archive();
    let before = fx.entry("scratchpad/a.md");
    assert_eq!(fx.stored_zst(), vec!["scratchpad/a.md.zst"]);

    std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o000)).unwrap();
    fx.archive();
    let after = fx.entry("scratchpad/a.md");
    let zst = fx.stored_zst();
    let deleted = {
        fx.age_tree();
        fx.gc_deleted()
    };
    std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(
        zst,
        vec!["scratchpad/a.md.zst"],
        "the earlier capture was reconciled away because this run could not read \
         the file"
    );
    assert_eq!(
        after["stored"], true,
        "the surviving archive lost its claim"
    );
    assert_eq!(after["source_sha256"], before["source_sha256"]);
    assert_eq!(after["content_sha256"], before["content_sha256"]);
    assert_eq!(after["capture_failed"], true);
    assert_law_s(&fx);
    assert_eq!(
        deleted, 0,
        "the tree was reclaimed while its live file could not be re-read, so the \
         gate could not have checked the live bytes against the archive"
    );
}

/// A manifest written before `capture_failed` existed must keep its meaning: the
/// field defaults to false, so every entry in it reads as an ordinary one.
#[test]
fn p8_manifest_without_the_field_is_unchanged() {
    let fx = Fx::new("compat");
    fx.write("scratchpad/a.md", b"a\n");
    fx.archive();

    let mf = fx.manifest();
    assert!(
        mf["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e.get("capture_failed").is_none()),
        "an ordinary tree started emitting the flag, so existing manifests are no \
         longer written byte-identically: {mf:#}"
    );
}

/// Salvage rests on the artifact being *there*, not on the prior ledger's word
/// for it. If the `.zst` went out of band, carrying `stored: true` forward would
/// claim an artifact that does not exist — the set-equality half of store law S
/// broken in the other direction.
#[test]
fn p8_salvage_does_not_claim_an_artifact_that_is_gone() {
    if is_root() {
        return;
    }
    let fx = Fx::new("salvage-gone");
    let a = fx.write("scratchpad/a.md", b"content\n");
    fx.archive();
    let zst = fx.store_dir().join("scratchpad/a.md.zst");
    assert!(zst.exists());

    // The artifact disappears by some other hand, and the live file becomes
    // unreadable before the next run can notice.
    std::fs::remove_file(&zst).unwrap();
    std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o000)).unwrap();
    fx.archive();
    let e = fx.entry("scratchpad/a.md");
    std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(
        e["stored"], false,
        "the ledger claims an artifact that is not in the store: {e}"
    );
    assert_eq!(e["capture_failed"], true);
    assert_law_s(&fx);
}

/// Hashes are not required to salvage — a manifest written before D2/R1 carries
/// none while its `.zst` is real and valid — but they must not be *invented*
/// either. A salvaged legacy entry stays hashless, so the gate keeps treating
/// the artifact as unverifiable instead of gaining a claim it cannot check.
#[test]
fn p8_salvaged_legacy_entry_gains_no_hashes_it_cannot_prove() {
    if is_root() {
        return;
    }
    let fx = Fx::new("salvage-legacy");
    let a = fx.write("scratchpad/a.md", b"legacy-content\n");
    fx.archive();

    // Rewrite the ledger into its pre-D2/R1 shape: a real artifact, no hashes.
    let mfp = fx.store_dir().join("manifest.json");
    let mut mf: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&mfp).unwrap()).unwrap();
    for e in mf["entries"].as_array_mut().unwrap() {
        let e = e.as_object_mut().unwrap();
        e.remove("source_sha256");
        e.remove("content_sha256");
    }
    std::fs::write(&mfp, serde_json::to_string_pretty(&mf).unwrap()).unwrap();
    let artifact = std::fs::read(fx.store_dir().join("scratchpad/a.md.zst")).unwrap();

    std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o000)).unwrap();
    fx.archive();
    let e = fx.entry("scratchpad/a.md");
    std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(e["stored"], true, "a real archive was forfeited: {e}");
    assert!(
        e["source_sha256"].is_null() && e["content_sha256"].is_null(),
        "hashes were invented for bytes this run never read: {e}"
    );
    assert_eq!(e["capture_failed"], true);
    assert_eq!(
        std::fs::read(fx.store_dir().join("scratchpad/a.md.zst")).unwrap(),
        artifact,
        "the artifact was rewritten by a run that captured nothing"
    );
    assert_law_s(&fx);
}

/// A symlinked store directory is **refused, not repaired**. The lock file's
/// symlink is self-healed because it holds nothing; a store directory holds
/// archived data, and the link may be an operator who deliberately put the store
/// on another volume — replacing it would orphan that store and start an empty
/// one. Refusing is reversible by hand; replacing is not.
#[test]
fn p8_symlinked_store_dir_is_refused_and_left_intact() {
    let fx = Fx::new("symlink-store");
    fx.write("scratchpad/n.md", b"content\n");
    let outside = fx.yomi_home.parent().unwrap().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("precious.txt"), b"UNRELATED\n").unwrap();

    std::fs::create_dir_all(fx.yomi_home.join("archive/_scratch")).unwrap();
    std::os::unix::fs::symlink(&outside, fx.store_dir()).unwrap();

    // The run must still succeed: one refused key is not a failed archive.
    fx.archive();

    let leaked: Vec<String> = std::fs::read_dir(&outside)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "precious.txt")
        .collect();
    assert!(
        leaked.is_empty(),
        "archive wrote {leaked:?} outside the archive tree through a symlinked \
         store directory"
    );
    assert!(
        std::fs::symlink_metadata(fx.store_dir())
            .unwrap()
            .file_type()
            .is_symlink(),
        "the store directory symlink was replaced rather than refused; a link \
         that points at a deliberately relocated store must survive untouched"
    );
}

/// Every regular file under `root`, as (relative path, bytes), plus `root`'s own
/// mode — a total snapshot, so "nothing changed" can be asserted as one fact.
fn snapshot(root: &Path) -> (Vec<(String, Vec<u8>)>, u32) {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&p) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push((
                    p.strip_prefix(root).unwrap().to_string_lossy().into_owned(),
                    std::fs::read(&p).unwrap_or_default(),
                ));
            }
        }
    }
    out.sort();
    let mode = std::fs::metadata(root).unwrap().permissions().mode() & 0o777;
    (out, mode)
}

/// The GC gate's stake in a foreign store directory is the largest of the three
/// layers, because its output is a deletion. The link here points at a *valid*
/// store for this very tree, so a gate that followed it would find complete
/// coverage and delete — destroying the live tree on the strength of evidence
/// from outside the archive tree.
#[test]
fn p8_gate_refuses_a_store_dir_it_does_not_own() {
    let fx = Fx::new("gate-foreign");
    fx.write("scratchpad/a.md", b"content\n");
    fx.archive();
    assert_eq!(fx.stored_zst(), vec!["scratchpad/a.md.zst"]);

    let outside = fx.yomi_home.parent().unwrap().join("relocated-store");
    fx.relocate_store_behind_symlink(&outside);
    fx.age_tree();

    let deleted = fx.gc_deleted();
    assert_eq!(
        deleted, 0,
        "the gate followed a symlinked store directory and authorized a delete on \
         evidence from outside the archive tree"
    );
    assert!(
        fx.session_dir().exists(),
        "the live tree was destroyed on foreign evidence"
    );
    let reasons = fx.gc_reasons();
    assert!(
        reasons.iter().any(|r| r == "ForeignStoreDir"),
        "the refusal was recorded under the wrong reason; an operator cannot tell \
         'never archived' from 'your store path was replaced'. gc.log: {reasons:?}"
    );
}

/// The three layers must reach the *same* verdict on the same path. Writer,
/// reconciler and gate all go through `classify_store_dir`, so a full
/// archive + gc cycle leaves a foreign store byte-for-byte untouched: nothing
/// written into it, nothing pruned from it, its mode unchanged, and the link
/// itself still in place.
#[test]
fn p8_all_three_layers_refuse_the_same_store_dir() {
    let fx = Fx::new("three-layers");
    fx.write("scratchpad/a.md", b"content\n");
    fx.write("scratchpad/b.md", b"more\n");
    fx.archive();

    let outside = fx.yomi_home.parent().unwrap().join("relocated-store");
    fx.relocate_store_behind_symlink(&outside);
    // A `.zst` the manifest does not claim: bait for the reconciler, which would
    // prune it as an orphan if it walked through the link.
    std::fs::write(outside.join("scratchpad/orphan.md.zst"), b"not claimed\n").unwrap();
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755)).unwrap();
    let before = snapshot(&outside);

    // Writer + reconciler.
    fx.archive();
    // Gate.
    fx.age_tree();
    assert_eq!(fx.gc_deleted(), 0);

    assert_eq!(
        snapshot(&outside),
        before,
        "a foreign store directory was written to, pruned, or re-moded by an \
         archive + gc cycle; the three layers do not agree on what a store is"
    );
    assert!(
        std::fs::symlink_metadata(fx.store_dir())
            .unwrap()
            .file_type()
            .is_symlink(),
        "the link was replaced rather than refused"
    );
    assert!(fx.session_dir().exists(), "the live tree was reclaimed");
}

/// A store path that is a regular file is as foreign as a symlink. It used to
/// reach `create_dir_all`, whose error aborted the whole archive run.
#[test]
fn p8_store_path_that_is_a_file_refuses_without_failing_the_run() {
    let fx = Fx::new("store-is-file");
    fx.write("scratchpad/a.md", b"content\n");
    std::fs::create_dir_all(fx.yomi_home.join("archive/_scratch")).unwrap();
    std::fs::write(fx.store_dir(), b"not a directory\n").unwrap();

    // The run must still succeed: one refused key is not a failed archive.
    fx.archive();

    assert_eq!(
        std::fs::read(fx.store_dir()).unwrap(),
        b"not a directory\n",
        "the blocking file was overwritten"
    );
    fx.age_tree();
    assert_eq!(fx.gc_deleted(), 0);
    assert!(fx.session_dir().exists());
}

/// Filler with no secret shape, sized to match the archived content byte for
/// byte. The attack needs the sizes equal — a size mismatch is refused before
/// any read, so an unequal fixture would prove nothing.
const DECOY: &[u8] = b"xxxxxxxxxxxxxxxx\n";
/// Same length as [`DECOY`].
const ARCHIVED: &[u8] = b"ordinary-content\n";

impl Fx {
    /// Put a denylisted inode at `~/.claude/.credentials.json` and hardlink it
    /// over `rel`, so the name still resolves but the inode is one §4 forbids
    /// opening for read or delete.
    fn hardlink_denied_inode_over(&self, rel: &str) -> PathBuf {
        let claude = self.home.join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        let denied = claude.join(".credentials.json");
        std::fs::write(&denied, DECOY).unwrap();
        let victim = self.session_dir().join(rel);
        std::fs::remove_file(&victim).unwrap();
        std::fs::hard_link(&denied, &victim).unwrap();
        denied
    }
}

/// **The reason string is the proof.** `Blacklisted` can only come from the
/// guard, which refuses on the *opened fd's* inode before a byte is read;
/// `ShaMismatch` can only come from having read the file and hashed it. With the
/// sizes matched, an unguarded re-hash reaches the read and reports
/// `ShaMismatch` — that is the defect, and this is how it is observed from
/// outside the process.
#[test]
fn p8_gate_refuses_a_denied_inode_before_reading_it() {
    let fx = Fx::new("gate-denied-live");
    fx.write("scratchpad/a.md", ARCHIVED);
    fx.archive();
    assert_eq!(fx.entry("scratchpad/a.md")["bytes"], ARCHIVED.len());

    let denied = fx.hardlink_denied_inode_over("scratchpad/a.md");
    fx.age_tree();
    assert_eq!(
        fx.gc_deleted(),
        0,
        "a tree holding a denied inode was reclaimed"
    );

    let reasons = fx.gc_reasons();
    assert!(
        reasons.iter().any(|r| r == "Blacklisted"),
        "the gate did not refuse by inode. A reason of `ShaMismatch` means the \
         denied file was opened by name and its bytes were read into this process \
         before the hash disagreed — the one read in yomi that skipped the \
         denylist. gc.log: {reasons:?}"
    );
    assert!(
        !reasons.iter().any(|r| r == "ShaMismatch"),
        "the tree was refused only after hashing the denied file's bytes: \
         {reasons:?}"
    );
    assert_eq!(std::fs::read(&denied).unwrap(), DECOY);
}

/// The same read, reached the way **U2 made permanent**. Before retention, a
/// denylisted name had no manifest entry to match: the writer skipped it and the
/// lookup refused first, so the unguarded read was reachable only inside the race
/// between the two checks. A retained entry keeps matching a name whose inode has
/// since been swapped, every run, forever.
#[test]
fn p8_gate_refuses_a_denied_inode_matching_a_retained_entry() {
    let fx = Fx::new("gate-denied-retained");
    fx.write("scratchpad/a.md", ARCHIVED);
    fx.archive();

    let denied = fx.hardlink_denied_inode_over("scratchpad/a.md");
    // This run's candidate loop skips the denied path, so the prior entry is
    // *retained* — present: false, hashes intact, artifact kept.
    fx.archive();
    let e = fx.entry("scratchpad/a.md");
    assert_eq!(
        e["present"], false,
        "fixture did not produce a retained entry: {e}"
    );
    assert_eq!(
        e["bytes"],
        ARCHIVED.len(),
        "retained size must match the decoy"
    );

    fx.age_tree();
    assert_eq!(fx.gc_deleted(), 0);
    let reasons = fx.gc_reasons();
    assert!(
        reasons.iter().any(|r| r == "Blacklisted"),
        "a retained entry let the gate open and read a denied inode. gc.log: \
         {reasons:?}"
    );
    assert_eq!(std::fs::read(&denied).unwrap(), DECOY);
    assert!(
        fx.stored_zst().iter().any(|p| p.ends_with("a.md.zst")),
        "the archive of the displaced file was destroyed"
    );
}

/// The guard must not blunt the check it wraps: same size, different bytes, no
/// denylist involved — the streaming re-hash still has to catch the drift.
#[test]
fn p8_guarded_rehash_still_detects_same_size_drift() {
    let fx = Fx::new("rehash-drift");
    fx.write("scratchpad/a.md", ARCHIVED);
    fx.archive();

    fx.write("scratchpad/a.md", DECOY); // same length, other bytes
    fx.age_tree();
    assert_eq!(fx.gc_deleted(), 0, "a drifted tree was reclaimed");
    assert!(
        fx.gc_reasons().iter().any(|r| r == "ShaMismatch"),
        "the re-hash stopped detecting content drift: {:?}",
        fx.gc_reasons()
    );
}
