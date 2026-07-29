//! P9: `yomi verify`'s scratch pass — store law S in three vocabularies.
//!
//! The pass exists because scratch writes no catalog row: `verify_rows()` cannot
//! reach it, and mirroring scratch into the catalog to give `verify` something to
//! iterate would create a third ledger able to drift from both the manifest and
//! the store. The pass attests to the ledger the delete gate actually consumes.
//!
//! The whole point of this file is the **separation of the three vocabularies**
//! (design §3/§5):
//!
//! * `violation` — S1 broken, or S2 broken where S2 applies. **Exit 2.**
//! * `unverifiable` — S2 inapplicable (no `content_sha256`), or an identity that
//!   does not decode. A statement about what the ledger can prove. **Not exit 2.**
//! * `foreign matter` — a `*.zst` that is not a regular file, which archive will
//!   neither claim nor remove. **Not exit 2.**
//!
//! An entry with `stored: true` and no hashes is a real population — every
//! manifest written before D2/R1 looks like that — so a pass that reads S as one
//! claim fails on every legacy store on every run, and a verify that fails
//! nightly is a verify that gets ignored.
//!
//! Every fixture is fabricated under `CARGO_TARGET_TMPDIR`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_yomi");

/// Distinctive stored content, used to prove the pass emits none of what it reads.
const PAYLOAD: &str = "SCRATCH-PAYLOAD-MUST-NOT-BE-ECHOED";

fn unique() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// Root ignores the mode bits one test below depends on.
fn is_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    static ROOT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ROOT.get_or_init(|| {
        let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("p9-uid-{}", unique()));
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
            "p9-{tag}-{}-{}",
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

    /// A tree with one stored file and one the default deny globs reject.
    fn seeded(tag: &str) -> Self {
        let fx = Fx::new(tag);
        fx.write("scratchpad/a.md", format!("{PAYLOAD}\n").as_bytes());
        fx.write("scratchpad/blob.bin", b"denied junk\n");
        fx.archive();
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

    fn write(&self, rel: &str, bytes: &[u8]) {
        let p = self.session_dir().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
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

    /// `verify --all --json`, returning `(exit code, the `scratch` object)`.
    fn verify(&self) -> (i32, serde_json::Value) {
        self.verify_args(&["verify", "--all", "--json"])
    }

    fn verify_args(&self, args: &[&str]) -> (i32, serde_json::Value) {
        let out = self.run(args);
        let txt = String::from_utf8_lossy(&out.stdout);
        let v: serde_json::Value = serde_json::from_str(txt.trim()).unwrap_or_else(|e| {
            panic!(
                "verify --json unparseable ({e}): stdout={txt:?} stderr={:?}",
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code().unwrap(), v["scratch"].clone())
    }

    fn manifest_path(&self) -> PathBuf {
        self.store_dir().join("manifest.json")
    }

    fn read_manifest(&self) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(self.manifest_path()).unwrap()).unwrap()
    }

    fn write_manifest(&self, mf: &serde_json::Value) {
        std::fs::write(
            self.manifest_path(),
            serde_json::to_string_pretty(mf).unwrap(),
        )
        .unwrap();
    }

    /// Rewrite the entry for `rel` through `f`.
    fn edit_entry(&self, rel: &str, f: impl Fn(&mut serde_json::Map<String, serde_json::Value>)) {
        let mut mf = self.read_manifest();
        for e in mf["entries"].as_array_mut().unwrap() {
            if e["path"] == rel {
                f(e.as_object_mut().unwrap());
            }
        }
        self.write_manifest(&mf);
    }
}

/// The `issue` strings in one class of the report.
fn issues(scratch: &serde_json::Value, class: &str) -> Vec<String> {
    scratch[class]
        .as_array()
        .unwrap_or_else(|| panic!("no `{class}` array in {scratch:#}"))
        .iter()
        .map(|f| f["issue"].as_str().unwrap().to_string())
        .collect()
}

fn assert_clean_except(scratch: &serde_json::Value, class: &str) {
    for other in ["violations", "unverifiable", "foreign_matter", "refused"] {
        if other != class {
            assert!(
                issues(scratch, other).is_empty(),
                "unexpected `{other}` findings alongside `{class}`: {scratch:#}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// A. The clean and the empty cases.
// ---------------------------------------------------------------------------

/// A store archive just wrote satisfies S in both halves.
#[test]
fn p9_clean_store_passes() {
    let fx = Fx::seeded("clean");
    let (code, s) = fx.verify();
    assert_eq!(code, 0, "a clean store failed verify: {s:#}");
    assert_eq!(s["keys"], 1);
    assert_eq!(
        s["verified"], 1,
        "the stored artifact was not checked: {s:#}"
    );
    for class in ["violations", "unverifiable", "foreign_matter", "refused"] {
        assert!(issues(&s, class).is_empty(), "{class}: {s:#}");
    }
}

/// A home that has never archived scratch has nothing to attest to — and the
/// read-side command must not create the store to find that out (W1/R8).
#[test]
fn p9_absent_scratch_root_is_zero_findings_and_exit_zero() {
    let fx = Fx::new("absent");
    let (code, s) = fx.verify();
    assert_eq!(code, 0);
    assert_eq!(s["keys"], 0);
    assert_eq!(s["verified"], 0);
    for class in ["violations", "unverifiable", "foreign_matter", "refused"] {
        assert!(issues(&s, class).is_empty(), "{class}: {s:#}");
    }
    assert!(
        !fx.yomi_home.join("archive/_scratch").exists(),
        "a read-only command created the scratch store root"
    );
}

/// A uuid scopes the pass to the one store dir carrying it.
#[test]
fn p9_session_argument_scopes_the_pass() {
    let fx = Fx::seeded("scope");
    let (code, s) = fx.verify_args(&["verify", &fx.uuid, "--json"]);
    assert_eq!(code, 0);
    assert_eq!(
        s["keys"], 1,
        "the session's own store was not selected: {s:#}"
    );

    let (code, s) = fx.verify_args(&["verify", "ffffffff-0000-0000-0000-000000000000", "--json"]);
    assert_eq!(code, 0);
    assert_eq!(s["keys"], 0, "an unrelated uuid selected a store: {s:#}");
}

// ---------------------------------------------------------------------------
// B. violations — defects of the store. Exit 2.
// ---------------------------------------------------------------------------

/// S2 where it applies: the artifact must decompress to its `content_sha256`.
#[test]
fn p9_corrupt_artifact_is_a_violation() {
    let fx = Fx::seeded("corrupt");
    std::fs::write(fx.store_dir().join("scratchpad/a.md.zst"), b"not zstd").unwrap();

    let (code, s) = fx.verify();
    assert_eq!(issues(&s, "violations"), vec!["ContentMismatch"], "{s:#}");
    assert_clean_except(&s, "violations");
    assert_eq!(code, 2, "a corrupt artifact did not fail the run");
}

/// S1: a regular-file `*.zst` no `stored: true` entry claims. Catches drift from
/// outside the tool.
#[test]
fn p9_orphan_artifact_is_a_violation() {
    let fx = Fx::seeded("orphan");
    let ghost = fx.store_dir().join("scratchpad/ghost.md.zst");
    std::fs::write(&ghost, b"unclaimed").unwrap();

    let (code, s) = fx.verify();
    assert_eq!(issues(&s, "violations"), vec!["OrphanArtifact"], "{s:#}");
    assert_eq!(code, 2);
    assert!(
        s["violations"][0]["rel"] == "scratchpad/ghost.md.zst",
        "the orphan was not named: {s:#}"
    );
}

/// S1 in the other direction: the ledger disclaims bytes the store holds.
#[test]
fn p9_zst_under_a_not_stored_entry_is_a_violation() {
    let fx = Fx::seeded("unclaimed");
    // `blob.bin` is deny-listed, so its entry is `stored: false`.
    assert_eq!(
        fx.read_manifest()["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["path"] == "scratchpad/blob.bin")
            .unwrap()["stored"],
        false
    );
    std::fs::write(fx.store_dir().join("scratchpad/blob.bin.zst"), b"x").unwrap();

    let (code, s) = fx.verify();
    assert_eq!(issues(&s, "violations"), vec!["UnclaimedArtifact"], "{s:#}");
    assert_eq!(code, 2);
}

/// S1: a `stored: true` entry with no regular-file artifact behind it.
#[test]
fn p9_missing_artifact_is_a_violation() {
    let fx = Fx::seeded("missing");
    std::fs::remove_file(fx.store_dir().join("scratchpad/a.md.zst")).unwrap();

    let (code, s) = fx.verify();
    assert_eq!(issues(&s, "violations"), vec!["MissingArtifact"], "{s:#}");
    assert_eq!(code, 2);
}

/// The two manifest-level failures stay distinct: the gate would refuse the tree
/// either way, and `verify` is the thing that says which.
#[test]
fn p9_manifest_absent_and_unreadable_are_distinct_violations() {
    let fx = Fx::seeded("nomanifest");
    std::fs::remove_file(fx.manifest_path()).unwrap();
    let (code, s) = fx.verify();
    assert_eq!(issues(&s, "violations"), vec!["NoManifest"], "{s:#}");
    assert_eq!(code, 2);

    let fx = Fx::seeded("badmanifest");
    std::fs::write(fx.manifest_path(), b"{ not json").unwrap();
    let (code, s) = fx.verify();
    assert_eq!(
        issues(&s, "violations"),
        vec!["UnreadableManifest"],
        "{s:#}"
    );
    assert_eq!(code, 2);
}

// ---------------------------------------------------------------------------
// C. unverifiable — what the ledger cannot prove. **Not** exit 2.
// ---------------------------------------------------------------------------

/// **The core of this unit.** `stored: true` with no `content_sha256` is not a
/// broken store: S2 simply does not apply. Reading S as one claim would report a
/// violation here on every run.
#[test]
fn p9_missing_content_hash_is_unverifiable_not_a_violation() {
    let fx = Fx::seeded("nohash");
    fx.edit_entry("scratchpad/a.md", |e| {
        e.remove("content_sha256");
    });

    let (code, s) = fx.verify();
    assert_eq!(issues(&s, "unverifiable"), vec!["NoContentHash"], "{s:#}");
    assert_clean_except(&s, "unverifiable");
    assert_eq!(
        code, 0,
        "an entry S2 cannot speak about failed the run; a legacy store would fail \
         every night and the verify would be ignored: {s:#}"
    );
    assert_eq!(
        s["verified"], 0,
        "an unhashed artifact was counted verified"
    );
}

/// A whole pre-D2/R1 manifest — `stored: true`, both hashes absent, artifacts
/// real and valid. Such stores exist; they are not broken.
#[test]
fn p9_legacy_store_without_hashes_exits_zero() {
    let fx = Fx::seeded("legacy");
    let mut mf = fx.read_manifest();
    for e in mf["entries"].as_array_mut().unwrap() {
        let e = e.as_object_mut().unwrap();
        e.remove("source_sha256");
        e.remove("content_sha256");
    }
    fx.write_manifest(&mf);

    let (code, s) = fx.verify();
    assert_eq!(code, 0, "a legacy store failed verify: {s:#}");
    assert_eq!(issues(&s, "unverifiable"), vec!["NoContentHash"], "{s:#}");
    assert!(issues(&s, "violations").is_empty(), "{s:#}");
}

// ---------------------------------------------------------------------------
// D. foreign matter — only an operator can clear it. **Not** exit 2.
// ---------------------------------------------------------------------------

/// S1's left side is regular files only, because reconciliation deliberately
/// will not remove anything else. Calling a symlink an S1 violation would be
/// calling something a violation that archive cannot repair.
#[test]
fn p9_non_regular_zst_is_foreign_matter_not_a_violation() {
    let fx = Fx::seeded("foreignzst");
    std::os::unix::fs::symlink(
        fx.store_dir().join("scratchpad/a.md.zst"),
        fx.store_dir().join("scratchpad/link.md.zst"),
    )
    .unwrap();

    let (code, s) = fx.verify();
    assert_eq!(
        issues(&s, "foreign_matter"),
        vec!["ForeignArtifact"],
        "{s:#}"
    );
    assert_clean_except(&s, "foreign_matter");
    assert_eq!(
        code, 0,
        "an object archive can neither claim nor remove failed the run: {s:#}"
    );
}

// ---------------------------------------------------------------------------
// E. refused keys — the ledger could not be trusted to be read. Exit 2.
// ---------------------------------------------------------------------------

/// The pass classifies the store dir before opening anything under it. A foreign
/// ledger must not be read at all, so nothing below is attempted.
#[test]
fn p9_foreign_store_dir_is_a_refused_key() {
    let fx = Fx::seeded("foreigndir");
    let outside = fx.yomi_home.parent().unwrap().join("relocated");
    std::fs::rename(fx.store_dir(), &outside).unwrap();
    std::os::unix::fs::symlink(&outside, fx.store_dir()).unwrap();

    let (code, s) = fx.verify();
    assert_eq!(issues(&s, "refused"), vec!["ForeignStoreDir"], "{s:#}");
    assert_clean_except(&s, "refused");
    assert_eq!(code, 2, "a refused key did not fail the run");
    assert_eq!(
        s["verified"], 0,
        "artifacts behind a foreign store dir were verified: {s:#}"
    );
}

/// An entry whose identity does not decode disables reconciliation for the whole
/// key, permanently, until an operator repairs it — so `verify` names the key.
/// The entry itself is untestable against either half of S.
#[test]
fn p9_undecodable_entry_names_the_key_and_the_entry() {
    let fx = Fx::seeded("undecodable");
    fx.edit_entry("scratchpad/a.md", |e| {
        e.insert("path_hex".into(), serde_json::Value::String("zz".into()));
    });

    let (code, s) = fx.verify();
    assert_eq!(issues(&s, "refused"), vec!["UnreconcilableKey"], "{s:#}");
    assert_eq!(
        issues(&s, "unverifiable"),
        vec!["UndecodableEntry"],
        "{s:#}"
    );
    assert_eq!(
        code, 2,
        "a key that can never reconcile again passed verify: {s:#}"
    );
    // The entry is named, and the key-level finding is not.
    assert_eq!(s["unverifiable"][0]["rel"], "scratchpad/a.md");
    assert_eq!(s["refused"][0]["rel"], "");
}

// ---------------------------------------------------------------------------
// F. The properties that hold across all of the above.
// ---------------------------------------------------------------------------

/// `unverifiable` and `foreign matter` together, on one store, still exit 0 —
/// while a single violation beside them flips it. This is the exit-code rule
/// stated as one test rather than inferred from the cases above.
#[test]
fn p9_unverifiable_and_foreign_matter_never_colour_the_exit_code() {
    let fx = Fx::seeded("mixed");
    fx.edit_entry("scratchpad/a.md", |e| {
        e.remove("content_sha256");
    });
    std::os::unix::fs::symlink(
        fx.store_dir().join("scratchpad/a.md.zst"),
        fx.store_dir().join("scratchpad/link.md.zst"),
    )
    .unwrap();

    let (code, s) = fx.verify();
    assert_eq!(issues(&s, "unverifiable"), vec!["NoContentHash"]);
    assert_eq!(issues(&s, "foreign_matter"), vec!["ForeignArtifact"]);
    assert!(issues(&s, "violations").is_empty());
    assert_eq!(code, 0, "two non-defects summed to a failure: {s:#}");

    // One real defect beside them does flip it.
    std::fs::write(fx.store_dir().join("scratchpad/ghost.md.zst"), b"x").unwrap();
    let (code, s) = fx.verify();
    assert_eq!(issues(&s, "violations"), vec!["OrphanArtifact"]);
    assert_eq!(issues(&s, "unverifiable"), vec!["NoContentHash"]);
    assert_eq!(issues(&s, "foreign_matter"), vec!["ForeignArtifact"]);
    assert_eq!(
        code, 2,
        "a violation beside non-defects did not fail: {s:#}"
    );
}

/// Redaction non-exposure is structural: the pass reads `manifest.json` and the
/// store's own `*.zst` and nothing else, and it emits identities and issue names
/// — never content. Decompressed bytes are hashed and dropped.
#[test]
fn p9_pass_never_emits_what_it_read() {
    let fx = Fx::seeded("nonexposure");
    // Force every path that touches stored bytes: one artifact verified, one
    // mismatching, one orphan read as a candidate.
    std::fs::write(
        fx.store_dir().join("scratchpad/ghost.md.zst"),
        format!("{PAYLOAD}-ORPHAN\n"),
    )
    .unwrap();

    for args in [&["verify", "--all", "--json"][..], &["verify", "--all"][..]] {
        let out = fx.run(args);
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !all.contains(PAYLOAD),
            "verify echoed stored content back to the operator ({args:?}): {all}"
        );
    }
}

/// The three vocabularies must be legible in the human output too, not only in
/// `--json`.
#[test]
fn p9_text_output_names_the_class_of_every_finding() {
    let fx = Fx::seeded("text");
    std::fs::write(fx.store_dir().join("scratchpad/ghost.md.zst"), b"x").unwrap();
    fx.edit_entry("scratchpad/a.md", |e| {
        e.remove("content_sha256");
    });

    let out = fx.run(&["verify", "--all"]);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(text.contains("Scratch: 1 store dirs"), "{text}");
    assert!(text.contains("VIOLATIONS (1)"), "{text}");
    assert!(text.contains("OrphanArtifact"), "{text}");
    assert!(text.contains("unverifiable (1)"), "{text}");
    assert!(text.contains("NoContentHash"), "{text}");
}

// ---------------------------------------------------------------------------
// G. Exclusion — verify can confirm without the lock, but it cannot accuse.
// ---------------------------------------------------------------------------

/// Holding the write lock out-of-process is exactly the condition a concurrent
/// `archive` creates, without needing a race to produce it.
fn with_lock_held<T>(fx: &Fx, f: impl FnOnce() -> T) -> T {
    let lock = yomi::lock::WriteLock::acquire(&fx.yomi_home.join(".yomi.lock"))
        .expect("hold the write lock");
    let out = f();
    drop(lock);
    out
}

/// Without exclusion the pair (manifest, store) is not a consistent snapshot, so
/// a finding that compares one against the other cannot stand. `archive` writes
/// artifacts *before* the manifest and reconciles *after* it, so the states these
/// findings describe are ones a healthy archive passes through by design.
#[test]
fn p9_comparative_findings_downgrade_without_exclusion() {
    let fx = Fx::seeded("noexcl");
    std::fs::write(fx.store_dir().join("scratchpad/ghost.md.zst"), b"x").unwrap();

    // Exclusive: the accusation stands.
    let (code, s) = fx.verify();
    assert_eq!(s["exclusive"], true, "{s:#}");
    assert_eq!(issues(&s, "violations"), vec!["OrphanArtifact"]);
    assert_eq!(code, 2);

    // Not exclusive: same finding, same name, different class, and no failure.
    let (code, s) = with_lock_held(&fx, || fx.verify());
    assert_eq!(s["exclusive"], false, "{s:#}");
    assert!(
        issues(&s, "violations").is_empty(),
        "an accusation stood on a store that was not a consistent snapshot: {s:#}"
    );
    assert_eq!(issues(&s, "unverifiable"), vec!["OrphanArtifact"], "{s:#}");
    assert_eq!(
        s["unverifiable"][0]["class"], "unverifiable",
        "the issue name must survive the downgrade, only the class moves: {s:#}"
    );
    assert_eq!(
        code, 0,
        "a downgraded finding failed the run; an overlapping cron would exit 2 \
         nightly with no defect present: {s:#}"
    );
}

/// Positives survive the downgrade. An artifact that hashes to its entry's
/// `content_sha256` is a true statement about that pair even if both change a
/// moment later — so the pass still confirms, it merely stops accusing.
#[test]
fn p9_verified_count_is_sound_without_exclusion() {
    let fx = Fx::seeded("noexcl-pos");
    let (_, s) = with_lock_held(&fx, || fx.verify());
    assert_eq!(s["exclusive"], false);
    assert_eq!(s["verified"], 1, "the pass stopped confirming: {s:#}");
    assert_eq!(s["keys"], 1);
}

/// Findings that rest on a single atomically-replaced object, or on the store
/// path's classification, are not comparisons — they stand without the lock, and
/// they still fail the run.
#[test]
fn p9_non_comparative_findings_stand_without_exclusion() {
    let fx = Fx::seeded("noexcl-stand");
    std::fs::write(fx.manifest_path(), b"{ not json").unwrap();

    let (code, s) = with_lock_held(&fx, || fx.verify());
    assert_eq!(s["exclusive"], false, "{s:#}");
    assert_eq!(
        issues(&s, "violations"),
        vec!["UnreadableManifest"],
        "{s:#}"
    );
    assert_eq!(
        code, 2,
        "a finding that needs no snapshot stopped failing the run: {s:#}"
    );
}

/// The human output must say why the accusations are missing, or a downgraded
/// run is indistinguishable from a clean one.
#[test]
fn p9_text_output_says_when_it_was_not_exclusive() {
    let fx = Fx::seeded("noexcl-text");
    let out = with_lock_held(&fx, || fx.run(&["verify", "--all"]));
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(text.contains("not exclusive"), "{text}");
}

// ---------------------------------------------------------------------------
// H. The store root is a store path too.
// ---------------------------------------------------------------------------

/// `classify_store_dir` guards each key, but every key is resolved *through* the
/// root — so a foreign root makes every key foreign while each still classifies
/// `Own` on its own. All three layers that touch a scratch store must apply the
/// rule at both levels.
#[test]
fn p9_foreign_scratch_root_is_refused_by_every_layer() {
    let fx = Fx::seeded("symroot");
    let foreign = fx.yomi_home.parent().unwrap().join("foreign_scratch");
    let root = fx.yomi_home.join("archive/_scratch");
    std::fs::rename(&root, &foreign).unwrap();
    std::os::unix::fs::symlink(&foreign, &root).unwrap();
    let before = std::fs::read_dir(&foreign).unwrap().count();

    // verify: refused, and nothing is drawn from the foreign ledger.
    let (code, s) = fx.verify();
    assert_eq!(issues(&s, "refused"), vec!["ForeignStoreDir"], "{s:#}");
    assert_eq!(s["refused"][0]["key"], "_scratch", "{s:#}");
    assert_eq!(code, 2);
    assert!(issues(&s, "violations").is_empty(), "{s:#}");
    assert_eq!(
        s["verified"], 0,
        "artifacts behind a foreign root were read: {s:#}"
    );

    // archive: writes nothing through it, and leaves the link in place.
    fx.write("scratchpad/new.md", b"new\n");
    fx.archive();
    assert_eq!(
        std::fs::read_dir(&foreign).unwrap().count(),
        before,
        "archive wrote through a symlinked scratch root"
    );
    assert!(
        std::fs::symlink_metadata(&root)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the root link was replaced rather than refused"
    );

    // gc: the tree is not reclaimed on evidence from outside the archive tree.
    let when = std::time::SystemTime::now() - std::time::Duration::from_secs(200 * 86_400);
    for p in [
        fx.session_dir().join("scratchpad/a.md"),
        fx.session_dir().join("scratchpad/blob.bin"),
        fx.session_dir().join("scratchpad/new.md"),
    ] {
        let _ = filetime::set_file_mtime(&p, filetime::FileTime::from_system_time(when));
    }
    let out = fx.run(&["gc", "--targets", "scratch", "--commit", "--json"]);
    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap();
    assert_eq!(
        v["deleted"], 0,
        "gc deleted a tree through a foreign root: {v:#}"
    );
    assert!(fx.session_dir().exists());
}

// ---------------------------------------------------------------------------
// I. Containment and CLI shape.
// ---------------------------------------------------------------------------

/// The two passes attest to different ledgers and neither is a precondition of
/// the other, so a scratch root that will not enumerate is a refusal of *that*
/// pass — the catalog results must still be emitted.
#[test]
fn p9_unreadable_scratch_root_refuses_that_pass_only() {
    if is_root() {
        return;
    }
    let fx = Fx::seeded("unreadableroot");
    // A transcript too, so the catalog pass has something real to report.
    let sess = fx.home.join(".claude/projects").join(&fx.slug);
    std::fs::write(
        sess.join(format!("{}.jsonl", fx.uuid)),
        serde_json::json!({
            "type": "user", "uuid": "u-1", "parentUuid": null,
            "timestamp": "2026-07-12T10:00:00.000Z", "cwd": "/home/test",
            "sessionId": fx.uuid, "message": {"role": "user", "content": "hi"}
        })
        .to_string()
            + "\n",
    )
    .unwrap();
    assert!(fx.run(&["archive", "--all"]).status.success());

    let root = fx.yomi_home.join("archive/_scratch");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o000)).unwrap();
    let out = fx.run(&["verify", "--all", "--json"]);
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

    let txt = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(txt.trim()).unwrap_or_else(|e| {
        panic!("the scratch pass aborted the command before printing ({e}): {txt:?}")
    });
    assert!(
        v["verified"].as_u64().unwrap() > 0,
        "a completed catalog verification was discarded: {v:#}"
    );
    assert_eq!(
        issues(&v["scratch"], "refused"),
        vec!["UnreadableStoreRoot"],
        "{v:#}"
    );
    assert_eq!(out.status.code().unwrap(), 2);
}

/// `--all` is an explicit alias for "no session", not an independent mode. It
/// used to be accepted beside a session and then never read — a documented
/// alternative that silently did nothing is worse than either option.
#[test]
fn p9_all_and_a_session_are_mutually_exclusive() {
    let fx = Fx::seeded("allconflict");
    let out = fx.run(&["verify", &fx.uuid, "--all"]);
    assert_ne!(
        out.status.code().unwrap(),
        0,
        "passing both a session and --all was accepted"
    );
    let err = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(
        err.contains("cannot be used with") || err.contains("conflict"),
        "the conflict was not explained: {err}"
    );
    // Each alone still works.
    assert_eq!(fx.verify_args(&["verify", "--all", "--json"]).0, 0);
    assert_eq!(fx.verify_args(&["verify", &fx.uuid, "--json"]).0, 0);
}
