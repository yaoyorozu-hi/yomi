//! P7 break tests: adversarial assault on U2 — the widened scratch enumeration
//! and store reconciliation (store law S).
//!
//! U2 is the first change in this series that **deletes `.zst` from the store**.
//! The safety of that rests entirely on the second of its two laws: a file that
//! has vanished from the live tree keeps its entry and its artifact, because
//! that artifact is the only remaining copy. These tests exist to break that
//! law, and to break the boundary of the delete authority around it.
//!
//! Written to BREAK, not to confirm. Every fixture is fabricated under
//! `CARGO_TARGET_TMPDIR`; nothing is written to `/`, to the repository working
//! copy, or outside the build tree, and no real Claude Code data is touched.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const BIN: &str = env!("CARGO_BIN_EXE_yomi");

/// A fabricated AWS example key (public documentation value, not a credential).
const FIXTURE_AKIA: &str = "AKIAIOSFODNN7EXAMPLE";

fn unique() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// uid 0, read off a file this process just created. The permission-denial
/// fixtures below are meaningless as root, which ignores the mode bits.
fn is_root() -> bool {
    static ROOT: OnceLock<bool> = OnceLock::new();
    *ROOT.get_or_init(|| {
        let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("p7-uid-{}", unique()));
        std::fs::write(&p, b"").unwrap();
        let uid = std::fs::metadata(&p).unwrap().uid();
        let _ = std::fs::remove_file(&p);
        uid == 0
    })
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

impl Fx {
    fn new(tag: &str) -> Self {
        Self::with_config(tag, "")
    }

    fn with_config(tag: &str, cfg: &str) -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "p7-{tag}-{}-{}",
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
            base,
        };
        std::fs::create_dir_all(fx.home.join(".claude/projects").join(&fx.slug)).unwrap();
        for d in [&fx.tmp_root, &fx.cache_home, &fx.proc_root, &fx.yomi_home] {
            std::fs::create_dir_all(d).unwrap();
        }
        // `ensure_layout` refuses a store looser than 700; the mode this dir gets
        // otherwise depends on the harness umask.
        std::fs::set_permissions(&fx.yomi_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        if !cfg.is_empty() {
            std::fs::write(fx.yomi_home.join("config.toml"), cfg).unwrap();
        }
        std::fs::create_dir_all(fx.session_dir().join("scratchpad")).unwrap();
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
        std::fs::write(p, bytes).unwrap();
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

    fn archive(&self) -> std::process::Output {
        let out = self.run(&["archive", "--all", "--include", "scratch"]);
        assert!(
            out.status.success(),
            "archive failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    /// `--dry-run --json`, returning the previewed orphan count.
    fn dry_run_orphans(&self) -> u64 {
        let out = self.run(&[
            "archive",
            "--all",
            "--include",
            "scratch",
            "--dry-run",
            "--json",
        ]);
        json_field(&out, "scratch_orphans_removed")
    }

    /// A real run, returning the reported orphan count.
    fn archive_orphans(&self) -> u64 {
        let out = self.run(&["archive", "--all", "--include", "scratch", "--json"]);
        json_field(&out, "scratch_orphans_removed")
    }

    fn manifest_at(&self, store: &Path) -> serde_json::Value {
        let p = store.join("manifest.json");
        serde_json::from_str(
            &std::fs::read_to_string(&p)
                .unwrap_or_else(|e| panic!("no manifest at {}: {e}", p.display())),
        )
        .expect("manifest json")
    }

    fn manifest(&self) -> serde_json::Value {
        self.manifest_at(&self.store_dir())
    }

    /// Every `_scratch` store directory, by raw name.
    fn store_dirs(&self) -> Vec<PathBuf> {
        let root = self.yomi_home.join("archive/_scratch");
        let mut v: Vec<PathBuf> = std::fs::read_dir(&root)
            .map(|rd| rd.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        v.sort();
        v
    }

    fn age_tree(&self) {
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(200 * 86_400);
        for p in walk_files(&self.session_dir()) {
            let _ = filetime::set_file_mtime(&p, filetime::FileTime::from_system_time(when));
        }
    }

    fn gc_deleted(&self) -> u64 {
        let out = self.run(&["gc", "--targets", "scratch", "--commit", "--json"]);
        json_field(&out, "deleted")
    }

    fn gc_reason(&self) -> String {
        let out = self.run(&["gc", "--targets", "scratch", "--json"]);
        let v: serde_json::Value =
            serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("gc json");
        v["items"][0]["reason"].as_str().unwrap_or("").to_string()
    }
}

fn json_field(out: &std::process::Output, key: &str) -> u64 {
    let txt = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(txt.trim()).unwrap_or_else(|e| {
        panic!(
            "no parseable --json output ({e}); stdout={txt:?} stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    v[key]
        .as_u64()
        .unwrap_or_else(|| panic!("no `{key}` in {v}"))
}

fn walk_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            match std::fs::symlink_metadata(&p) {
                Ok(md) if md.is_dir() => stack.push(p),
                Ok(_) => out.push(p),
                Err(_) => {}
            }
        }
    }
    out.sort();
    out
}

/// `*.zst` under `root`, as paths relative to it.
fn zst_under(root: &Path) -> Vec<String> {
    let mut v: Vec<String> = walk_files(root)
        .into_iter()
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("zst"))
        .map(|p| p.strip_prefix(root).unwrap().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn entries(mf: &serde_json::Value) -> Vec<serde_json::Value> {
    mf["entries"].as_array().cloned().unwrap_or_default()
}

fn entry_named(mf: &serde_json::Value, path: &str) -> serde_json::Value {
    entries(mf)
        .into_iter()
        .find(|e| e["path"] == path)
        .unwrap_or_else(|| panic!("no manifest entry for {path} in {mf:#}"))
}

/// Store law S: the `*.zst` present are exactly the `stored: true` entries.
fn assert_law_s(mf: &serde_json::Value, stored: &[String], ctx: &str) {
    let mut claimed: Vec<String> = entries(mf)
        .iter()
        .filter(|e| e["stored"] == true)
        .map(|e| format!("{}.zst", e["path"].as_str().unwrap()))
        .collect();
    claimed.sort();
    let mut present = stored.to_vec();
    present.sort();
    assert_eq!(
        present, claimed,
        "{ctx}: store law S broken — store holds {present:?} but the ledger \
         claims {claimed:?}"
    );
}

// ---------------------------------------------------------------------------
// A. The ledger must not claim an artifact it does not have.
//
// This is the invariant #9 established for the over-cap path. The store loop has
// a second way to leave `stored: true` with no artifact: `read_source` returning
// None. U2 widens enumeration to the whole session tree, so more files reach it.
// ---------------------------------------------------------------------------

/// A file that stats fine but cannot be opened (mode 000) passes the glob and
/// size policy, so it is marked `stored: true` — and then `read_source` refuses
/// it, leaving no `.zst` and no hashes. The manifest claims an artifact that was
/// never written.
#[test]
fn p7_unreadable_file_is_never_recorded_stored_without_hashes() {
    if is_root() {
        return;
    }
    let fx = Fx::new("unreadable");
    fx.write("scratchpad/ok.md", b"readable\n");
    fx.write("scratchpad/locked.md", b"unreadable\n");
    let locked = fx.session_dir().join("scratchpad/locked.md");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

    fx.archive();
    let mf = fx.manifest();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();

    let liars: Vec<String> = entries(&mf)
        .iter()
        .filter(|e| e["stored"] == true)
        .filter(|e| e["source_sha256"].as_str().is_none() || e["content_sha256"].as_str().is_none())
        .map(|e| e.to_string())
        .collect();
    assert!(
        liars.is_empty(),
        "{} manifest entries claim `stored: true` with no hashes because \
         `read_source` refused the file after the policy had already decided to \
         store it. A file that could not be read must be recorded `stored: \
         false`, exactly as an over-cap tree is (#9). Offending: {liars:#?}. \
         Store holds: {:?}",
        liars.len(),
        zst_under(&fx.store_dir())
    );
}

/// The concern this file originally stated as `deleted == 1` — which was wrong.
/// Requiring the tree to be reclaimed would have required deleting a source
/// whose content was never captured, inverting archive-verify-then-delete: a
/// transient EACCES during one archive run would silently authorize destroying
/// the only copy. Refusing is correct.
///
/// What must hold is the weaker, real invariant: the refusal is **not
/// permanent**. #9 was permanent — re-archiving regenerated the same broken
/// manifest, and no action short of a code change freed the tree. A capture
/// failure must instead track reality: refused while the cause persists, and
/// reclaimable the moment it clears, with no manual repair of the store.
///
/// Skipped under uid 0, which ignores the mode bits this fixture relies on.
#[test]
fn p7_capture_failure_refusal_is_transient_not_permanent() {
    if is_root() {
        return;
    }
    let fx = Fx::new("capture-transient");
    fx.write("scratchpad/ok.md", b"readable\n");
    fx.write("scratchpad/locked.md", b"unreadable\n");
    let locked = fx.session_dir().join("scratchpad/locked.md");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

    // While the cause persists, repeated archive+GC cycles must keep refusing.
    // #9's signature was exactly this loop never converging; here it must not
    // converge *yet*, and must not corrupt anything while it does not.
    let mut refused = Vec::new();
    for _ in 0..3 {
        fx.archive();
        fx.age_tree();
        refused.push(fx.gc_deleted());
    }
    let reason = fx.gc_reason();
    assert_eq!(
        refused,
        vec![0, 0, 0],
        "an uncaptured file did not hold the tree: {refused:?}. Deleting a source \
         whose content was never read inverts archive-verify-then-delete."
    );
    assert_eq!(
        reason, "OpenFailed",
        "the refusal is diagnosed as {reason:?}; nothing failed re-verification \
         — the content was never read at all"
    );
    assert!(
        fx.session_dir().exists(),
        "the tree was reclaimed despite an uncaptured file"
    );

    // The cause clears. No repair of the store, no manual step: the next archive
    // captures the file and the tree becomes reclaimable.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
    fx.archive();
    fx.age_tree();
    let deleted = fx.gc_deleted();

    assert_eq!(
        deleted,
        1,
        "the tree stayed unreclaimable after the file became readable again \
         (gc reason {:?}) — the refusal outlived its cause, which is the #9 \
         permanence this design exists to avoid",
        fx.gc_reason()
    );
    assert!(
        !fx.session_dir().exists(),
        "gc reported a reclaim but the tree is still on disk"
    );
}

/// A capture failure must not leave the store and the ledger disagreeing. Both
/// shapes are checked: no prior archive to salvage (entry goes `stored: false`,
/// so no artifact may remain) and a prior archive salvaged (entry stays
/// `stored: true`, so its artifact must survive).
///
/// Skipped under uid 0.
#[test]
fn p7_capture_failure_keeps_store_and_ledger_in_agreement() {
    if is_root() {
        return;
    }
    // (i) First-ever archive fails to capture: nothing to salvage.
    let fx = Fx::new("capture-laws-fresh");
    fx.write("scratchpad/a.md", b"a\n");
    let a = fx.session_dir().join("scratchpad/a.md");
    std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o000)).unwrap();
    fx.archive();
    let mf = fx.manifest();
    let stored = zst_under(&fx.store_dir());
    std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o644)).unwrap();

    let e = entry_named(&mf, "scratchpad/a.md");
    assert_eq!(e["capture_failed"], true, "not marked capture_failed: {e}");
    assert_eq!(
        e["stored"], false,
        "claims an artifact it never captured: {e}"
    );
    assert_law_s(&mf, &stored, "fresh capture failure");

    // (ii) A good archive exists, then the file becomes unreadable: the earlier
    // capture is salvaged, so the ledger keeps claiming it and the artifact must
    // still be there.
    let fx2 = Fx::new("capture-laws-salvage");
    fx2.write("scratchpad/a.md", b"captured-content\n");
    fx2.archive();
    assert_eq!(zst_under(&fx2.store_dir()).len(), 1);
    let a2 = fx2.session_dir().join("scratchpad/a.md");
    std::fs::set_permissions(&a2, std::fs::Permissions::from_mode(0o000)).unwrap();
    fx2.archive();
    let mf2 = fx2.manifest();
    let stored2 = zst_under(&fx2.store_dir());
    std::fs::set_permissions(&a2, std::fs::Permissions::from_mode(0o644)).unwrap();

    let e2 = entry_named(&mf2, "scratchpad/a.md");
    assert_eq!(e2["capture_failed"], true);
    assert_eq!(
        e2["stored"], true,
        "the salvaged entry dropped its claim, which makes reconciliation treat \
         a good archive as unclaimed: {e2}"
    );
    assert_law_s(&mf2, &stored2, "salvaged capture failure");
    assert!(
        stored2.iter().any(|p| p.ends_with("a.md.zst")),
        "the earlier capture was destroyed by a permission bit: {stored2:?}"
    );
}

/// A pre-D2/R1 manifest records `stored: true` with **no hashes** for a file
/// whose `.zst` genuinely exists — the codebase documents that population and
/// parses it deliberately. The salvage filter requires both hashes, so such an
/// entry cannot be salvaged; the entry goes `stored: false`, and reconciliation
/// then removes a real, existing archive. The last copy is destroyed over a
/// permission bit, which is the one thing law two exists to prevent.
///
/// Skipped under uid 0.
#[test]
fn p7_legacy_hashless_entry_keeps_its_real_artifact_on_capture_failure() {
    if is_root() {
        return;
    }
    let fx = Fx::new("legacy-salvage");
    fx.write("scratchpad/a.md", b"legacy-captured-content\n");
    fx.archive();
    let zst = fx.store_dir().join("scratchpad/a.md.zst");
    assert!(zst.exists(), "fixture stored nothing");
    let artifact_before = std::fs::read(&zst).unwrap();

    // Age the ledger into the pre-D2 shape: stored, but no hashes recorded. The
    // artifact on disk is untouched and still valid.
    let mfp = fx.store_dir().join("manifest.json");
    let mut mf: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&mfp).unwrap()).unwrap();
    for e in mf["entries"].as_array_mut().unwrap() {
        if e["path"] == "scratchpad/a.md" {
            e.as_object_mut().unwrap().remove("source_sha256");
            e.as_object_mut().unwrap().remove("content_sha256");
        }
    }
    std::fs::write(&mfp, serde_json::to_string_pretty(&mf).unwrap()).unwrap();

    let a = fx.session_dir().join("scratchpad/a.md");
    std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o000)).unwrap();
    fx.archive();
    let stored = zst_under(&fx.store_dir());
    std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert!(
        zst.exists(),
        "a real, existing archive was deleted because its (legacy, hashless) \
         ledger entry could not be salvaged when the live file became \
         unreadable. Store now holds: {stored:?}"
    );
    assert_eq!(
        std::fs::read(&zst).unwrap(),
        artifact_before,
        "the artifact was rewritten during a run that captured nothing"
    );
}

// ---------------------------------------------------------------------------
// B. Retention — the law the whole delete authority rests on.
// ---------------------------------------------------------------------------

/// A file that vanishes and whose name would now be denied by policy must still
/// keep its artifact: retention is appended after the cap and after the store
/// pass precisely so a vanished entry is never re-policied.
#[test]
fn p7_retained_entry_is_not_repoliced_by_a_deny_change() {
    let fx = Fx::new("retain-deny");
    fx.write("scratchpad/keep.md", b"keep\n");
    fx.write("scratchpad/gone.md", b"gone-content\n");
    fx.archive();
    assert_eq!(
        zst_under(&fx.store_dir()).len(),
        2,
        "fixture did not store both"
    );

    // The file vanishes, and policy simultaneously turns against its name.
    std::fs::remove_file(fx.session_dir().join("scratchpad/gone.md")).unwrap();
    std::fs::write(
        fx.yomi_home.join("config.toml"),
        "[scratch]\ndeny = [\"**/gone.md\"]\n",
    )
    .unwrap();
    fx.archive();

    let stored = zst_under(&fx.store_dir());
    assert!(
        stored.iter().any(|p| p.ends_with("gone.md.zst")),
        "the archive-only copy of a vanished file was destroyed because the new \
         policy would have denied its name. A retained entry must not be \
         re-policied — it belongs to no live tree. Store now holds: {stored:?}"
    );
    let e = entries(&fx.manifest())
        .into_iter()
        .find(|e| e["path"] == "scratchpad/gone.md")
        .expect("retained entry missing from the ledger entirely");
    assert_eq!(
        e["present"], false,
        "retained entry not marked present:false"
    );
}

/// A file that becomes unreadable is dropped from the live set, so the prior
/// entry is retained and its artifact kept. This is the direction that cannot
/// lose data, and it must hold even though the file is still on disk.
#[test]
fn p7_file_turning_unreadable_retains_its_artifact() {
    if is_root() {
        return;
    }
    let fx = Fx::new("retain-unreadable");
    fx.write("scratchpad/a.md", b"original\n");
    fx.archive();
    assert_eq!(zst_under(&fx.store_dir()).len(), 1);

    let a = fx.session_dir().join("scratchpad/a.md");
    std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o000)).unwrap();
    fx.archive();
    let stored = zst_under(&fx.store_dir());
    std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(
        stored.len(),
        1,
        "the artifact of a file that merely became unreadable was reconciled \
         away; store holds {stored:?}"
    );
}

/// A prior manifest entry whose identity cannot be decoded — a corrupt or
/// hand-edited `path_hex` — is dropped from the new ledger by `filter_map`, and
/// its artifact then looks like an orphan. Reconciliation must not destroy an
/// artifact on the strength of a ledger it could not fully parse.
#[test]
fn p7_undecodable_prior_entry_does_not_forfeit_its_artifact() {
    let fx = Fx::new("bad-hex");
    fx.write("scratchpad/a.md", b"content-a\n");
    fx.write("scratchpad/b.md", b"content-b\n");
    fx.archive();
    assert_eq!(zst_under(&fx.store_dir()).len(), 2);

    // Both files vanish, so both entries would be retained...
    std::fs::remove_file(fx.session_dir().join("scratchpad/a.md")).unwrap();
    std::fs::remove_file(fx.session_dir().join("scratchpad/b.md")).unwrap();
    // ...but one entry's identity is corrupted first.
    let mfp = fx.store_dir().join("manifest.json");
    let mut mf: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&mfp).unwrap()).unwrap();
    for e in mf["entries"].as_array_mut().unwrap() {
        if e["path"] == "scratchpad/a.md" {
            e["path_hex"] = serde_json::Value::String("zz".into()); // not hex
        }
    }
    std::fs::write(&mfp, serde_json::to_string_pretty(&mf).unwrap()).unwrap();

    fx.archive();
    let stored = zst_under(&fx.store_dir());
    assert!(
        stored.iter().any(|p| p.ends_with("a.md.zst")),
        "the only copy of a vanished file was deleted because its manifest entry \
         had an undecodable identity. An entry the reader cannot parse is a \
         reason to refuse, not a licence to destroy its artifact. Store holds: \
         {stored:?}"
    );
}

// ---------------------------------------------------------------------------
// C. N10 — the store key is lossy, so two sessions can share one store.
// ---------------------------------------------------------------------------

/// `ScratchDir::key` is built with `to_string_lossy`, so two session directories
/// whose names differ only in non-UTF-8 bytes collapse to one store key. They
/// then share a store directory and a manifest — and, when they hold files of
/// the same relative name, one session's archived copy overwrites the other's.
#[test]
fn p7_lossy_colliding_session_dirs_do_not_share_a_store() {
    let fx = Fx::new("n10");
    // Two sibling sessions under one slug, names colliding only when lossy.
    let slug_dir = fx.tmp_root.join(&fx.slug);
    let mut made = Vec::new();
    for raw in [&b"sess-\xfe"[..], &b"sess-\xff"[..]] {
        let mut name = slug_dir.clone().into_os_string().into_vec();
        name.push(b'/');
        name.extend_from_slice(raw);
        let sess = PathBuf::from(std::ffi::OsString::from_vec(name));
        std::fs::create_dir_all(sess.join("scratchpad")).unwrap();
        // Same relative name in both — the common case (`notes.md`).
        std::fs::write(
            sess.join("scratchpad/note.md"),
            format!("payload for {}\n", String::from_utf8_lossy(raw)),
        )
        .unwrap();
        made.push(sess);
    }
    // Remove the default session dir so only the two colliding ones exist.
    let _ = std::fs::remove_dir_all(fx.session_dir());

    fx.archive();

    let dirs = fx.store_dirs();
    assert_eq!(
        dirs.len(),
        2,
        "two distinct session directories collapsed into {} store director{} \
         because the store key is derived with `to_string_lossy`. Their \
         manifests and `.zst` share one namespace, so the second archive run \
         overwrites the first session's only archived copy. Store dirs: {:?}",
        dirs.len(),
        if dirs.len() == 1 { "y" } else { "ies" },
        dirs.iter().map(|d| d.to_string_lossy()).collect::<Vec<_>>()
    );
}

/// The consequence of the shared key, stated as data: two colliding sessions
/// holding a file of the same relative name end up with ONE artifact between
/// them. The second run's live pass claims that identity, so the first
/// session's entry is not retained and its stored bytes are overwritten — the
/// archive silently keeps one payload and loses the other.
#[test]
fn p7_lossy_colliding_sessions_do_not_destroy_each_others_archives() {
    let fx = Fx::new("n10-data");
    let slug_dir = fx.tmp_root.join(&fx.slug);
    let payloads: [(&[u8], &str); 2] = [
        (&b"sess-\xfe"[..], "PAYLOAD-FE-must-survive\n"),
        (&b"sess-\xff"[..], "PAYLOAD-FF-must-survive\n"),
    ];
    for (raw, payload) in payloads {
        let mut name = slug_dir.clone().into_os_string().into_vec();
        name.push(b'/');
        name.extend_from_slice(raw);
        let sess = PathBuf::from(std::ffi::OsString::from_vec(name));
        std::fs::create_dir_all(sess.join("scratchpad")).unwrap();
        std::fs::write(sess.join("scratchpad/note.md"), payload).unwrap();
    }
    let _ = std::fs::remove_dir_all(fx.session_dir());

    fx.archive();

    // Whatever the store layout, both payloads must be recoverable from it.
    let mut recovered = Vec::new();
    for d in fx.store_dirs() {
        for p in walk_files(&d) {
            if p.extension().and_then(|e| e.to_str()) != Some("zst") {
                continue;
            }
            let plain =
                yomi::archive::compress::decompress_all(&std::fs::read(&p).unwrap()).unwrap();
            recovered.push(String::from_utf8_lossy(&plain).into_owned());
        }
    }
    let missing: Vec<&str> = payloads
        .iter()
        .map(|(_, p)| *p)
        .filter(|p| !recovered.iter().any(|r| r.contains(p.trim())))
        .collect();
    assert!(
        missing.is_empty(),
        "archiving two sessions whose directory names collide under \
         `to_string_lossy` destroyed {} of 2 archived payloads: {missing:?} are \
         absent from the store. Recovered instead: {recovered:?}. The second \
         session's live pass claimed the first's identity, so the first entry \
         was not retained and its `.zst` was overwritten.",
        missing.len()
    );
}

/// The `Denied` arm of capture failure is the S3/B4 TOCTOU: between the walk
/// that enumerated the file and the read that would capture it, the name is
/// swapped for a hardlink at the credential. `open_guarded` refuses by inode, so
/// this must land as a capture failure — and, crucially, the credential's bytes
/// must never reach the store, and the tree must not then be reclaimed with the
/// credential inode inside it.
#[test]
fn p7_credential_hardlink_swapped_in_after_the_walk_captures_nothing() {
    let fx = Fx::new("denied-toctou");
    // A credential at the canonical path the denylist re-stats live.
    let claude = fx.home.join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    let cred = claude.join(".credentials.json");
    let secret = format!("{{\"accessToken\":\"{FIXTURE_AKIA}-NOT-REAL\"}}\n");
    std::fs::write(&cred, &secret).unwrap();

    fx.write("scratchpad/a.md", b"ordinary content\n");
    fx.archive();
    assert_eq!(
        zst_under(&fx.store_dir()).len(),
        1,
        "fixture stored nothing"
    );

    // The candidate name now resolves to the credential's inode.
    let a = fx.session_dir().join("scratchpad/a.md");
    std::fs::remove_file(&a).unwrap();
    std::fs::hard_link(&cred, &a).unwrap();

    fx.archive();
    let mf = fx.manifest();
    // Measured mechanism: the candidate loop's `is_blacklisted` performs the
    // same path-glob + live-inode check `open_guarded` does, so it catches the
    // swap first and the candidate never enters the live set at all. The prior
    // entry is therefore *retained* (`present: false`) rather than recorded as a
    // capture failure — `read_source`'s `Denied` arm is reachable only in the
    // race window between the two checks. Retention is the stronger outcome: it
    // keeps the good archive of the file the credential displaced.
    let e = entry_named(&mf, "scratchpad/a.md");
    assert_eq!(
        e["present"], false,
        "the displaced file's entry was neither retained nor marked uncaptured; \
         it is being treated as an ordinary live file: {e}"
    );
    // `present: false` is the conservative "treat it as gone" reading, not a
    // claim about whether the *name* is occupied. `blacklisted: true` is what
    // answers that, stamped onto the retained entry after the tail — which is
    // why retention above is untouched by it (D-S5).
    assert_eq!(
        e["blacklisted"], true,
        "the denylisted inode occupying this name is recorded nowhere, so the \
         tree's permanent refusal has no stated reason: {e}"
    );
    assert!(
        zst_under(&fx.store_dir())
            .iter()
            .any(|p| p.ends_with("a.md.zst")),
        "the archive of the file the credential displaced was destroyed"
    );

    // The credential's bytes must not exist anywhere under the store.
    for p in walk_files(&fx.store_dir()) {
        let raw = std::fs::read(&p).unwrap();
        assert!(
            !contains(&raw, secret.trim().as_bytes()),
            "credential bytes reached {} verbatim",
            p.display()
        );
        if p.extension().and_then(|x| x.to_str()) == Some("zst") {
            let plain = yomi::archive::compress::decompress_all(&raw).expect("decompress");
            assert!(
                !contains(&plain, secret.trim().as_bytes()),
                "credential bytes were archived into {}",
                p.display()
            );
        }
    }

    // And the tree must not be reclaimed while a credential inode sits in it.
    fx.age_tree();
    let deleted = fx.gc_deleted();
    assert_eq!(
        deleted,
        0,
        "the tree was reclaimed with a credential hardlink inside it (gc reason \
         {:?})",
        fx.gc_reason()
    );
    assert!(cred.exists(), "the credential inode lost a link");
    assert_eq!(
        std::fs::read_to_string(&cred).unwrap(),
        secret,
        "the credential's content changed"
    );
}

/// The `read_source` refusals that are deterministically reachable — an
/// unreadable file, and a source past the 256MB read bound — share one ledger
/// fact: nothing was captured. They must be recorded identically, whatever the
/// errno behind them.
///
/// The third arm, `Denied`, is deliberately absent: the candidate loop's
/// `is_blacklisted` runs the same path-glob + live-inode check that
/// `open_guarded` does, so a denylisted inode is caught before `read_source` is
/// ever called and the entry is retained instead
/// (`p7_credential_hardlink_swapped_in_after_the_walk_captures_nothing`). That
/// arm is reachable only inside the race window between the two checks.
///
/// The oversize arm uses a sparse file — apparent size past the bound, no disk
/// used and no read performed, so the fixture is free.
///
/// Skipped under uid 0 (the unreadable arm).
#[test]
fn p7_capture_failure_paths_are_recorded_alike() {
    if is_root() {
        return;
    }
    // Caps raised above the 256MB read bound so *policy* admits the sparse file
    // and only `read_source` refuses it.
    let cfg = "[scratch]\nfile_cap = \"300MB\"\ntotal_cap = \"1GB\"\n";

    let mut shapes = Vec::new();
    for arm in ["unreadable", "oversize"] {
        let fx = Fx::with_config(&format!("paths-{arm}"), cfg);
        fx.write("scratchpad/a.md", b"content\n");
        let a = fx.session_dir().join("scratchpad/a.md");
        if arm == "unreadable" {
            std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o000)).unwrap();
        } else {
            // Sparse: apparent size past MAX_SOURCE_BYTES, zero blocks used.
            let f = std::fs::File::create(&a).unwrap();
            f.set_len(256 * 1024 * 1024 + 1).unwrap();
        }
        fx.archive();
        let e = entry_named(&fx.manifest(), "scratchpad/a.md");
        fx.age_tree();
        let reason = fx.gc_reason();
        if arm == "unreadable" {
            std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o644)).unwrap();
        } else {
            // The hole costs one block on disk but 256MB of *apparent* size, and
            // CI caches `target/` with a tar-based action that would materialize
            // it. Left-behind fixtures are the house style; a sparse one is not.
            std::fs::remove_file(&a).unwrap();
        }
        shapes.push((
            arm,
            e["capture_failed"].clone(),
            e["stored"].clone(),
            reason,
        ));
    }

    for (arm, failed, stored, reason) in &shapes {
        assert_eq!(
            *failed,
            serde_json::Value::Bool(true),
            "{arm}: not recorded as a capture failure (shapes: {shapes:?})"
        );
        assert_eq!(
            *stored,
            serde_json::Value::Bool(false),
            "{arm}: claims an artifact it never captured (shapes: {shapes:?})"
        );
        assert_eq!(
            reason, "OpenFailed",
            "{arm}: diagnosed {reason:?} (shapes: {shapes:?})"
        );
    }
}

/// `capture_failed` is attacker-writable state in the store, so neither value
/// may be forgeable into a wrongful *reclaim*. Forging it false on a genuinely
/// uncaptured entry must still refuse — the remaining gates have to catch it.
///
/// Skipped under uid 0.
#[test]
fn p7_forged_capture_failed_false_cannot_force_a_reclaim() {
    if is_root() {
        return;
    }
    let fx = Fx::new("forge-false");
    fx.write("scratchpad/a.md", b"a\n");
    let a = fx.session_dir().join("scratchpad/a.md");
    std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o000)).unwrap();
    fx.archive();

    // Strip the flag the gate keys on, leaving an entry that claims a clean
    // "policy declined to store" for a file nothing ever read.
    let mfp = fx.store_dir().join("manifest.json");
    let mut mf: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&mfp).unwrap()).unwrap();
    for e in mf["entries"].as_array_mut().unwrap() {
        e.as_object_mut().unwrap().remove("capture_failed");
    }
    std::fs::write(&mfp, serde_json::to_string_pretty(&mf).unwrap()).unwrap();

    fx.age_tree();
    let deleted = fx.gc_deleted();
    std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(
        deleted, 0,
        "clearing `capture_failed` in the stored manifest was enough to make the \
         gate reclaim a tree whose file was never captured — the flag is the \
         only thing standing between an unread file and its deletion"
    );
    assert!(fx.session_dir().exists());
}

/// The other direction: forging the flag *true* refuses a healthy tree. That is
/// fail-closed and acceptable — but it must not be a permanent wedge, so the
/// next archive has to clear it from the live pass.
#[test]
fn p7_forged_capture_failed_true_is_cleared_by_the_next_archive() {
    let fx = Fx::new("forge-true");
    fx.write("scratchpad/a.md", b"a\n");
    fx.archive();

    let mfp = fx.store_dir().join("manifest.json");
    let mut mf: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&mfp).unwrap()).unwrap();
    for e in mf["entries"].as_array_mut().unwrap() {
        e["capture_failed"] = serde_json::Value::Bool(true);
    }
    std::fs::write(&mfp, serde_json::to_string_pretty(&mf).unwrap()).unwrap();

    fx.age_tree();
    assert_eq!(
        fx.gc_deleted(),
        0,
        "a forged capture_failed did not refuse; the gate ignores the flag it is \
         supposed to key on"
    );

    // A run that can read the file must retract the forged claim.
    fx.archive();
    let e = entry_named(&fx.manifest(), "scratchpad/a.md");
    assert_ne!(
        e["capture_failed"],
        serde_json::Value::Bool(true),
        "the forged flag survived a successful capture: {e}"
    );
    fx.age_tree();
    assert_eq!(
        fx.gc_deleted(),
        1,
        "the tree stayed wedged after a successful re-archive (reason {:?})",
        fx.gc_reason()
    );
}

// ---------------------------------------------------------------------------
// D. The delete authority's boundary.
// ---------------------------------------------------------------------------

/// A store directory that is a symlink: `create_dir_all`, `set_700` and
/// `atomic_write` all follow it, so the archive writes its manifest and
/// artifacts outside the archive tree and re-modes an unrelated directory —
/// while reconciliation refuses the same path. Writes and deletes must agree on
/// whether a symlinked store dir is legitimate.
#[test]
fn p7_symlinked_store_dir_does_not_let_writes_escape() {
    let fx = Fx::new("symlink-store");
    fx.write("scratchpad/n.md", b"content\n");
    let outside = fx.base.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("precious.txt"), b"UNRELATED\n").unwrap();
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mode_before = std::fs::metadata(&outside).unwrap().permissions().mode() & 0o777;

    std::fs::create_dir_all(fx.yomi_home.join("archive/_scratch")).unwrap();
    std::os::unix::fs::symlink(&outside, fx.store_dir()).unwrap();

    fx.archive();

    let escaped = walk_files(&outside)
        .into_iter()
        .filter(|p| p.file_name() != Some(OsStr::new("precious.txt")))
        .map(|p| {
            p.strip_prefix(&outside)
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    let mode_after = std::fs::metadata(&outside).unwrap().permissions().mode() & 0o777;

    assert!(
        escaped.is_empty() && mode_after == mode_before,
        "archive wrote {escaped:?} into {} — outside the archive tree — through a \
         symlinked store directory, and changed its mode {mode_before:o} -> \
         {mode_after:o}. Reconciliation refuses a symlinked store dir; the write \
         path must refuse it too, or the two disagree about what the store is.",
        outside.display()
    );
    assert!(
        outside.join("precious.txt").exists(),
        "an unrelated file in the symlink target was destroyed"
    );
}

/// Reconciliation is scoped to one key's store dir. Another key's artifacts,
/// the quarantine tree (raw originals — forensic material), and `manifest.json`
/// must all be beyond its reach.
#[test]
fn p7_reconcile_touches_neither_other_keys_nor_quarantine() {
    let fx = Fx::new("bounds");
    // A tree whose secret forces a quarantine original to exist.
    fx.write(
        "scratchpad/leak.md",
        format!("aws key {FIXTURE_AKIA}\n").as_bytes(),
    );
    fx.write("scratchpad/a.md", b"a\n");
    fx.archive();

    // A second key's store, and a stale artifact inside it.
    let other = fx.yomi_home.join("archive/_scratch/-other--key");
    std::fs::create_dir_all(other.join("scratchpad")).unwrap();
    std::fs::write(other.join("scratchpad/x.md.zst"), b"other-key-artifact").unwrap();
    std::fs::write(other.join("manifest.json"), b"{\"entries\":[]}").unwrap();

    let quarantine = fx.yomi_home.join("quarantine");
    let q_before = walk_files(&quarantine);
    assert!(
        !q_before.is_empty(),
        "fixture produced no quarantine originals; the reach test is vacuous"
    );

    // Force a full reconcile: deny everything, so every live artifact is stale.
    std::fs::write(fx.yomi_home.join("config.toml"), "[scratch]\nallow = []\n").unwrap();
    fx.archive();

    assert_eq!(
        zst_under(&fx.store_dir()).len(),
        0,
        "the reconcile under test did not actually remove anything; the bounds \
         assertions below would be vacuous"
    );
    assert!(
        other.join("scratchpad/x.md.zst").exists(),
        "reconciling one key removed another key's artifact"
    );
    assert!(
        other.join("manifest.json").exists() && fx.store_dir().join("manifest.json").exists(),
        "reconciliation removed a manifest.json"
    );
    assert_eq!(
        walk_files(&quarantine),
        q_before,
        "reconciliation reached into quarantine/ — those are the raw originals"
    );
}

/// A non-regular file named `*.zst` — a symlink at something outside the store —
/// must be left alone, never followed and never unlinked.
#[test]
fn p7_non_regular_zst_is_left_alone() {
    let fx = Fx::new("nonregular");
    fx.write("scratchpad/a.md", b"a\n");
    fx.archive();

    let outside = fx.base.join("target.txt");
    std::fs::write(&outside, b"MUST SURVIVE\n").unwrap();
    let planted = fx.store_dir().join("scratchpad/evil.md.zst");
    std::os::unix::fs::symlink(&outside, &planted).unwrap();

    // Deny everything so reconciliation sweeps the whole store dir.
    std::fs::write(fx.yomi_home.join("config.toml"), "[scratch]\nallow = []\n").unwrap();
    fx.archive();

    assert!(
        outside.exists(),
        "reconciliation followed a symlink named *.zst and destroyed its target"
    );
    assert!(
        std::fs::symlink_metadata(&planted).is_ok(),
        "a non-regular *.zst was unlinked; the authority is supposed to stop at \
         regular files"
    );
}

// ---------------------------------------------------------------------------
// E. `--dry-run` must be an honest preview of the delete.
// ---------------------------------------------------------------------------

/// The previewed orphan count must equal what the real run then removes; a
/// preview that undercounts is a preview that hides deletions.
#[test]
fn p7_dry_run_preview_count_equals_the_real_removal() {
    let fx = Fx::new("dryrun-count");
    for n in ["a", "b", "c"] {
        fx.write(&format!("scratchpad/{n}.md"), b"x\n");
    }
    fx.archive();
    assert_eq!(zst_under(&fx.store_dir()).len(), 3);

    // Policy now stores nothing: all three artifacts are stale.
    std::fs::write(fx.yomi_home.join("config.toml"), "[scratch]\nallow = []\n").unwrap();

    let previewed = fx.dry_run_orphans();
    let before = zst_under(&fx.store_dir()).len();
    let reported = fx.archive_orphans();
    let after = zst_under(&fx.store_dir()).len();
    let actually_removed = (before - after) as u64;

    assert_eq!(
        previewed, actually_removed,
        "--dry-run previewed {previewed} removals but the real run removed \
         {actually_removed}; the preview is not honest"
    );
    assert_eq!(
        reported, actually_removed,
        "the real run reported {reported} removals but removed {actually_removed}"
    );
}

/// `--dry-run` must not create the store directory or write a manifest.
#[test]
fn p7_dry_run_writes_nothing() {
    let fx = Fx::new("dryrun-pure");
    fx.write("scratchpad/a.md", b"a\n");

    let previewed = fx.dry_run_orphans();
    assert_eq!(
        previewed, 0,
        "preview claimed removals with no store at all"
    );
    assert!(
        !fx.store_dir().exists(),
        "--dry-run created the store directory"
    );
    assert!(
        fx.store_dirs().is_empty(),
        "--dry-run created store directories: {:?}",
        fx.store_dirs()
    );
}

// ---------------------------------------------------------------------------
// F. Consequences of the widened enumeration.
// ---------------------------------------------------------------------------

/// U2 archives files that were previously never enumerated — anything directly
/// under `<uuid>/` and anything under `tasks/` regardless of extension. Those
/// newly-captured bytes must go through the secret scanner like any other.
#[test]
fn p7_secrets_in_newly_enumerated_paths_are_redacted() {
    let fx = Fx::new("newpaths-secrets");
    let secret_line = format!("aws_access_key_id = {FIXTURE_AKIA}\n");
    // Neither location was enumerated before U2.
    fx.write("notes.md", secret_line.as_bytes());
    fx.write("tasks/run.log", secret_line.as_bytes());
    fx.write("tasks/report.md", secret_line.as_bytes());
    fx.archive();

    let stored = zst_under(&fx.store_dir());
    assert!(
        stored.len() >= 3,
        "the widened enumeration did not store the new locations: {stored:?}"
    );
    // No stored artifact may contain the raw secret, compressed or not.
    for p in walk_files(&fx.store_dir()) {
        let raw = std::fs::read(&p).unwrap();
        assert!(
            !contains(&raw, FIXTURE_AKIA.as_bytes()),
            "raw secret present in {} (stored verbatim, unscanned)",
            p.display()
        );
        if p.extension().and_then(|e| e.to_str()) == Some("zst") {
            let plain = yomi::archive::compress::decompress_all(&raw).expect("decompress");
            assert!(
                !contains(&plain, FIXTURE_AKIA.as_bytes()),
                "the secret survived redaction in {}; a path the widened \
                 enumeration newly captures is not being scanned",
                p.display()
            );
        }
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Non-UTF-8 names in the newly-enumerated locations must keep a lossless
/// identity end to end — manifest, store path, and reconciliation.
#[test]
fn p7_non_utf8_names_in_new_locations_survive_reconcile() {
    let fx = Fx::new("newpaths-nonutf8");
    for (dir, raw) in [
        (fx.session_dir(), &b"top-\xff.md"[..]),
        (fx.session_dir().join("tasks"), &b"t-\xfe.md"[..]),
    ] {
        std::fs::create_dir_all(&dir).unwrap();
        let mut p = dir.into_os_string().into_vec();
        p.push(b'/');
        p.extend_from_slice(raw);
        std::fs::write(PathBuf::from(std::ffi::OsString::from_vec(p)), b"payload\n").unwrap();
    }
    fx.archive();
    let first = zst_under(&fx.store_dir());
    assert_eq!(
        first.len(),
        2,
        "non-UTF-8 names in the new locations were not stored: {first:?}"
    );
    assert!(
        entries(&fx.manifest())
            .iter()
            .all(|e| e["path_hex"].is_string()),
        "a non-UTF-8 entry carries no path_hex; its identity is lossy"
    );

    // Re-archiving must be a no-op: if the identity round-trip were lossy, the
    // second run would fail to match its own artifacts and delete them.
    fx.archive();
    assert_eq!(
        zst_under(&fx.store_dir()),
        first,
        "a second archive destroyed artifacts of non-UTF-8 names — the manifest \
         identity does not round-trip through reconciliation"
    );
}

// ---------------------------------------------------------------------------
// G. Convergence.
// ---------------------------------------------------------------------------

/// A crash between the manifest write and the reconcile leaves the store
/// holding more than the ledger claims. That state must be transient: the next
/// run has to converge, not entrench it.
#[test]
fn p7_store_with_extra_artifacts_converges_on_next_run() {
    let fx = Fx::new("converge-crash");
    fx.write("scratchpad/a.md", b"a\n");
    fx.archive();

    // Exactly the post-crash state: an artifact the ledger does not claim.
    let orphan = fx.store_dir().join("scratchpad/ghost.md.zst");
    std::fs::write(&orphan, b"not-in-any-manifest").unwrap();
    assert_eq!(zst_under(&fx.store_dir()).len(), 2);

    fx.archive();
    assert!(
        !orphan.exists(),
        "an artifact absent from the ledger survived a full archive run; the \
         store does not converge on law S after an interrupted run"
    );
    assert_eq!(
        zst_under(&fx.store_dir()),
        vec!["scratchpad/a.md.zst".to_string()],
        "store did not converge to exactly the ledger's claim"
    );
}

/// Raising and lowering the cap repeatedly must settle, not oscillate into a
/// state where a live file has neither an artifact nor an accurate record.
#[test]
fn p7_cap_oscillation_converges() {
    let fx = Fx::new("converge-cap");
    fx.write("scratchpad/a.md", &vec![b'a'; 800]);
    fx.write("scratchpad/b.md", &vec![b'b'; 800]);

    for round in 0..3 {
        std::fs::write(
            fx.yomi_home.join("config.toml"),
            "[scratch]\ntotal_cap = \"1KB\"\n",
        )
        .unwrap();
        fx.archive();
        let over = fx.manifest();
        assert_eq!(
            over["over_total_cap"], true,
            "round {round}: cap not exceeded"
        );
        assert!(
            entries(&over).iter().all(|e| e["stored"] == false),
            "round {round}: an over-cap live entry still claims stored"
        );
        assert_eq!(
            zst_under(&fx.store_dir()).len(),
            0,
            "round {round}: over-cap store is not empty"
        );

        std::fs::write(
            fx.yomi_home.join("config.toml"),
            "[scratch]\ntotal_cap = \"1MB\"\n",
        )
        .unwrap();
        fx.archive();
        let under = fx.manifest();
        assert_eq!(under["over_total_cap"], false);
        assert_eq!(
            zst_under(&fx.store_dir()).len(),
            2,
            "round {round}: raising the cap did not restore both artifacts"
        );
        assert!(
            entries(&under)
                .iter()
                .all(|e| e["stored"] == true && e["source_sha256"].is_string()),
            "round {round}: a restored entry claims stored without hashes"
        );
    }
}

/// Two archive runs at once must be serialized by the write lock; the loser
/// refuses rather than interleaving two reconciliations over one store.
#[test]
fn p7_concurrent_archive_never_interleaves_reconciliation() {
    let fx = Fx::new("concurrent");
    for n in ["a", "b", "c", "d"] {
        fx.write(&format!("scratchpad/{n}.md"), b"x\n");
    }
    fx.archive();

    let mut kids: Vec<_> = (0..4)
        .map(|_| {
            Command::new(BIN)
                .args([
                    "archive",
                    "--all",
                    "--include",
                    "scratch",
                    "--json",
                    "--home",
                ])
                .arg(&fx.yomi_home)
                .env("HOME", &fx.home)
                .env("YOMI_TMP_ROOT", &fx.tmp_root)
                .env("YOMI_CACHE_HOME", &fx.cache_home)
                .env("YOMI_PROC_ROOT", &fx.proc_root)
                .env_remove("YOMI_HOME")
                .env_remove("YOMI_CLAUDE_HOME")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn archive")
        })
        .collect();
    let outs: Vec<_> = kids
        .drain(..)
        .map(|c| c.wait_with_output().unwrap())
        .collect();
    let codes: Vec<i32> = outs.iter().map(|o| o.status.code().unwrap()).collect();
    for (i, o) in outs.iter().enumerate() {
        assert!(
            [0, 2, 3].contains(&codes[i]),
            "archive #{i} exited {}: {:?}",
            codes[i],
            String::from_utf8_lossy(&o.stderr)
        );
    }
    // Whatever the interleaving, the store must still satisfy law S afterwards.
    let stored = zst_under(&fx.store_dir());
    assert_eq!(
        stored.len(),
        4,
        "after four concurrent archive runs the store holds {stored:?} instead of \
         the four artifacts the ledger claims (exit codes {codes:?})"
    );
    let claimed: Vec<String> = entries(&fx.manifest())
        .iter()
        .filter(|e| e["stored"] == true)
        .map(|e| format!("{}.zst", e["path"].as_str().unwrap()))
        .collect();
    let mut claimed_sorted = claimed.clone();
    claimed_sorted.sort();
    assert_eq!(
        stored, claimed_sorted,
        "store and ledger disagree after concurrent runs (exit codes {codes:?})"
    );
}
