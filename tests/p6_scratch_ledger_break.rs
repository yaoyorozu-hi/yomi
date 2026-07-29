//! P6 break tests: the scratch store and its manifest as **one ledger**.
//!
//! Store law S (design §3): for a scratch key `<K>`, the set of `*.zst` under
//! `archive/_scratch/<K>/` is exactly the set of `store_rel()` of the manifest's
//! `stored: true` entries. `archive` establishes S.
//!
//! Two rules meet here and pull in opposite directions, so most of this file is
//! about their boundary:
//!
//! * a **live** file is governed by current policy — if policy stops storing it,
//!   its `.zst` goes;
//! * a **vanished** file's entry and `.zst` are retained verbatim, marked
//!   `present: false` — that artifact is the last copy, and no cap decision
//!   authorizes destroying what was already taken.
//!
//! Also covers the enumeration widening: the writer now walks the whole session
//! dir, so a `tasks/notes.txt` or a file dropped straight in `<uuid>/` is
//! manifested instead of leaving the tree permanently unreclaimable.
//!
//! Every fixture is fabricated under `CARGO_TARGET_TMPDIR`; no real Claude Code
//! data is touched, and nothing is written outside the build tree.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_yomi");

fn unique() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
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
    fn new(tag: &str, total_cap: &str) -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "p6-{tag}-{}-{}",
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
        // `ensure_layout` refuses a store looser than 700, and the mode this dir
        // gets otherwise depends on the harness umask.
        std::fs::set_permissions(&fx.yomi_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        fx.set_total_cap(total_cap);
        fx
    }

    /// Rewrite `config.toml` with a new `total_cap`. `ScratchConfig` is
    /// `#[serde(default)]`, so the globs and `file_cap` keep their design
    /// defaults and the cap is the only variable.
    fn set_total_cap(&self, total_cap: &str) {
        std::fs::write(
            self.yomi_home.join("config.toml"),
            format!("[scratch]\ntotal_cap = \"{total_cap}\"\n"),
        )
        .unwrap();
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

    /// `archive --include scratch`, returning the run report as JSON.
    fn archive(&self) -> serde_json::Value {
        self.archive_with(&["archive", "--all", "--include", "scratch", "--json"])
    }

    fn archive_dry_run(&self) -> serde_json::Value {
        self.archive_with(&[
            "archive",
            "--all",
            "--include",
            "scratch",
            "--dry-run",
            "--json",
        ])
    }

    fn archive_with(&self, args: &[&str]) -> serde_json::Value {
        let out = self.run(args);
        let txt = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "archive failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_str(txt.trim()).unwrap_or_else(|e| {
            panic!("archive --json produced no parseable output ({e}): {txt:?}")
        })
    }

    fn manifest(&self) -> serde_json::Value {
        let p = self.store_dir().join("manifest.json");
        let txt = std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("no manifest at {}: {e}", p.display()));
        serde_json::from_str(&txt).expect("manifest json")
    }

    /// Every `*.zst` under the key's store dir, as store-relative paths.
    fn stored_zst(&self) -> Vec<String> {
        zst_under(&self.store_dir(), &self.store_dir())
    }

    /// Age every file past the 7d `min_age` floor and the 3d `scratch_retain`.
    fn age_tree(&self) {
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(200 * 86_400);
        let mut stack = vec![self.session_dir()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    filetime::set_file_mtime(&p, filetime::FileTime::from_system_time(when))
                        .unwrap();
                }
            }
        }
    }

    /// `gc --commit`, returning the number of items it reports reclaiming.
    fn gc_commit(&self) -> u64 {
        let out = self.run(&["gc", "--targets", "scratch", "--commit", "--json"]);
        let txt = String::from_utf8_lossy(&out.stdout);
        serde_json::from_str::<serde_json::Value>(txt.trim()).unwrap_or_else(|e| {
            panic!(
                "gc --json produced no parseable output ({e}); stdout={txt:?} stderr={:?}",
                String::from_utf8_lossy(&out.stderr)
            )
        })["deleted"]
            .as_u64()
            .expect("deleted field")
    }
}

fn zst_under(root: &Path, rel_to: &Path) -> Vec<String> {
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
            } else if p.extension().and_then(|x| x.to_str()) == Some("zst") {
                out.push(
                    p.strip_prefix(rel_to)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .to_string(),
                );
            }
        }
    }
    out.sort();
    out
}

fn entries(mf: &serde_json::Value) -> Vec<serde_json::Value> {
    mf["entries"].as_array().expect("entries array").clone()
}

fn entry(mf: &serde_json::Value, path: &str) -> serde_json::Value {
    mf["entries"]
        .as_array()
        .expect("entries array")
        .iter()
        .find(|e| e["path"] == path)
        .unwrap_or_else(|| panic!("no manifest entry for {path}; manifest={mf:#}"))
        .clone()
}

/// Law S, checked against the fixture's own store: the `.zst` on disk are
/// exactly the `stored: true` entries' `<path>.zst`.
fn assert_law_s(fx: &Fx) {
    let mf = fx.manifest();
    let mut claimed: Vec<String> = entries(&mf)
        .iter()
        .filter(|e| e["stored"] == true)
        .map(|e| format!("{}.zst", e["path"].as_str().unwrap()))
        .collect();
    claimed.sort();
    assert_eq!(
        fx.stored_zst(),
        claimed,
        "store law S violated: the .zst on disk are not exactly what the manifest \
         claims. manifest={mf:#}"
    );
}

// ---------------------------------------------------------------------------
// A. Reconciliation — a policy change may not leave the ledger denying its store.
// ---------------------------------------------------------------------------

/// The measured N1 defect, verbatim: archive under a generous cap, lower the cap,
/// re-archive. The previous run's `.zst` used to stay on disk while the new
/// manifest declared `over_total_cap: true` and every entry `stored: false` — a
/// store holding a faithful copy that yomi's own ledger denied, after which GC
/// deleted the live tree on the size-only path.
#[test]
fn p6_lowering_the_cap_reconciles_the_store() {
    let fx = Fx::new("cap-down", "1MB");
    fx.write("scratchpad/a.md", &[b'A'; 801]);
    fx.write("scratchpad/b.md", &[b'B'; 801]);

    let r = fx.archive();
    assert_eq!(
        fx.stored_zst(),
        vec!["scratchpad/a.md.zst", "scratchpad/b.md.zst"],
        "fixture did not store both files under the generous cap"
    );
    assert_eq!(r["scratch_orphans_removed"], 0, "nothing to reconcile yet");
    assert_law_s(&fx);

    fx.set_total_cap("1KB");
    let r = fx.archive();

    let mf = fx.manifest();
    assert_eq!(mf["over_total_cap"], true, "cap was not applied: {mf:#}");
    assert!(
        entries(&mf).iter().all(|e| e["stored"] == false),
        "an over-cap tree still claims stored entries: {mf:#}"
    );
    assert_eq!(
        fx.stored_zst(),
        Vec::<String>::new(),
        "the previous run's artifacts survived a cap the manifest says stores \
         nothing — the store holds bytes the ledger denies"
    );
    assert_eq!(
        r["scratch_orphans_removed"], 2,
        "the discarded artifacts were not reported; a config change that drops \
         stored bytes must be loud. report={r:#}"
    );
    assert_law_s(&fx);
}

/// Reconciliation is driven by the manifest, not by the cap: a file that becomes
/// deny-listed loses its artifact while its still-stored siblings keep theirs.
#[test]
fn p6_denying_one_file_removes_only_its_artifact() {
    let fx = Fx::new("deny-one", "1MB");
    fx.write("scratchpad/keep.md", b"keep\n");
    fx.write("scratchpad/drop.md", b"drop\n");
    fx.archive();
    assert_eq!(
        fx.stored_zst(),
        vec!["scratchpad/drop.md.zst", "scratchpad/keep.md.zst"]
    );

    std::fs::write(
        fx.yomi_home.join("config.toml"),
        "[scratch]\ntotal_cap = \"1MB\"\ndeny = [\"drop.md\"]\n",
    )
    .unwrap();
    let r = fx.archive();

    assert_eq!(fx.stored_zst(), vec!["scratchpad/keep.md.zst"]);
    assert_eq!(r["scratch_orphans_removed"], 1);
    assert_eq!(entry(&fx.manifest(), "scratchpad/drop.md")["stored"], false);
    assert_law_s(&fx);
}

/// The delete authority is `*.zst` under **this key's** store dir and nothing
/// else. Everything planted around it must survive a reconciliation that does
/// remove something.
#[test]
fn p6_reconciliation_authority_is_bounded() {
    let fx = Fx::new("bounds", "1MB");
    fx.write("scratchpad/a.md", &[b'A'; 801]);
    fx.write("scratchpad/b.md", &[b'B'; 801]);
    fx.archive();
    assert_eq!(fx.stored_zst().len(), 2);

    // Neighbours: another scratch key, the archive root, a quarantined original,
    // and a non-`.zst` file inside this very store dir.
    let other_key = fx.yomi_home.join("archive/_scratch/-other--key");
    std::fs::create_dir_all(&other_key).unwrap();
    std::fs::write(other_key.join("innocent.zst"), b"other key").unwrap();
    let archive_root_zst = fx.yomi_home.join("archive/loose.zst");
    std::fs::write(&archive_root_zst, b"archive root").unwrap();
    let quarantined = fx.yomi_home.join("quarantine/_scratch--x/raw.zst");
    std::fs::create_dir_all(quarantined.parent().unwrap()).unwrap();
    std::fs::write(&quarantined, b"quarantined original").unwrap();
    let sidecar = fx.store_dir().join("scratchpad/notes.txt");
    std::fs::write(&sidecar, b"not an artifact").unwrap();

    fx.set_total_cap("1KB");
    let r = fx.archive();
    assert_eq!(
        r["scratch_orphans_removed"], 2,
        "the reconciliation under test did not actually remove anything"
    );

    for survivor in [
        &other_key.join("innocent.zst"),
        &archive_root_zst,
        &quarantined,
        &sidecar,
        &fx.store_dir().join("manifest.json"),
    ] {
        assert!(
            survivor.exists(),
            "reconciliation reached {} — the delete authority is not bounded to \
             *.zst under one key's store dir",
            survivor.display()
        );
    }
}

/// `--dry-run` must preview the removals and perform none of them, and must not
/// rewrite the manifest either.
#[test]
fn p6_dry_run_previews_without_removing() {
    let fx = Fx::new("dry", "1MB");
    fx.write("scratchpad/a.md", &[b'A'; 801]);
    fx.write("scratchpad/b.md", &[b'B'; 801]);
    fx.archive();
    let before = fx.manifest();

    fx.set_total_cap("1KB");
    let r = fx.archive_dry_run();

    assert_eq!(
        r["scratch_orphans_removed"], 2,
        "dry-run did not report the removals it would make: {r:#}"
    );
    assert_eq!(
        fx.stored_zst(),
        vec!["scratchpad/a.md.zst", "scratchpad/b.md.zst"],
        "--dry-run deleted stored artifacts"
    );
    assert_eq!(fx.manifest(), before, "--dry-run rewrote the manifest");
}

// ---------------------------------------------------------------------------
// B. A vanished file keeps its archive.
// ---------------------------------------------------------------------------

/// The counterweight to reconciliation. An entry whose live file is gone is the
/// one case where the store holds the *only* remaining copy, so it is retained
/// verbatim — record, hashes and `.zst` — and marked `present: false`.
#[test]
fn p6_vanished_file_keeps_its_entry_and_artifact() {
    let fx = Fx::new("vanish", "1MB");
    fx.write("scratchpad/stays.md", b"stays\n");
    let gone = fx.write("scratchpad/gone.md", b"gone forever\n");
    fx.archive();
    let before = entry(&fx.manifest(), "scratchpad/gone.md");
    assert_eq!(before["stored"], true);

    std::fs::remove_file(&gone).unwrap();
    let r = fx.archive();

    assert!(
        fx.store_dir().join("scratchpad/gone.md.zst").exists(),
        "archive destroyed the last remaining copy of a file that merely left \
         the live tree"
    );
    assert_eq!(
        r["scratch_orphans_removed"], 0,
        "a retained entry's artifact was counted as an orphan: {r:#}"
    );

    let mf = fx.manifest();
    let after = entry(&mf, "scratchpad/gone.md");
    assert_eq!(after["present"], false, "retained entry not marked: {mf:#}");
    assert_eq!(after["stored"], before["stored"]);
    assert_eq!(after["bytes"], before["bytes"]);
    assert_eq!(after["source_sha256"], before["source_sha256"]);
    assert_eq!(after["content_sha256"], before["content_sha256"]);

    // A live entry carries no `present` field at all, so an all-live tree
    // serializes exactly as it did before the field existed.
    assert!(
        entry(&mf, "scratchpad/stays.md").get("present").is_none(),
        "a live entry emitted a `present` field: {mf:#}"
    );
    // The retained entry belongs to no live tree, so it is outside the cap.
    assert_eq!(
        mf["total_bytes"].as_u64(),
        Some(6),
        "a vanished file's bytes were counted against the live tree: {mf:#}"
    );
    assert_law_s(&fx);
}

/// The two rules at their sharpest: one file vanishes, and the cap is then
/// lowered so the *live* remainder is no longer stored. Policy applies to the
/// live file only; the archive-only copy is untouched.
#[test]
fn p6_cap_change_does_not_destroy_an_archive_only_copy() {
    let fx = Fx::new("both", "1MB");
    fx.write("scratchpad/live.md", &[b'L'; 801]);
    let gone = fx.write("scratchpad/gone.md", &[b'G'; 801]);
    fx.archive();
    assert_eq!(fx.stored_zst().len(), 2);

    std::fs::remove_file(&gone).unwrap();
    fx.set_total_cap("1B");
    let r = fx.archive();

    assert_eq!(
        fx.stored_zst(),
        vec!["scratchpad/gone.md.zst"],
        "the cap change either kept the live file's artifact or destroyed the \
         archive-only one"
    );
    assert_eq!(r["scratch_orphans_removed"], 1);
    let mf = fx.manifest();
    assert_eq!(mf["over_total_cap"], true);
    assert_eq!(entry(&mf, "scratchpad/live.md")["stored"], false);
    let retained = entry(&mf, "scratchpad/gone.md");
    assert_eq!(retained["stored"], true);
    assert_eq!(retained["present"], false);
    assert_law_s(&fx);
}

/// A tree that empties out **completely** is the strongest case of the retention
/// rule, and the easiest place to leave a hole: a writer that skips file-less
/// trees as "nothing to do" never records that the files went, so the manifest
/// keeps claiming them present while their `.zst` sit in the store with nothing
/// left to correct the record.
#[test]
fn p6_tree_emptied_completely_still_records_the_absence() {
    let fx = Fx::new("emptied", "1MB");
    let a = fx.write("scratchpad/a.md", b"a\n");
    let b = fx.write("tasks/run.output", b"b\n");
    fx.archive();
    assert_eq!(fx.stored_zst().len(), 2);

    std::fs::remove_file(&a).unwrap();
    std::fs::remove_file(&b).unwrap();
    let r = fx.archive();

    let mf = fx.manifest();
    assert_eq!(
        entries(&mf).len(),
        2,
        "an emptied tree lost its records: {mf:#}"
    );
    assert!(
        entries(&mf).iter().all(|e| e["present"] == false),
        "the tree holds no file, yet the manifest still claims its entries are \
         present: {mf:#}"
    );
    assert_eq!(fx.stored_zst().len(), 2, "the last copies were destroyed");
    assert_eq!(r["scratch_orphans_removed"], 0);
    assert_eq!(mf["total_bytes"].as_u64(), Some(0));
    assert_law_s(&fx);
}

/// A retained entry is not permanent: if the file comes back, the live pass
/// governs it again under current policy and the ledger keeps one record.
#[test]
fn p6_reappearing_file_replaces_its_retained_entry() {
    let fx = Fx::new("return", "1MB");
    let f = fx.write("scratchpad/blink.md", b"first\n");
    fx.archive();
    std::fs::remove_file(&f).unwrap();
    fx.archive();
    assert_eq!(
        entry(&fx.manifest(), "scratchpad/blink.md")["present"],
        false
    );

    fx.write("scratchpad/blink.md", b"second content\n");
    fx.archive();

    let mf = fx.manifest();
    let matching: Vec<_> = entries(&mf)
        .into_iter()
        .filter(|e| e["path"] == "scratchpad/blink.md")
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "a reappearing file left two records for one identity: {mf:#}"
    );
    assert!(
        matching[0].get("present").is_none(),
        "the reappeared file is still marked absent: {mf:#}"
    );
    assert_eq!(matching[0]["bytes"], 15);
    assert_law_s(&fx);
}

// ---------------------------------------------------------------------------
// C. Enumeration is the whole session dir.
// ---------------------------------------------------------------------------

/// The writer used to enumerate `scratchpad/**` and `tasks/*.output` only, while
/// the deleter removed `<slug>/<uuid>/` entire. Anything else in the tree was
/// therefore unmanifested, and the GC gate refuses a tree holding a live file it
/// cannot account for — permanently, through any number of archive/GC cycles.
#[test]
fn p6_whole_session_tree_is_manifested_and_reclaimable() {
    let fx = Fx::new("widen", "1MB");
    fx.write("scratchpad/a.md", b"scratchpad file\n");
    fx.write("tasks/run.output", b"task output\n");
    fx.write("tasks/notes.txt", b"not a .output\n");
    fx.write("loose.md", b"dropped straight in the session dir\n");
    fx.write("nested/deep/other.log", b"nested\n");

    fx.archive();
    let mf = fx.manifest();
    let paths: Vec<String> = entries(&mf)
        .iter()
        .map(|e| e["path"].as_str().unwrap().to_string())
        .collect();
    for expected in [
        "scratchpad/a.md",
        "tasks/run.output",
        "tasks/notes.txt",
        "loose.md",
        "nested/deep/other.log",
    ] {
        assert!(
            paths.iter().any(|p| p == expected),
            "{expected} is not in the manifest, so the GC gate can never account \
             for it: {mf:#}"
        );
    }
    assert_law_s(&fx);

    fx.age_tree();
    assert_eq!(
        fx.gc_commit(),
        1,
        "a tree whose every file is manifested was still not reclaimed"
    );
    assert!(
        !fx.session_dir().exists(),
        "the scratch tree is still on disk at {}",
        fx.session_dir().display()
    );
}

/// The `tasks/*.output` rule was a second, hardcoded filter that only the writer
/// applied. It is now the `[scratch]` globs' business, which means it is
/// configurable and identical for every path in the tree.
#[test]
fn p6_extension_filtering_lives_in_the_globs() {
    let fx = Fx::new("globs", "1MB");
    fx.write("tasks/run.output", b"output\n");
    fx.write("tasks/notes.txt", b"txt\n");
    fx.write("tasks/binary.bin", b"bin\n");
    fx.archive();

    let mf = fx.manifest();
    // `*.output` and `*.txt` are in the default allow set; `**/*.bin` is denied.
    assert_eq!(entry(&mf, "tasks/run.output")["stored"], true);
    assert_eq!(
        entry(&mf, "tasks/notes.txt")["stored"],
        true,
        "a non-.output file under tasks/ is now governed by the allow globs like \
         anything else: {mf:#}"
    );
    assert_eq!(entry(&mf, "tasks/binary.bin")["stored"], false);
    assert_law_s(&fx);

    // A deny glob added by config reaches tasks/ exactly as it reaches
    // scratchpad/ — one rule set, one path space.
    std::fs::write(
        fx.yomi_home.join("config.toml"),
        "[scratch]\ntotal_cap = \"1MB\"\ndeny = [\"*.txt\"]\n",
    )
    .unwrap();
    let r = fx.archive();
    assert_eq!(entry(&fx.manifest(), "tasks/notes.txt")["stored"], false);
    assert_eq!(r["scratch_orphans_removed"], 1);
    assert_law_s(&fx);
}

/// Repeated archive runs over an unchanged tree must converge: no orphans, no
/// growth, no churn in the ledger.
#[test]
fn p6_repeated_archive_is_idempotent() {
    let fx = Fx::new("idem", "1MB");
    fx.write("scratchpad/a.md", b"a\n");
    fx.write("tasks/run.output", b"o\n");
    fx.write("loose.md", b"l\n");

    fx.archive();
    let first = fx.manifest();
    for round in 0..3 {
        let r = fx.archive();
        assert_eq!(
            r["scratch_orphans_removed"], 0,
            "round {round} removed artifacts from an unchanged tree: {r:#}"
        );
        let mf = fx.manifest();
        assert_eq!(
            entries(&mf),
            entries(&first),
            "round {round} changed the ledger for an unchanged tree"
        );
        assert_law_s(&fx);
    }
}
