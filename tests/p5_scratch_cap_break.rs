//! P5 break tests: the `over_total_cap` scratch tree.
//!
//! Design §3, "Scratch (the 134M trap)", makes over-cap trees **manifest-only +
//! flag**: contents are deliberately not hoarded, the `over_total_cap` flag
//! records why, and the GC gate's size-only path is the intended assurance —
//! "Nothing about it is lost except bytes we deliberately declined to hoard."
//! Reclaiming the 134M scratch clone is the P2 done-when criterion, in §9's
//! "Phases (each with a hard done-when)".
//!
//! The archive writer instead marks every entry `stored: true` while writing no
//! `.zst` and no hashes, and the GC gate refuses a stored entry with no hashes.
//! The over-cap tree — precisely the case the cap exists for — is therefore never
//! reclaimed, by any number of archive/GC cycles.
//!
//! These tests assert the TARGET state, so they fail until over-cap entries are
//! written `stored: false`. Two of them pass today and must keep passing: they
//! pin the flag the fix depends on, and a control tree that differs only in
//! staying under the cap.
//!
//! Every fixture is fabricated under `CARGO_TARGET_TMPDIR`; no real Claude Code
//! data is touched, and nothing is written outside the build tree.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_yomi");

/// Total bytes of the fixture tree below. Both caps are expressed relative to
/// this so the test never depends on a real 134M checkout.
const TREE_BYTES: u64 = 2 * 801;

struct Fx {
    home: PathBuf,
    yomi_home: PathBuf,
    tmp_root: PathBuf,
    cache_home: PathBuf,
    proc_root: PathBuf,
    slug: String,
    uuid: String,
}

fn unique() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

impl Fx {
    /// `total_cap` is written into `config.toml`; `ScratchConfig` is
    /// `#[serde(default)]`, so the allow/deny globs and `file_cap` keep their
    /// design defaults and the cap is the only variable between fixtures.
    fn new(tag: &str, total_cap: &str) -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "p5-{tag}-{}-{}",
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
        std::fs::write(
            fx.yomi_home.join("config.toml"),
            format!("[scratch]\ntotal_cap = \"{total_cap}\"\n"),
        )
        .unwrap();

        // Two allow-listed files, each well under the 5MB `file_cap`, together
        // over a cap set below TREE_BYTES. Only the cap decides `over_total_cap`.
        let pad = fx.session_dir().join("scratchpad");
        std::fs::create_dir_all(&pad).unwrap();
        std::fs::write(pad.join("a.md"), format!("{}\n", "A".repeat(800))).unwrap();
        std::fs::write(pad.join("b.md"), format!("{}\n", "B".repeat(800))).unwrap();
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

    fn manifest_after_archive(&self) -> serde_json::Value {
        self.archive();
        self.manifest()
    }

    fn archived_zst_count(&self) -> usize {
        self.archive();
        self.stored_zst_count()
    }

    fn manifest(&self) -> serde_json::Value {
        let p = self.store_dir().join("manifest.json");
        let txt = std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("no manifest at {}: {e}", p.display()));
        serde_json::from_str(&txt).expect("manifest json")
    }

    fn stored_zst_count(&self) -> usize {
        let mut n = 0;
        let mut stack = vec![self.store_dir()];
        while let Some(d) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().and_then(|x| x.to_str()) == Some("zst") {
                    n += 1;
                }
            }
        }
        n
    }
}

/// Cap below the tree size — the over-cap case.
fn over_cap(tag: &str) -> Fx {
    Fx::new(tag, "1KB")
}

/// Cap above the tree size — byte-identical tree, cap is the only difference.
fn under_cap(tag: &str) -> Fx {
    Fx::new(tag, "1MB")
}

// ---------------------------------------------------------------------------
// Preconditions of the fix. These pass today and must keep passing.
// ---------------------------------------------------------------------------

/// The proposed fix reads `over_total_cap` to justify writing `stored: false`.
/// That flag must actually be recorded — and it is.
#[test]
fn p5_over_cap_manifest_records_the_flag() {
    let fx = over_cap("flag");
    fx.archive();
    let mf = fx.manifest();
    assert_eq!(
        mf["over_total_cap"], true,
        "over_total_cap was not recorded for a {TREE_BYTES}-byte tree under a 1KB \
         cap; the fix has no flag to key off. manifest={mf:#}"
    );
    assert_eq!(
        mf["total_bytes"].as_u64(),
        Some(TREE_BYTES),
        "manifest total_bytes disagrees with the fixture"
    );
    assert_eq!(
        under_cap("flag-ctl").manifest_after_archive()["over_total_cap"],
        false,
        "the same tree under a larger cap must not be flagged"
    );
}

/// Over-cap trees deliberately store nothing. This is the ratified trade
/// (design §3: "Nothing about it is lost except bytes we deliberately declined
/// to hoard"), and it is what makes the reclaim below a delete of unarchived
/// data — by design, not by accident. Recorded here so the fix cannot be read
/// as merely cosmetic.
#[test]
fn p5_over_cap_tree_stores_no_bytes() {
    let fx = over_cap("nobytes");
    fx.archive();
    assert_eq!(
        fx.stored_zst_count(),
        0,
        "an over-cap tree wrote stored artifacts; the premise of this file is wrong"
    );
    assert_eq!(
        under_cap("nobytes-ctl").archived_zst_count(),
        2,
        "the same tree under a larger cap must store both files"
    );
}

/// Control: byte-identical tree, cap not exceeded, reclaimed normally. Isolates
/// the cap as the sole trigger and proves the fixture and harness are sound —
/// without this, the failures below could be a broken fixture.
#[test]
fn p5_under_cap_control_tree_is_reclaimed() {
    let fx = under_cap("control");
    fx.archive();
    fx.age_tree();
    assert_eq!(fx.gc_commit(), 1, "control tree was not reclaimed");
    assert!(
        !fx.session_dir().exists(),
        "control tree still on disk after a reported reclaim"
    );
}

// ---------------------------------------------------------------------------
// The defect. These fail until over-cap entries are written `stored: false`.
// ---------------------------------------------------------------------------

/// A manifest entry claiming `stored: true` asserts that a verifiable artifact
/// was written. For an over-cap tree no `.zst` and no hashes exist, so the
/// manifest is internally inconsistent — and it is that inconsistency, not the
/// cap itself, that the GC gate trips over.
#[test]
fn p5_over_cap_manifest_never_claims_stored_without_hashes() {
    let fx = over_cap("consistency");
    fx.archive();
    let mf = fx.manifest();
    let liars: Vec<String> = mf["entries"]
        .as_array()
        .expect("entries array")
        .iter()
        .filter(|e| e["stored"] == true)
        .filter(|e| e["source_sha256"].as_str().is_none() || e["content_sha256"].as_str().is_none())
        .map(|e| e.to_string())
        .collect();
    assert!(
        liars.is_empty(),
        "{} manifest entries claim `stored: true` with no hashes and no stored \
         bytes ({} .zst files on disk). An unstorable entry must be recorded \
         `stored: false`; `over_total_cap: {}` already records why. Offending \
         entries: {liars:#?}",
        liars.len(),
        fx.stored_zst_count(),
        mf["over_total_cap"]
    );
}

/// The P2 done-when: "reclaims the 134M scratch clone" (§9, "Phases (each with a
/// hard done-when)").
/// An over-cap tree is aged, non-live, and manifested — every condition the
/// design places on a scratch reclaim — and must be reclaimed on the size-only
/// path.
#[test]
fn p5_over_cap_scratch_tree_is_reclaimed() {
    let fx = over_cap("reclaim");
    fx.archive();
    fx.age_tree();

    let deleted = fx.gc_commit();
    assert_eq!(
        deleted, 1,
        "the over-cap scratch tree was not reclaimed (gc reported {deleted} \
         deletions). This is the P2 done-when criterion, and the over-cap tree \
         is exactly the case the cap exists for."
    );
    assert!(
        !fx.session_dir().exists(),
        "the over-cap scratch tree is still on disk at {}",
        fx.session_dir().display()
    );
}

/// The claim is permanence, not a one-off skip: the manifest is regenerated in
/// the same shape on every archive, so no number of archive/GC cycles ever
/// reclaims the tree. Three full cycles here — if the tree is still present
/// after the last one, it is unreclaimable, not merely skipped once.
#[test]
fn p5_over_cap_tree_is_not_permanently_unreclaimable() {
    let fx = over_cap("permanence");
    let mut reports = Vec::new();
    for _ in 0..3 {
        fx.archive();
        fx.age_tree();
        reports.push(fx.gc_commit());
        if !fx.session_dir().exists() {
            break;
        }
    }
    assert!(
        !fx.session_dir().exists(),
        "the over-cap tree survived three full archive+GC cycles (deletions per \
         cycle: {reports:?}); re-archiving regenerates the identical manifest, so \
         the tree is permanently unreclaimable rather than transiently skipped"
    );
}
