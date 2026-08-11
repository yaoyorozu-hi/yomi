//! P18 break test: recursive self-ingestion.
//!
//! `archive --include scratch` walks `<tmp_root>/<slug>/<uuid>/` entire, and
//! yomi's `quarantine/` holds unredacted originals **by design**. Put the store
//! inside a walked tree — `$YOMI_HOME` and `--home` both do it in one flag — and
//! the two facts compose: run N reads run N-1's raw secrets back as ordinary
//! `*.md`/`*.json` work files, stores them one level deeper, and quarantines them
//! again. Monotonic, unbounded, and every copy keeps the original's name, so it
//! stays inside the default allow globs forever.
//!
//! Nothing but the denylist can refuse this, and the compiled-in denylist held no
//! entry for yomi's own store: the default `~/.yomi` was safe only by sitting
//! outside the three source roots by accident.
//!
//! Written to BREAK, not to confirm. Fixtures live under `CARGO_TARGET_TMPDIR`.
//!
//! **The fixture secret is the public AWS documentation example key**, which
//! authenticates nothing. Assertions name paths and counts — never file contents
//! — so a failure cannot print an original.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_yomi");
const FIXTURE_AKIA: &str = "AKIAIOSFODNN7EXAMPLE";

fn unique() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

/// A fake host whose yomi store sits **inside** the scratch tree yomi walks.
struct Fx {
    base: PathBuf,
    home: PathBuf,
    tmp_root: PathBuf,
    cache_home: PathBuf,
    slug: String,
    uuid: String,
}

impl Fx {
    fn new(tag: &str) -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "p18-{tag}-{}-{}",
            std::process::id(),
            unique()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let fx = Fx {
            home: base.join("home"),
            tmp_root: base.join("tmp"),
            cache_home: base.join("cache"),
            slug: "-home-test".to_string(),
            uuid: "s1".to_string(),
            base,
        };
        std::fs::create_dir_all(fx.home.join(".claude/projects").join(&fx.slug)).unwrap();
        std::fs::create_dir_all(&fx.cache_home).unwrap();
        std::fs::create_dir_all(fx.session_dir().join("scratchpad")).unwrap();
        std::fs::write(
            fx.session_dir().join("scratchpad/leak.md"),
            format!("aws_access_key_id = {FIXTURE_AKIA}\n"),
        )
        .unwrap();
        fx
    }

    fn session_dir(&self) -> PathBuf {
        self.tmp_root.join(&self.slug).join(&self.uuid)
    }

    /// The store, deliberately inside the tree the scratch walk enumerates.
    /// `archive` creates it, so it gets its real 700 layout.
    fn store(&self) -> PathBuf {
        self.session_dir().join("yomi")
    }

    fn scratch_store_dir(&self) -> PathBuf {
        self.store()
            .join("archive/_scratch")
            .join(format!("{}--{}", self.slug, self.uuid))
    }

    /// One `archive --include scratch` pass, as its JSON report.
    fn pass(&self) -> serde_json::Value {
        let out = Command::new(BIN)
            .args(["--json", "archive", "--all", "--include", "scratch"])
            .arg("--home")
            .arg(self.store())
            .env("HOME", &self.home)
            .env("YOMI_CLAUDE_HOME", self.home.join(".claude"))
            .env("YOMI_TMP_ROOT", &self.tmp_root)
            .env("YOMI_CACHE_HOME", &self.cache_home)
            .env_remove("YOMI_HOME")
            .output()
            .expect("run yomi");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(0), "archive failed: {stderr}");
        serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("archive --json ({e}); stderr={stderr}"))
    }

    /// Every file under the store, as store-relative paths. Paths only: the
    /// manifest carries a fresh `captured_at` and the catalog its own churn, so
    /// content equality is not the invariant — the *set of things that exist* is.
    fn store_paths(&self) -> BTreeSet<PathBuf> {
        walk(&self.store())
            .into_iter()
            .map(|p| p.strip_prefix(self.store()).unwrap().to_path_buf())
            .collect()
    }
}

fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(root) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        match std::fs::symlink_metadata(&p) {
            Ok(md) if md.is_dir() => out.extend(walk(&p)),
            Ok(_) => out.push(p),
            Err(_) => {}
        }
    }
    out.sort();
    out
}

fn count(v: &serde_json::Value, key: &str) -> u64 {
    v[key]
        .as_u64()
        .unwrap_or_else(|| panic!("report has no numeric {key}: {v}"))
}

/// The measurement: a store inside the walked tree, two passes, and the second
/// pass must take in **nothing** the first one left behind.
///
/// Before the fix the second pass stored the first pass's `manifest.json` and its
/// quarantined `leak.md`, so `findings`/`quarantined` climbed by one per pass and
/// each pass added a directory level. Both are asserted: the counts (the signal an
/// operator would see) and the file set (the bytes that would accumulate).
///
/// **Pass 2's expected counts are zero, not one, since scratch dedup landed.**
/// The planted file is unchanged, so the second pass reuses its capture and never
/// scans it — the count an operator reads is now "1 unchanged, 0 findings" rather
/// than a re-scan that finds the same secret again. The ceiling this test cares
/// about is unchanged and is now tighter: anything above zero means content was
/// scanned that the dedup predicate did not recognise, which is either
/// self-ingestion or a dedup regression. `artifacts_skipped` is asserted beside
/// the zeros so they cannot be satisfied by the file simply going unarchived.
#[test]
fn a_store_inside_the_walked_tree_is_not_ingested() {
    let fx = Fx::new("two-pass");

    let first = fx.pass();
    let after_first = fx.store_paths();
    assert!(
        after_first
            .iter()
            .any(|p| p.ends_with("_scratch/-home-test--s1/scratchpad/leak.md.zst")),
        "fixture never archived the scratch file at all: {after_first:?}"
    );
    assert_eq!(
        count(&first, "findings"),
        1,
        "pass 1 should see exactly the one planted secret"
    );
    assert_eq!(count(&first, "quarantined"), 1);
    // The store's own bookkeeping is already inside the tree by the time the walk
    // runs, so the refusal is observable on the very first pass. This is what
    // proves the *denylist* stopped the read, not a `total_cap` that happens to
    // keep a large tree manifest-only.
    assert!(
        count(&first, "blacklisted_skipped") > 0,
        "pass 1 walked the store without refusing any of it: {first}"
    );

    let second = fx.pass();
    let after_second = fx.store_paths();

    assert_eq!(
        count(&second, "artifacts_skipped"),
        1,
        "pass 2 did not reuse the capture of the one unchanged planted file, so \
         the zeros below would prove nothing: {second}"
    );
    assert_eq!(
        count(&second, "findings"),
        0,
        "pass 2 scanned content: either it read its own store, or the unchanged \
         planted file was re-captured instead of skipped: {second}"
    );
    assert_eq!(
        count(&second, "quarantined"),
        0,
        "pass 2 wrote an original to quarantine/: either it ingested the one pass \
         1 wrote, or it re-captured the unchanged planted file: {second}"
    );
    let added: Vec<&PathBuf> = after_second.difference(&after_first).collect();
    assert!(
        added.is_empty(),
        "pass 2 added files to the store: {added:?}"
    );

    // The unredacted originals are exactly one file: the planted secret. A nested
    // copy would appear here first, one directory level deeper each pass.
    let originals = walk(&fx.store().join("quarantine"));
    assert_eq!(
        originals.len(),
        1,
        "quarantine holds more than the one planted original: {originals:?}"
    );
    assert!(
        originals[0].ends_with("_scratch/-home-test--s1/scratchpad/leak.md"),
        "unexpected quarantine path: {:?}",
        originals[0]
    );

    // Nothing under the scratch store mirrors a path that runs *through* the
    // store directory — the shape every recursion level takes.
    for p in walk(&fx.scratch_store_dir()) {
        let rel = p.strip_prefix(fx.scratch_store_dir()).unwrap();
        assert!(
            !rel.components().any(|c| c.as_os_str() == "yomi"),
            "stored an artifact from inside the store itself: {rel:?}"
        );
    }

    let _ = std::fs::remove_dir_all(&fx.base);
}

/// Six passes, because the defect was *unbounded* rather than a single extra
/// copy: each pass fed the next one a deeper tree. The counts must be flat, and
/// the store must stop growing after the first pass.
///
/// Flat at zero from pass 2 on: the planted file is unchanged, so every later pass
/// reuses its capture. See the note on the two-pass test above.
#[test]
fn repeated_passes_do_not_grow_the_store() {
    let fx = Fx::new("six-pass");

    fx.pass();
    let settled = fx.store_paths();
    for pass in 2..=6 {
        let r = fx.pass();
        assert_eq!(
            count(&r, "artifacts_skipped"),
            1,
            "pass {pass}: the unchanged planted file was not skipped, so the \
             zeros below prove nothing: {r}"
        );
        assert_eq!(
            count(&r, "findings"),
            0,
            "pass {pass}: content was scanned — self-ingestion is back, or the \
             unchanged file was re-captured: {r}"
        );
        assert_eq!(count(&r, "quarantined"), 0, "pass {pass}: {r}");
        assert_eq!(
            fx.store_paths(),
            settled,
            "pass {pass} changed which files exist in the store"
        );
    }

    let _ = std::fs::remove_dir_all(&fx.base);
}
