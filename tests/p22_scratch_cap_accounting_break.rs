//! P22 break tests: what `[scratch] total_cap` counts, and where its default sits.
//!
//! Decision #9. The cap used to sum **every** live candidate, so the build output
//! and `.git` trees the `deny` globs exist to refuse were what carried a tree over
//! it — and an over-cap tree stores nothing, including the few MB it would have
//! stored. Measured on this host before the fix: three of four trees over the cap,
//! one of them with a would-store set of **0 bytes**, and the largest tree's
//! 21.7MB of admitted files dropped by a 20MB cap it exceeded only on bytes nobody
//! proposed to keep.
//!
//! The cap now compares the **admitted** subset — the candidates with no
//! `not_stored` cause — and the default rose 20MB → 64MB with it, because 20 was a
//! number chosen against whole-tree totals and the largest admitted tree measured
//! here would still have stored nothing at it. Both changes are one decision: the
//! accounting fix is what makes 20MB the wrong number.
//!
//! What must not move, and is pinned here: `file_cap` (5MB, per file), the recorded
//! `not_stored` causes and their evaluation order, the `over_total_cap` flag, and
//! `--full` lifting both caps.
//!
//! Every fixture is fabricated under `CARGO_TARGET_TMPDIR` and removed when the
//! fixture drops. No real Claude Code data, no `~/.yomi`, no `/tmp` (issue #48).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_yomi");

/// The mixed tree below, by role. Admitted: `notes.md` + `run.output`. Refused by
/// the globs: a `target/` fingerprint (allow-matched *and* deny-matched, the only
/// route to `Denied`) and a file with no allowed extension.
const NOTES: usize = 2_000;
const OUTPUT: usize = 500;
const DENIED: usize = 40_000;
const NOT_ALLOWED: usize = 30_000;
const ADMITTED: u64 = (NOTES + OUTPUT) as u64;
const RAW: u64 = (NOTES + OUTPUT + DENIED + NOT_ALLOWED) as u64;

/// Six files of this size: 22,020,096 B admitted — over the old 20MB default,
/// comfortably under the 64MB one. Each is under the 5MB `file_cap`, so only the
/// tree cap can decide the tree.
const MID_FILE: usize = 3_670_016;
const MID_FILES: usize = 6;

/// Fourteen files of this size: 68,600,000 B admitted, over the 64MB default.
/// Each is under `file_cap` for the same reason.
const BIG_FILE: usize = 4_900_000;
const BIG_FILES: usize = 14;

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
    uuid: String,
}

/// The fixture removes its own tree. A `remove_dir_all` placed *before* the
/// fixture is built — the shape elsewhere in this suite — is a no-op that leaves
/// every run's directories behind (issue #48).
impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

impl Fx {
    /// A fixture with no `config.toml` at all, so `[scratch]` is exactly the
    /// design default — the only way to test what the default *is*.
    fn new(tag: &str) -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "p22-{tag}-{}-{}",
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
        // `ensure_layout` refuses a store looser than 700, and the mode this dir
        // gets otherwise depends on the harness umask.
        std::fs::set_permissions(&fx.yomi_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        fx
    }

    fn with_total_cap(tag: &str, total_cap: &str) -> Self {
        let fx = Fx::new(tag);
        fx.set_total_cap(total_cap);
        fx
    }

    /// `ScratchConfig` is `#[serde(default)]`, so the globs and `file_cap` keep
    /// their design values and the tree cap is the only variable.
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

    fn key(&self) -> String {
        format!("{}--{}", self.slug, self.uuid)
    }

    fn store_dir(&self) -> PathBuf {
        self.yomi_home.join("archive/_scratch").join(self.key())
    }

    fn write(&self, rel: &str, bytes: &[u8]) {
        let p = self.session_dir().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
    }

    /// Two admitted files beside two the globs refuse, the refused ones an order
    /// of magnitude larger. Whole-tree accounting reads this tree as 72,500 B;
    /// would-store accounting reads it as 2,500 B.
    fn write_mixed_tree(&self) {
        self.write("scratchpad/notes.md", &vec![b'N'; NOTES]);
        self.write("tasks/run.output", &vec![b'O'; OUTPUT]);
        self.write("target/debug/fingerprint.json", &vec![b'F'; DENIED]);
        self.write("payload.dat", &vec![b'P'; NOT_ALLOWED]);
    }

    /// `n` admitted files of `size`, each under `file_cap`.
    fn write_admitted_files(&self, n: usize, size: usize) {
        let bytes = vec![b'A'; size];
        for i in 0..n {
            self.write(&format!("scratchpad/f{i}.md"), &bytes);
        }
    }

    fn run(&self, args: &[&str]) -> Out {
        let o = Command::new(BIN)
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
            .expect("run yomi");
        Out {
            code: o.status.code().unwrap(),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }

    fn archive(&self, args: &[&str]) {
        let mut v = vec!["archive", "--all", "--include", "scratch"];
        v.extend_from_slice(args);
        let out = self.run(&v);
        assert_eq!(out.code, 0, "archive {args:?} failed: {}", out.summary());
    }

    /// The multi-MB fixtures archive with `--no-scan`: the secret scanner reads
    /// every stored byte through its regex set, which is ~1s/MB in a debug build
    /// and has nothing to do with what a cap counts. The cap decision, the
    /// manifest and the store writes are identical either way.
    fn archive_unscanned(&self, args: &[&str]) {
        let mut v = vec!["--no-scan"];
        v.extend_from_slice(args);
        self.archive(&v);
    }

    fn manifest(&self) -> serde_json::Value {
        let p = self.store_dir().join("manifest.json");
        let txt = std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("no manifest at {}: {e}", p.display()));
        serde_json::from_str(&txt).expect("manifest json")
    }

    /// Every `*.zst` under the key's store dir, store-relative and sorted.
    fn stored_zst(&self) -> Vec<String> {
        let root = self.store_dir();
        let mut out = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(d) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else {
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
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(self.stdout.trim())
            .unwrap_or_else(|e| panic!("not json ({e}): {}", self.summary()))
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

fn entries(mf: &serde_json::Value) -> Vec<serde_json::Value> {
    mf["entries"].as_array().expect("entries array").clone()
}

fn entry(mf: &serde_json::Value, path: &str) -> serde_json::Value {
    entries(mf)
        .into_iter()
        .find(|e| e["path"] == path)
        .unwrap_or_else(|| panic!("no manifest entry for {path}; manifest={mf:#}"))
}

// ---------------------------------------------------------------------------
// A. What the cap counts.
// ---------------------------------------------------------------------------

/// **The defect, and the fix.** The raw tree is 72,500 B against an 8KB cap; the
/// bytes it would store are 2,500 B. Under whole-tree accounting this tree stored
/// nothing at all — suppressed by a `target/` directory the `deny` globs had
/// already refused — and it bought nothing, because a `stored: false` entry takes
/// the GC gate's presence+size path whichever rule wrote it.
#[test]
fn p22_a_the_cap_counts_only_the_bytes_it_would_store() {
    let fx = Fx::with_total_cap("would-store", "8KB");
    fx.write_mixed_tree();

    fx.archive(&[]);

    let mf = fx.manifest();
    assert_eq!(
        mf["over_total_cap"], false,
        "a tree whose admitted bytes are {ADMITTED} was declined by an 8KB cap; the \
         cap is still counting bytes it would never store: {mf:#}"
    );
    assert_eq!(
        fx.stored_zst(),
        vec!["scratchpad/notes.md.zst", "tasks/run.output.zst"],
        "the admitted files were not stored: {mf:#}"
    );
    assert_eq!(
        mf["admitted_bytes"].as_u64(),
        Some(ADMITTED),
        "the cap's own quantity is misrecorded: {mf:#}"
    );
    assert_eq!(
        mf["total_bytes"].as_u64(),
        Some(RAW),
        "total_bytes stopped being the tree's footprint: {mf:#}"
    );
    // The globs still decide what is stored, and still say which one did.
    for (path, cause) in [
        ("target/debug/fingerprint.json", "denied"),
        ("payload.dat", "not_allowed"),
    ] {
        let e = entry(&mf, path);
        assert_eq!(e["stored"], false, "{path} was stored: {mf:#}");
        assert_eq!(e["not_stored"], cause, "the cause moved for {path}: {mf:#}");
    }
}

/// The other side of the same rule: a tree whose *admitted* set is over the cap is
/// still manifest-only. Nothing about the cliff softens — only the quantity it is
/// measured on changes.
#[test]
fn p22_a_an_admitted_set_over_the_cap_still_stores_nothing() {
    let fx = Fx::with_total_cap("over-admitted", "2KB");
    fx.write_mixed_tree();

    fx.archive(&[]);

    let mf = fx.manifest();
    assert_eq!(
        mf["over_total_cap"], true,
        "an admitted set of {ADMITTED} B was not declined by a 2KB cap: {mf:#}"
    );
    assert_eq!(
        fx.stored_zst(),
        Vec::<String>::new(),
        "an over-cap tree stored bytes: {mf:#}"
    );
    assert!(
        entries(&mf).iter().all(|e| e["stored"] == false),
        "an over-cap tree still claims a stored entry: {mf:#}"
    );
    assert_eq!(mf["admitted_bytes"].as_u64(), Some(ADMITTED));
    assert_eq!(mf["total_bytes"].as_u64(), Some(RAW));
    // The tree cap flips `stored`; it does not overwrite what the globs decided.
    // A reader explaining `payload.dat` must still be told it was never admitted,
    // or widening the cap looks like the remedy for it.
    assert_eq!(entry(&mf, "payload.dat")["not_stored"], "not_allowed");
    assert_eq!(
        entry(&mf, "target/debug/fingerprint.json")["not_stored"],
        "denied"
    );
    assert!(
        entry(&mf, "scratchpad/notes.md")
            .get("not_stored")
            .is_none(),
        "the tree cap wrote a per-file cause for a file no per-file rule \
         declined: {mf:#}"
    );
}

/// `file_cap` is untouched by this change — 5MB, per file — and a file it declines
/// is a file the run would not store, so its bytes stay out of the admitted total.
/// A 6MB file beside 2,000 B of notes therefore leaves an 8KB tree cap unbothered.
#[test]
fn p22_a_a_file_over_file_cap_counts_out_of_the_admitted_total() {
    let fx = Fx::with_total_cap("file-cap", "8KB");
    fx.write("scratchpad/notes.md", &vec![b'N'; NOTES]);
    fx.write("scratchpad/huge.md", &vec![b'H'; 6 * 1024 * 1024]);

    fx.archive(&[]);

    let mf = fx.manifest();
    assert_eq!(
        entry(&mf, "scratchpad/huge.md")["not_stored"],
        "file_cap",
        "the default file_cap no longer declines a 6MB file; this PR moves \
         total_cap only: {mf:#}"
    );
    assert_eq!(
        mf["over_total_cap"], false,
        "bytes file_cap declined were counted against the tree cap: {mf:#}"
    );
    assert_eq!(mf["admitted_bytes"].as_u64(), Some(NOTES as u64));
    assert_eq!(
        fx.stored_zst(),
        vec!["scratchpad/notes.md.zst"],
        "the admitted file was not stored: {mf:#}"
    );
}

// ---------------------------------------------------------------------------
// B. Where the default sits.
// ---------------------------------------------------------------------------

/// The default is 64MB, and `file_cap` beside it is unchanged at 5MB. Read off the
/// resolved config with no `config.toml` present, which is the only place the
/// default itself is observable.
#[test]
fn p22_b_the_default_caps_are_64mb_and_5mb() {
    let fx = Fx::new("defaults");
    let out = fx.run(&["config", "get", "--json"]);
    assert_eq!(out.code, 0, "config get failed: {}", out.summary());
    let cfg = out.json();
    assert_eq!(
        cfg["scratch"]["total_cap"], "67108864",
        "the default total_cap is not 64MB: {cfg:#}"
    );
    assert_eq!(
        cfg["scratch"]["file_cap"], "5242880",
        "the default file_cap moved; this PR raises total_cap only: {cfg:#}"
    );
}

/// **Why the default moved with the accounting.** 22,020,096 B of admitted content
/// is over the old 20MB default and under the new one, so the same tree that the
/// accounting fix hands to the cap intact is a tree 20MB would still have refused
/// in full. The second half of the test is the control: the raise is load-bearing,
/// not decorative.
#[test]
fn p22_b_the_default_admits_a_tree_the_old_default_refused() {
    let fx = Fx::new("raised-default");
    fx.write_admitted_files(MID_FILES, MID_FILE);
    let admitted = (MID_FILES * MID_FILE) as u64;

    fx.archive_unscanned(&[]);

    let mf = fx.manifest();
    assert_eq!(
        mf["admitted_bytes"].as_u64(),
        Some(admitted),
        "fixture is not the size this test reasons about: {mf:#}"
    );
    assert!(
        admitted > 20 * 1024 * 1024 && admitted < 64 * 1024 * 1024,
        "fixture no longer sits between the old and new defaults ({admitted} B)"
    );
    assert_eq!(
        mf["over_total_cap"], false,
        "the default cap refused a {admitted}-byte admitted set: {mf:#}"
    );
    assert_eq!(
        fx.stored_zst().len(),
        MID_FILES,
        "the default cap stored {} of {MID_FILES} admitted files: {mf:#}",
        fx.stored_zst().len()
    );

    // Control: the old default, on the byte-identical tree.
    fx.set_total_cap("20MB");
    fx.archive_unscanned(&[]);

    let mf = fx.manifest();
    assert_eq!(
        mf["over_total_cap"], true,
        "20MB did not refuse the tree, so the raise proves nothing: {mf:#}"
    );
    assert_eq!(
        fx.stored_zst(),
        Vec::<String>::new(),
        "a 20MB cap stored a {admitted}-byte admitted set: {mf:#}"
    );
}

// ---------------------------------------------------------------------------
// C. `--full` still lifts it.
// ---------------------------------------------------------------------------

/// The cap lift is unchanged, and is exercised here against the **real default**
/// rather than a 1KB stand-in: 68,600,000 B of admitted content is over 64MB, so a
/// plain run is manifest-only and `--full` stores all of it.
#[test]
fn p22_c_full_lifts_the_default_tree_cap() {
    let fx = Fx::new("full-default");
    fx.write_admitted_files(BIG_FILES, BIG_FILE);
    let admitted = (BIG_FILES * BIG_FILE) as u64;
    assert!(
        admitted > 64 * 1024 * 1024,
        "fixture no longer exceeds the default cap ({admitted} B)"
    );

    // No bytes are read on this run: the cap declines the tree first.
    fx.archive_unscanned(&[]);
    let mf = fx.manifest();
    assert_eq!(
        mf["over_total_cap"], true,
        "the default cap admitted {admitted} B: {mf:#}"
    );
    assert!(
        mf.get("caps_lifted").is_none(),
        "a capped run recorded lifted caps: {mf:#}"
    );
    assert_eq!(fx.stored_zst(), Vec::<String>::new());

    fx.archive_unscanned(&["--full"]);

    let mf = fx.manifest();
    assert_eq!(
        mf["caps_lifted"], true,
        "--full did not record the lift: {mf:#}"
    );
    assert_eq!(
        mf["over_total_cap"], false,
        "--full left the tree cap applied: {mf:#}"
    );
    assert_eq!(
        mf["admitted_bytes"].as_u64(),
        Some(admitted),
        "--full stopped measuring the admitted set: {mf:#}"
    );
    assert_eq!(
        fx.stored_zst().len(),
        BIG_FILES,
        "--full stored {} of {BIG_FILES} files: {mf:#}",
        fx.stored_zst().len()
    );
}

// ---------------------------------------------------------------------------
// D. The reader is told which quantity the verdict is about.
// ---------------------------------------------------------------------------

/// `over_total_cap` is a verdict on the admitted set, so the admitted set is
/// reported next to it. Without it a reader sees a 72,500-byte tree flagged over an
/// 8KB cap and concludes the cap is hopeless for this tree, when the figure it
/// compared was 2,500 B.
#[test]
fn p22_d_the_listing_reports_both_totals_and_the_reason_names_the_admitted_set() {
    let fx = Fx::with_total_cap("listing", "2KB");
    fx.write_mixed_tree();
    fx.archive(&[]);

    let listing = fx.run(&["read", &fx.key(), "--scratch", "--json"]);
    assert_eq!(
        listing.code,
        0,
        "read --scratch failed: {}",
        listing.summary()
    );
    let j = listing.json();
    assert_eq!(j["total_bytes"].as_u64(), Some(RAW));
    assert_eq!(j["admitted_bytes"].as_u64(), Some(ADMITTED));
    assert_eq!(j["over_total_cap"], true);

    let human = fx.run(&["read", &fx.key(), "--scratch"]);
    assert!(
        human.stdout.contains(&format!("{ADMITTED} admitted"))
            && human.stdout.contains("over total_cap"),
        "the listing reports a flag without the quantity it is a verdict on: {}",
        human.summary()
    );

    // And the per-entry explanation says which bytes were summed, so the operator
    // is not sent to measure the tree.
    let refused = fx.run(&[
        "read",
        &fx.key(),
        "--scratch",
        "--file",
        "scratchpad/notes.md",
        "--json",
    ]);
    let reason = refused.json()["reason"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        reason.contains("total_cap") && reason.contains(&ADMITTED.to_string()),
        "the over-cap explanation does not name the admitted total: {reason:?}"
    );
}
