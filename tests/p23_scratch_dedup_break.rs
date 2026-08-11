//! P23 break tests: scratch dedup — the skip path, and every condition guarding it.
//!
//! `archive_scratch` had no skip path at all. `artifacts_skipped` never appeared in
//! it, and the store pass re-read, re-scanned, re-compressed and re-wrote every
//! `stored` entry on every run: measured on this host, 30.87 MB pushed through the
//! secret scanner and 3,580 `.zst` frames rewritten per run over a tree nothing had
//! touched. `capture` has had `Plan::Skip` for whole-file roles since it existed;
//! scratch had nothing.
//!
//! **The skip is not a pure optimisation, and these tests are mostly about the
//! parts that are not.** A skip keyed on the source hash alone would keep an
//! unredacted or wrongly-redacted store copy alive forever after the scan policy
//! was tightened — `--no-scan`, `--quarantine-on-secret` and `[scan] allow` all
//! change what is stored and **none of them changes `source_sha256`** — so the
//! recorded `scan_policy_sha256` is part of the predicate, and so are the three
//! ledger states a skip must not perpetuate: a missing `content_sha256` (the GC
//! gate cannot verify it and only a re-store fills it), a retained or salvaged
//! entry (captured under a policy its ledger does not describe), and a
//! `quarantined` claim whose original is gone.
//!
//! Written to BREAK. Every fixture is fabricated under `CARGO_TARGET_TMPDIR` and
//! removed when the fixture drops. No real Claude Code data, no `~/.yomi`, no
//! `/tmp` (issue #48).
//!
//! **The fixture secret is the public AWS documentation example key**, which
//! authenticates nothing. Assertions name hashes, paths and counts — never file
//! contents — so a failure cannot print an original.

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use yomi::util::sha256_hex;

const BIN: &str = env!("CARGO_BIN_EXE_yomi");

/// HIGH: redacted and the original quarantined.
const FIXTURE_AKIA: &str = "AKIAIOSFODNN7EXAMPLE";
/// MED: redacted, and quarantined only under `--quarantine-on-secret`.
const FIXTURE_JWT: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w";

fn unique() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
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
/// fixture is built is a no-op that leaves every run's directories behind
/// (issue #48).
impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

impl Fx {
    fn new(tag: &str) -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "p23-{tag}-{}-{}",
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

    /// Replace `config.toml`. `ScanConfig` is `#[serde(default)]`, so a `[scan]`
    /// block leaves `[scratch]` at its design defaults.
    fn set_scan_allow(&self, patterns: &[&str]) {
        let list = patterns
            .iter()
            .map(|p| format!("{p:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        std::fs::write(
            self.yomi_home.join("config.toml"),
            format!("[scan]\nallow = [{list}]\n"),
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

    fn read_source(&self, rel: &str) -> Vec<u8> {
        std::fs::read(self.session_dir().join(rel)).expect("read fixture source")
    }

    /// Three admitted files at three depths, none of them secret-bearing.
    fn write_plain_tree(&self) {
        self.write("scratchpad/notes.md", b"notes one\n");
        self.write("scratchpad/sub/deep.md", b"deeper\n");
        self.write("tasks/run.output", b"output\n");
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

    /// One `archive --include scratch` pass, as its JSON report.
    fn archive(&self, extra: &[&str]) -> serde_json::Value {
        let mut v = vec!["--json", "archive", "--all", "--include", "scratch"];
        v.extend_from_slice(extra);
        let out = self.run(&v);
        assert_eq!(out.code, 0, "archive {extra:?} failed: {}", out.summary());
        out.json()
    }

    fn manifest(&self) -> serde_json::Value {
        let p = self.store_dir().join("manifest.json");
        let txt = std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("no manifest at {}: {e}", p.display()));
        serde_json::from_str(&txt).expect("manifest json")
    }

    fn write_manifest(&self, mf: &serde_json::Value) {
        std::fs::write(
            self.store_dir().join("manifest.json"),
            serde_json::to_string_pretty(mf).unwrap() + "\n",
        )
        .unwrap();
    }

    /// Every stored `.zst`, as store-relative path → (inode, length).
    ///
    /// **Inode, not mtime.** Every store write goes through `safefs`, which stages
    /// a temp sibling and `renameat`s it into place, so a rewrite always changes
    /// the inode — an exact answer to "was this artifact written again", where an
    /// mtime comparison depends on clock granularity.
    fn artifacts(&self) -> BTreeMap<String, (u64, u64)> {
        let root = self.store_dir();
        let mut out = BTreeMap::new();
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
                    let md = std::fs::symlink_metadata(&p).unwrap();
                    out.insert(
                        p.strip_prefix(&root)
                            .unwrap()
                            .to_string_lossy()
                            .into_owned(),
                        (md.ino(), md.len()),
                    );
                }
            }
        }
        out
    }

    /// Every file under `quarantine/`, as quarantine-relative path → inode.
    fn originals(&self) -> BTreeMap<String, u64> {
        let root = self.yomi_home.join("quarantine");
        let mut out = BTreeMap::new();
        let mut stack = vec![root.clone()];
        while let Some(d) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in rd.flatten() {
                let p = e.path();
                let md = std::fs::symlink_metadata(&p).unwrap();
                if md.is_dir() {
                    stack.push(p);
                } else {
                    out.insert(
                        p.strip_prefix(&root)
                            .unwrap()
                            .to_string_lossy()
                            .into_owned(),
                        md.ino(),
                    );
                }
            }
        }
        out
    }

    /// `yomi verify --json`, with law Q's verdict. Exit 0 means no violation in
    /// either pass.
    fn verify(&self) -> (i32, serde_json::Value) {
        let out = self.run(&["--json", "verify"]);
        (out.code, out.json())
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

fn skipped(report: &serde_json::Value) -> u64 {
    report["artifacts_skipped"]
        .as_u64()
        .unwrap_or_else(|| panic!("report has no numeric artifacts_skipped: {report}"))
}

fn count(report: &serde_json::Value, key: &str) -> u64 {
    report[key]
        .as_u64()
        .unwrap_or_else(|| panic!("report has no numeric {key}: {report}"))
}

fn entry(mf: &serde_json::Value, path: &str) -> serde_json::Value {
    mf["entries"]
        .as_array()
        .expect("entries array")
        .iter()
        .find(|e| e["path"] == path)
        .cloned()
        .unwrap_or_else(|| panic!("no manifest entry for {path}; manifest={mf:#}"))
}

fn policy(mf: &serde_json::Value) -> String {
    mf["scan_policy_sha256"]
        .as_str()
        .unwrap_or_else(|| panic!("manifest records no scan_policy_sha256: {mf:#}"))
        .to_string()
}

// ---------------------------------------------------------------------------
// A. The skip itself.
// ---------------------------------------------------------------------------

/// **The defect, and the fix.** Two runs over an untouched tree: the second must
/// skip every artifact and write none of them. `artifacts_skipped` was
/// structurally unreachable from `archive_scratch` before this change — the store
/// pass had no branch that could increment it.
///
/// Asserted three ways, because a count alone would not prove the work was
/// avoided: the count, the *inodes* of the stored artifacts (a rewrite renames a
/// temp sibling into place, so an unchanged inode means no write happened), and
/// `findings`/`bytes_stored` at zero — the scanner and the compressor never ran.
#[test]
fn p23_a_a_second_run_over_an_untouched_tree_skips_every_artifact() {
    let fx = Fx::new("second-run");
    fx.write_plain_tree();

    let first = fx.archive(&[]);
    assert_eq!(
        skipped(&first),
        0,
        "the first run skipped something it had never stored: {first}"
    );
    let before = fx.artifacts();
    assert_eq!(
        before.len(),
        3,
        "fixture did not store the three admitted files: {before:?}"
    );
    let mf_before = fx.manifest();

    let second = fx.archive(&[]);

    assert_eq!(
        skipped(&second),
        3,
        "an untouched tree re-captured its artifacts: {second}"
    );
    assert_eq!(
        fx.artifacts(),
        before,
        "a skipped artifact was rewritten: the inode changed, so the frame was \
         compressed and staged again"
    );
    assert_eq!(
        count(&second, "bytes_stored"),
        0,
        "a run that stored nothing reported stored bytes: {second}"
    );
    assert_eq!(
        count(&second, "findings"),
        0,
        "the secret scanner ran over bytes that were already stored: {second}"
    );
    assert_eq!(
        count(&second, "scratch_orphans_removed"),
        0,
        "the skip left artifacts unclaimed by the new manifest: {second}"
    );

    // The ledger is unchanged where it describes the captures, so the GC gate is
    // handed exactly what the first run proved.
    let mf_after = fx.manifest();
    for rel in [
        "scratchpad/notes.md",
        "scratchpad/sub/deep.md",
        "tasks/run.output",
    ] {
        let (b, a) = (entry(&mf_before, rel), entry(&mf_after, rel));
        assert_eq!(a["stored"], true, "{rel} stopped being claimed: {a}");
        assert_eq!(a["source_sha256"], b["source_sha256"], "{rel}: source hash");
        assert_eq!(
            a["content_sha256"], b["content_sha256"],
            "{rel}: content hash"
        );
        assert!(
            a.get("capture_failed").is_none(),
            "a skip was recorded as a failed capture: {a}"
        );
    }
    assert_eq!(
        policy(&mf_after),
        policy(&mf_before),
        "the same policy hashed to two different values on two runs, so dedup \
         could never hold"
    );
    assert_eq!(
        policy(&mf_after).len(),
        64,
        "scan_policy_sha256 is not a sha256 hex digest"
    );
}

/// One file edited: that file is re-stored and **only** that file. The unit of the
/// skip is the entry, not the tree.
#[test]
fn p23_a_only_the_changed_file_is_re_stored() {
    let fx = Fx::new("one-changed");
    fx.write_plain_tree();
    fx.archive(&[]);
    let before = fx.artifacts();
    let sha_before = entry(&fx.manifest(), "scratchpad/notes.md")["source_sha256"].clone();

    fx.write("scratchpad/notes.md", b"notes one, amended\n");
    let second = fx.archive(&[]);

    assert_eq!(
        skipped(&second),
        2,
        "editing one file cost the other two their skip: {second}"
    );
    let after = fx.artifacts();
    assert_ne!(
        after["scratchpad/notes.md.zst"], before["scratchpad/notes.md.zst"],
        "the edited file was not re-stored"
    );
    for rel in ["scratchpad/sub/deep.md.zst", "tasks/run.output.zst"] {
        assert_eq!(after[rel], before[rel], "{rel} was rewritten needlessly");
    }
    let e = entry(&fx.manifest(), "scratchpad/notes.md");
    assert_ne!(
        e["source_sha256"], sha_before,
        "the edited file kept its old source hash: {e}"
    );
}

/// Dedup holds with the caps lifted, and across the cap decision changing. The
/// caps decide *whether* a file is stored; they are not scan policy and are
/// deliberately not in the policy digest, so a `--full` capture is reusable by a
/// plain run — for the files the plain run still admits.
#[test]
fn p23_a_dedup_holds_under_full_and_across_the_cap_decision() {
    let fx = Fx::new("full");
    fx.write_plain_tree();

    let first = fx.archive(&["--full"]);
    assert_eq!(skipped(&first), 0, "{first}");
    assert_eq!(fx.manifest()["caps_lifted"], true);
    let before = fx.artifacts();

    let second = fx.archive(&["--full"]);
    assert_eq!(
        skipped(&second),
        3,
        "--full re-captured an untouched tree: {second}"
    );
    assert_eq!(fx.artifacts(), before, "--full rewrote a skipped artifact");

    // And a capped run after it: these files are well inside both caps, so all
    // three are still admitted and all three are still skippable.
    let third = fx.archive(&[]);
    assert_eq!(
        skipped(&third),
        3,
        "a capped run re-captured what a --full run stored, though the caps \
         declined none of it: {third}"
    );
    assert_eq!(fx.artifacts(), before);
    assert!(
        fx.manifest().get("caps_lifted").is_none(),
        "the capped run recorded lifted caps"
    );
}

/// `--dry-run` forecasts no skips, and the reason is the same one §3 already
/// accepts for `capture_failed`: the store pass does not run, so no source is
/// opened and no hash exists to compare. Pinned so the zero is read as the
/// documented limitation rather than as a defect.
#[test]
fn p23_a_dry_run_forecasts_no_skips_and_writes_nothing() {
    let fx = Fx::new("dry-run");
    fx.write_plain_tree();
    fx.archive(&[]);
    let before = fx.artifacts();
    let mf_before = fx.manifest();

    let dry = fx.archive(&["--dry-run"]);
    assert_eq!(
        skipped(&dry),
        0,
        "--dry-run claimed to know a capture would be reused, which needs a read \
         it does not perform: {dry}"
    );
    assert_eq!(fx.artifacts(), before, "--dry-run wrote to the store");
    assert_eq!(
        fx.manifest(),
        mf_before,
        "--dry-run rewrote the ledger (W1/R8)"
    );
}

// ---------------------------------------------------------------------------
// B. The scan policy is part of the predicate. Three inputs, one at a time.
// ---------------------------------------------------------------------------

/// **`--no-scan` → scan: the store copy holds the raw secret and must be
/// re-stored.** The source is byte-identical, so a source-hash-only predicate
/// would skip it and the unredacted copy would sit in the store forever, with no
/// later run able to repair it.
#[test]
fn p23_b_turning_the_scanner_back_on_re_stores_a_raw_copy() {
    let fx = Fx::new("no-scan");
    fx.write(
        "scratchpad/leak.md",
        format!("key = {FIXTURE_AKIA}\n").as_bytes(),
    );
    let raw = sha256_hex(&fx.read_source("scratchpad/leak.md"));

    let first = fx.archive(&["--no-scan"]);
    assert_eq!(
        count(&first, "quarantined"),
        0,
        "--no-scan quarantined: {first}"
    );
    let e = entry(&fx.manifest(), "scratchpad/leak.md");
    assert_eq!(
        e["content_sha256"], raw,
        "--no-scan did not store the raw bytes, so this test measures nothing: {e}"
    );
    assert!(e.get("quarantined").is_none(), "{e}");
    assert!(fx.originals().is_empty(), "--no-scan wrote an original");
    let before = fx.artifacts();

    let second = fx.archive(&[]);

    assert_eq!(
        skipped(&second),
        0,
        "the scan policy tightened and the raw store copy was skipped: {second}"
    );
    assert_ne!(
        fx.artifacts()["scratchpad/leak.md.zst"],
        before["scratchpad/leak.md.zst"],
        "the raw artifact was not rewritten"
    );
    let e = entry(&fx.manifest(), "scratchpad/leak.md");
    assert_ne!(
        e["content_sha256"], raw,
        "the re-store kept the raw content hash: the secret was not redacted: {e}"
    );
    assert_eq!(
        e["quarantined"], true,
        "the re-store did not quarantine the original: {e}"
    );
    assert_eq!(fx.originals().len(), 1, "no original was written");

    // Settled: the run after it skips again.
    let third = fx.archive(&[]);
    assert_eq!(
        skipped(&third),
        1,
        "dedup never resumed after the policy change: {third}"
    );
}

/// **An edit to `[scan] allow` re-stores.** Allowing the fixture key suppresses
/// its finding, so the same source bytes are stored unredacted and no original is
/// written — a different store copy under an unchanged `source_sha256`.
#[test]
fn p23_b_an_edit_to_scan_allow_re_stores() {
    let fx = Fx::new("scan-allow");
    fx.write(
        "scratchpad/leak.md",
        format!("key = {FIXTURE_AKIA}\n").as_bytes(),
    );
    let raw = sha256_hex(&fx.read_source("scratchpad/leak.md"));

    fx.archive(&[]);
    let redacted = entry(&fx.manifest(), "scratchpad/leak.md")["content_sha256"].clone();
    assert_ne!(redacted, serde_json::json!(raw), "fixture was not redacted");
    let policy_before = policy(&fx.manifest());
    let before = fx.artifacts();

    fx.set_scan_allow(&[FIXTURE_AKIA]);
    let second = fx.archive(&[]);

    assert_ne!(
        policy(&fx.manifest()),
        policy_before,
        "an allowlist edit did not change the recorded policy"
    );
    assert_eq!(
        skipped(&second),
        0,
        "the allowlist changed what would be stored and the old copy was \
         skipped: {second}"
    );
    assert_ne!(
        fx.artifacts()["scratchpad/leak.md.zst"],
        before["scratchpad/leak.md.zst"],
        "the redacted artifact was not rewritten"
    );
    let e = entry(&fx.manifest(), "scratchpad/leak.md");
    assert_eq!(
        e["content_sha256"], raw,
        "the allowed secret is still redacted in the store copy: {e}"
    );
    assert!(
        e.get("quarantined").is_none(),
        "an allowed finding still quarantined: {e}"
    );

    let third = fx.archive(&[]);
    assert_eq!(skipped(&third), 1, "dedup never resumed: {third}");
}

/// **`--quarantine-on-secret` re-stores, even though it changes no stored byte.**
/// A MED finding is redacted either way; the flag decides whether the *original*
/// is preserved. Skipping past it would leave the recovery copy unwritten with
/// nothing able to notice.
#[test]
fn p23_b_changing_the_quarantine_policy_re_stores() {
    let fx = Fx::new("quarantine-policy");
    fx.write(
        "scratchpad/token.md",
        format!("jwt {FIXTURE_JWT}\n").as_bytes(),
    );

    let first = fx.archive(&[]);
    assert_eq!(
        count(&first, "redacted"),
        1,
        "fixture produced no MED finding: {first}"
    );
    assert_eq!(
        count(&first, "quarantined"),
        0,
        "a MED finding quarantined without the flag: {first}"
    );
    assert!(fx.originals().is_empty());
    let content_before = entry(&fx.manifest(), "scratchpad/token.md")["content_sha256"].clone();
    let before = fx.artifacts();

    let second = fx.archive(&["--quarantine-on-secret"]);

    assert_eq!(
        skipped(&second),
        0,
        "the quarantine policy widened and the entry was skipped, so the original \
         was never written: {second}"
    );
    assert_eq!(count(&second, "quarantined"), 1, "{second}");
    assert_eq!(fx.originals().len(), 1, "no original was written");
    let e = entry(&fx.manifest(), "scratchpad/token.md");
    assert_eq!(
        e["quarantined"], true,
        "the ledger does not record the original: {e}"
    );
    assert_eq!(
        e["content_sha256"], content_before,
        "the stored bytes moved; this flag decides the original, not the copy: {e}"
    );
    assert_ne!(
        fx.artifacts()["scratchpad/token.md.zst"],
        before["scratchpad/token.md.zst"],
        "the artifact was not rewritten by the re-store"
    );

    let third = fx.archive(&["--quarantine-on-secret"]);
    assert_eq!(skipped(&third), 1, "dedup never resumed: {third}");
}

/// **The digest is order-stable.** `[scan] allow` reaches the archiver as a `Vec`
/// from the config and as two collections inside `Allowlist`; if the digest
/// depended on that order, reordering two lines — or a future change to how the
/// entries are held — would re-store every artifact in the store on every run,
/// which is dedup switched off with no error to see.
#[test]
fn p23_b_the_policy_digest_does_not_depend_on_allowlist_order() {
    let fx = Fx::new("order");
    fx.write_plain_tree();
    fx.set_scan_allow(&["zzz-benign-[0-9]+", "aaa-benign-[0-9]+", "deadbeef"]);
    fx.archive(&[]);
    let first = policy(&fx.manifest());
    let before = fx.artifacts();

    // The same policy, written in a different order.
    fx.set_scan_allow(&["deadbeef", "aaa-benign-[0-9]+", "zzz-benign-[0-9]+"]);
    let second = fx.archive(&[]);

    assert_eq!(
        policy(&fx.manifest()),
        first,
        "reordering the allowlist changed the policy digest"
    );
    assert_eq!(
        skipped(&second),
        3,
        "reordering the allowlist re-stored the whole tree: {second}"
    );
    assert_eq!(fx.artifacts(), before);

    // Control: a real addition does change it, so the equality above is not
    // measuring a constant.
    fx.set_scan_allow(&[
        "deadbeef",
        "aaa-benign-[0-9]+",
        "zzz-benign-[0-9]+",
        "cafe0000",
    ]);
    let third = fx.archive(&[]);
    assert_ne!(
        policy(&fx.manifest()),
        first,
        "adding an allowlist entry did not change the policy digest"
    );
    assert_eq!(
        skipped(&third),
        0,
        "an allowlist addition did not re-store: {third}"
    );
}

// ---------------------------------------------------------------------------
// C. Ledger states a skip must not perpetuate.
// ---------------------------------------------------------------------------

/// **A manifest from before `scan_policy_sha256` existed forces one full re-store
/// and self-upgrades.** The default is the empty string, which no digest equals.
#[test]
fn p23_c_a_manifest_without_a_recorded_policy_re_stores_once() {
    let fx = Fx::new("old-manifest");
    fx.write_plain_tree();
    fx.archive(&[]);
    let before = fx.artifacts();

    let mut mf = fx.manifest();
    mf.as_object_mut().unwrap().remove("scan_policy_sha256");
    fx.write_manifest(&mf);

    let second = fx.archive(&[]);
    assert_eq!(
        skipped(&second),
        0,
        "a ledger that records no scan policy was treated as recording this \
         one: {second}"
    );
    assert_ne!(fx.artifacts(), before, "nothing was re-stored");
    assert_eq!(
        policy(&fx.manifest()).len(),
        64,
        "the field was not stamped"
    );

    let third = fx.archive(&[]);
    assert_eq!(
        skipped(&third),
        3,
        "the store did not self-upgrade: {third}"
    );
}

/// **An entry with `source_sha256` and no `content_sha256` is re-stored.** That
/// pair is what the GC gate needs (`StoreReverifyFailed` without it), and a
/// re-store is the only thing that can fill the missing field — so skipping on the
/// source hash alone would make an unverifiable store permanent. The same
/// condition is the self-heal path for every manifest written before D2/R1.
#[test]
fn p23_c_an_entry_missing_its_content_hash_is_re_stored() {
    let fx = Fx::new("no-content-sha");
    fx.write_plain_tree();
    fx.archive(&[]);
    let before = fx.artifacts();

    let mut mf = fx.manifest();
    for e in mf["entries"].as_array_mut().unwrap() {
        if e["path"] == "scratchpad/notes.md" {
            e.as_object_mut().unwrap().remove("content_sha256");
        }
    }
    fx.write_manifest(&mf);

    let second = fx.archive(&[]);
    assert_eq!(
        skipped(&second),
        2,
        "an entry the GC gate cannot verify was skipped, so nothing would ever \
         fill its content hash: {second}"
    );
    let after = fx.artifacts();
    assert_ne!(
        after["scratchpad/notes.md.zst"], before["scratchpad/notes.md.zst"],
        "the unverifiable entry was not re-stored"
    );
    assert_eq!(
        after["tasks/run.output.zst"],
        before["tasks/run.output.zst"]
    );
    let e = entry(&fx.manifest(), "scratchpad/notes.md");
    assert!(
        e["content_sha256"].is_string(),
        "the re-store did not restore the content hash: {e}"
    );
}

/// **A claimed `.zst` that is not on disk is re-stored.** The carried claim is
/// grounded in the artifact actually being there, exactly as `salvage` grounds
/// its own — never in the prior ledger's word for it.
#[test]
fn p23_c_a_missing_artifact_is_re_stored_rather_than_claimed() {
    let fx = Fx::new("missing-zst");
    fx.write_plain_tree();
    fx.archive(&[]);

    std::fs::remove_file(fx.store_dir().join("scratchpad/notes.md.zst")).unwrap();

    let second = fx.archive(&[]);
    assert_eq!(
        skipped(&second),
        2,
        "an entry whose artifact is gone was skipped, leaving the ledger \
         claiming a file that does not exist: {second}"
    );
    assert!(
        fx.artifacts().contains_key("scratchpad/notes.md.zst"),
        "the artifact was not rewritten"
    );
    let (code, _) = fx.verify();
    assert_eq!(code, 0, "the store did not converge after the re-store");
}

/// **No ledger at all → a full re-store.** Cost, not a correctness gap: the
/// artifacts are still there and are reclaimed by reconciliation only if the new
/// manifest stops claiming them, which it does not.
#[test]
fn p23_c_a_missing_manifest_re_stores_the_tree() {
    let fx = Fx::new("no-manifest");
    fx.write_plain_tree();
    fx.archive(&[]);

    std::fs::remove_file(fx.store_dir().join("manifest.json")).unwrap();

    let second = fx.archive(&[]);
    assert_eq!(
        skipped(&second),
        0,
        "a tree with no prior ledger reused captures it cannot have read: {second}"
    );
    assert_eq!(fx.artifacts().len(), 3);
    let (code, _) = fx.verify();
    assert_eq!(code, 0);
}

// ---------------------------------------------------------------------------
// D. Quarantine — the carried flag, and the claim behind it.
// ---------------------------------------------------------------------------

/// **`quarantined` is carried across a skip.** Dropping it would have the ledger
/// deny an unredacted original that is still on disk, which law Q reads as a
/// stray — the same failure `salvage` avoids for the same reason. Checked through
/// `verify`, which is the layer that would accuse.
#[test]
fn p23_d_a_skip_carries_the_quarantined_flag() {
    let fx = Fx::new("carry-quarantined");
    fx.write(
        "scratchpad/leak.md",
        format!("key = {FIXTURE_AKIA}\n").as_bytes(),
    );
    fx.write("scratchpad/notes.md", b"nothing to see\n");

    let first = fx.archive(&[]);
    assert_eq!(
        count(&first, "quarantined"),
        1,
        "fixture quarantined nothing: {first}"
    );
    let originals = fx.originals();
    assert_eq!(originals.len(), 1);
    let before = fx.artifacts();

    let second = fx.archive(&[]);

    assert_eq!(
        skipped(&second),
        2,
        "the quarantined entry was re-captured: {second}"
    );
    assert_eq!(
        count(&second, "quarantined"),
        0,
        "the skip rewrote an original it did not need to: {second}"
    );
    assert_eq!(
        fx.originals(),
        originals,
        "the skip disturbed the quarantine tree"
    );
    assert_eq!(fx.artifacts(), before);
    let e = entry(&fx.manifest(), "scratchpad/leak.md");
    assert_eq!(
        e["quarantined"], true,
        "the skip dropped `quarantined`, so the ledger now denies an original \
         that is still on disk: {e}"
    );

    let (code, v) = fx.verify();
    assert_eq!(
        code,
        0,
        "verify accuses after a skip: {}",
        serde_json::to_string(&v["quarantine"]).unwrap_or_default()
    );
    assert_eq!(
        v["quarantine"]["violations"].as_array().map(Vec::len),
        Some(0),
        "law Q reports a violation after a skip: {:#}",
        v["quarantine"]
    );
    assert_eq!(
        v["quarantine"]["foreign_matter"].as_array().map(Vec::len),
        Some(0),
        "the carried original reads as a stray: {:#}",
        v["quarantine"]
    );
}

/// **A `quarantined` entry whose original has been removed is re-stored, which
/// rewrites it.** The carried flag asserts that an original exists; only a
/// re-store can make that true again, so skipping past it would leave law Q's Q1
/// accusing on every run with nothing able to repair it.
#[test]
fn p23_d_a_deleted_original_is_rewritten_by_a_re_store() {
    let fx = Fx::new("deleted-original");
    fx.write(
        "scratchpad/leak.md",
        format!("key = {FIXTURE_AKIA}\n").as_bytes(),
    );
    fx.archive(&[]);
    let originals = fx.originals();
    assert_eq!(originals.len(), 1);

    // What an operator clearing quarantine/ by hand leaves behind.
    let (rel, _) = originals.iter().next().unwrap();
    std::fs::remove_file(fx.yomi_home.join("quarantine").join(rel)).unwrap();
    let (code, _) = fx.verify();
    assert_ne!(
        code, 0,
        "fixture did not reach the state this test is about: law Q should accuse \
         a claimed original that is gone"
    );

    let second = fx.archive(&[]);

    assert_eq!(
        skipped(&second),
        0,
        "the entry was skipped, so the missing original stays missing forever: \
         {second}"
    );
    assert_eq!(count(&second, "quarantined"), 1, "{second}");
    assert!(
        fx.originals().contains_key(rel),
        "the original was not rewritten at its mirrored path"
    );
    let (code, v) = fx.verify();
    assert_eq!(
        code, 0,
        "law Q still accuses after the re-store: {:#}",
        v["quarantine"]
    );
}

// ---------------------------------------------------------------------------
// E. Retention and salvage — entries whose capture the ledger does not describe.
// ---------------------------------------------------------------------------

/// **A retained entry is not a skip candidate, and a returning file is re-stored
/// once.**
///
/// A `present: false` entry was captured by some run *older* than the ledger that
/// carries it, so the policy that ledger records says nothing about its store
/// copy. Were it skippable, a file that vanished across a policy change and came
/// back byte-identical would keep its pre-change copy forever. The cost of
/// excluding it is exactly one re-store: the run after settles back into a skip.
///
/// Retention itself is untouched — the vanished entry keeps its `.zst`, its hashes
/// and its claim, which is what makes it the last copy.
#[test]
fn p23_e_a_returning_file_is_re_stored_once_and_skipped_after() {
    let fx = Fx::new("retained");
    fx.write_plain_tree();
    fx.archive(&[]);
    let before = fx.artifacts();
    let deep = fx.session_dir().join("scratchpad/sub/deep.md");
    let bytes = std::fs::read(&deep).unwrap();

    // Gone: retained verbatim, and the other two still skip.
    std::fs::remove_file(&deep).unwrap();
    let second = fx.archive(&[]);
    assert_eq!(skipped(&second), 2, "{second}");
    let e = entry(&fx.manifest(), "scratchpad/sub/deep.md");
    assert_eq!(
        e["present"], false,
        "the vanished entry was not retained: {e}"
    );
    assert_eq!(e["stored"], true, "retention dropped the claim: {e}");
    assert_eq!(
        fx.artifacts(),
        before,
        "retention or a skip rewrote an artifact"
    );

    // Back, byte-identical. The live pass rebuilds it, and it is re-stored rather
    // than resumed from a claim the ledger cannot vouch for.
    std::fs::write(&deep, &bytes).unwrap();
    let third = fx.archive(&[]);
    assert_eq!(
        skipped(&third),
        2,
        "a returning file was skipped on the strength of a retained entry, whose \
         capture the ledger's recorded policy does not describe: {third}"
    );
    let after = fx.artifacts();
    assert_ne!(
        after["scratchpad/sub/deep.md.zst"], before["scratchpad/sub/deep.md.zst"],
        "the returning file was neither skipped nor re-stored"
    );
    let e = entry(&fx.manifest(), "scratchpad/sub/deep.md");
    assert!(
        e.get("present").is_none(),
        "the returning file is still recorded as absent: {e}"
    );

    let fourth = fx.archive(&[]);
    assert_eq!(
        skipped(&fourth),
        3,
        "dedup did not settle after the file returned: {fourth}"
    );
}

/// **A salvaged entry is not a skip candidate either.** Salvage carries hashes
/// from an arbitrarily old capture while leaving `present: true`, so `present`
/// alone does not close the retention door; `capture_failed` is the other half.
/// Together they make the rule inductive: every entry a skip leans on was stored
/// or skipped by the run whose ledger records the policy.
///
/// Skipped under uid 0, which ignores the mode bits this fixture relies on.
#[test]
fn p23_e_a_salvaged_entry_is_re_stored_when_the_source_returns() {
    if is_root() {
        return;
    }
    let fx = Fx::new("salvaged");
    fx.write_plain_tree();
    fx.archive(&[]);
    let before = fx.artifacts();

    let notes = fx.session_dir().join("scratchpad/notes.md");
    std::fs::set_permissions(&notes, std::fs::Permissions::from_mode(0o000)).unwrap();
    let second = fx.archive(&[]);
    std::fs::set_permissions(&notes, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(skipped(&second), 2, "{second}");
    let e = entry(&fx.manifest(), "scratchpad/notes.md");
    assert_eq!(
        e["capture_failed"], true,
        "fixture did not reach the salvage path: {e}"
    );
    assert_eq!(e["stored"], true, "salvage dropped the claim: {e}");

    let third = fx.archive(&[]);
    assert_eq!(
        skipped(&third),
        2,
        "a salvaged entry was skipped on hashes carried from a capture the \
         ledger's policy does not describe: {third}"
    );
    let after = fx.artifacts();
    assert_ne!(
        after["scratchpad/notes.md.zst"], before["scratchpad/notes.md.zst"],
        "the recovered source was not re-stored"
    );
    let e = entry(&fx.manifest(), "scratchpad/notes.md");
    assert!(
        e.get("capture_failed").is_none(),
        "capture_failed did not self-clear on the re-store: {e}"
    );

    let fourth = fx.archive(&[]);
    assert_eq!(skipped(&fourth), 3, "dedup did not settle: {fourth}");
}

// ---------------------------------------------------------------------------
// F. `--rearchive` — the operator's path past the predicate.
// ---------------------------------------------------------------------------

/// **The remedy for what the policy digest deliberately does not cover.** A
/// hardened detector changes what a scan would redact while changing neither the
/// source bytes nor the recorded policy, so nothing in the predicate can see it —
/// and `rescan`, which exists for exactly that, reaches only catalog rows and
/// scratch has none. `--rearchive` is the path: every capture is scanned,
/// compressed and written afresh.
///
/// `findings` is the assertion that matters — it is the proof the scanner ran
/// again over bytes that were already stored, which is the whole purpose.
#[test]
fn p23_f_rearchive_re_stores_an_untouched_tree() {
    let fx = Fx::new("rearchive");
    fx.write(
        "scratchpad/leak.md",
        format!("key = {FIXTURE_AKIA}\n").as_bytes(),
    );
    fx.write("scratchpad/notes.md", b"nothing to see\n");

    let first = fx.archive(&[]);
    assert_eq!(count(&first, "findings"), 1, "{first}");
    let before = fx.artifacts();
    let mf_before = fx.manifest();

    let forced = fx.archive(&["--rearchive"]);

    assert_eq!(
        skipped(&forced),
        0,
        "--rearchive reused a capture: the one path past the predicate does not \
         work, so a hardened detector can no longer be applied to an existing \
         scratch store copy at all: {forced}"
    );
    assert_eq!(
        count(&forced, "findings"),
        1,
        "--rearchive re-stored without re-scanning, which is the only reason to \
         re-store: {forced}"
    );
    assert_eq!(
        count(&forced, "quarantined"),
        1,
        "--rearchive did not rewrite the unredacted original: {forced}"
    );
    assert!(count(&forced, "bytes_stored") > 0, "{forced}");
    let after = fx.artifacts();
    for rel in ["scratchpad/leak.md.zst", "scratchpad/notes.md.zst"] {
        assert_ne!(after[rel], before[rel], "{rel} was not rewritten");
    }

    // Same policy and same bytes, so the ledger's claims are identical — the
    // re-store is work, not a change.
    for rel in ["scratchpad/leak.md", "scratchpad/notes.md"] {
        let (b, a) = (entry(&mf_before, rel), entry(&fx.manifest(), rel));
        assert_eq!(a["source_sha256"], b["source_sha256"], "{rel}");
        assert_eq!(a["content_sha256"], b["content_sha256"], "{rel}");
    }
    assert_eq!(policy(&fx.manifest()), policy(&mf_before));
    let (code, _) = fx.verify();
    assert_eq!(code, 0, "the store does not verify after --rearchive");
}

/// **The mirror of the B group, and the shape an upgraded operator actually
/// types.** There, a scan-policy change moves `scan_policy_sha256` and the
/// re-store follows from it. Here **every input the digest covers is held
/// byte-identical** — same `config.toml`, same flags but one, same sources — the
/// digest is asserted equal across the runs, and the re-store happens anyway.
///
/// That is exactly the post-upgrade case: a hardened detector changes what a scan
/// would redact and changes nothing the digest can see, so a path that only
/// re-stores on a digest change would be no path at all. The middle run is the
/// control — it proves the predicate *would* have skipped, so `--rearchive` is the
/// only variable in play.
#[test]
fn p23_f_rearchive_re_stores_though_every_digest_input_is_unchanged() {
    let fx = Fx::new("rearchive-same-policy");
    // A non-default policy, so the digest under test is not the default one.
    fx.set_scan_allow(&["deadbeef"]);
    fx.write(
        "scratchpad/leak.md",
        format!("key = {FIXTURE_AKIA}\n").as_bytes(),
    );
    fx.write("scratchpad/notes.md", b"nothing to see\n");
    let config = std::fs::read(fx.yomi_home.join("config.toml")).unwrap();

    let first = fx.archive(&[]);
    assert_eq!(count(&first, "findings"), 1, "{first}");
    let pinned = policy(&fx.manifest());
    let before = fx.artifacts();

    // Control: nothing has moved, so the predicate reuses everything.
    let control = fx.archive(&[]);
    assert_eq!(
        skipped(&control),
        2,
        "the control run did not skip, so this test cannot attribute anything to \
         the flag: {control}"
    );
    assert_eq!(fx.artifacts(), before);
    assert_eq!(policy(&fx.manifest()), pinned);

    // The same run, plus the flag. Nothing else differs.
    let forced = fx.archive(&["--rearchive"]);

    assert_eq!(
        policy(&fx.manifest()),
        pinned,
        "the fixture moved the scan policy, so the re-store below proves nothing \
         about --rearchive"
    );
    assert_eq!(
        std::fs::read(fx.yomi_home.join("config.toml")).unwrap(),
        config,
        "the fixture edited the config"
    );
    assert_eq!(
        skipped(&forced),
        0,
        "--rearchive re-stored nothing under an unchanged policy digest, which is \
         the only state a hardened detector leaves behind — so there would be no \
         way to re-redact an existing scratch store copy at all: {forced}"
    );
    assert_eq!(
        count(&forced, "findings"),
        1,
        "the scanner did not run again over the already-stored bytes: {forced}"
    );
    assert_eq!(count(&forced, "quarantined"), 1, "{forced}");
    let after = fx.artifacts();
    for rel in ["scratchpad/leak.md.zst", "scratchpad/notes.md.zst"] {
        assert_ne!(after[rel], before[rel], "{rel} was not rewritten");
    }
}

/// **One run only, and nothing records that it happened.** A forced run produces
/// exactly the ledger a policy-changed run produces, and no later decision asks
/// whether a capture was reused or rewritten — so unlike `caps_lifted` there is no
/// ambiguity for a field to resolve, and the ledger gains no field. Asserted on
/// the manifest's key set, so a field added later has to be justified rather than
/// arrive unnoticed.
#[test]
fn p23_f_rearchive_lasts_one_run_and_records_nothing() {
    let fx = Fx::new("rearchive-once");
    fx.write_plain_tree();
    fx.archive(&[]);
    let plain_keys: Vec<String> = fx.manifest().as_object().unwrap().keys().cloned().collect();

    fx.archive(&["--rearchive"]);
    let forced_keys: Vec<String> = fx.manifest().as_object().unwrap().keys().cloned().collect();
    assert_eq!(
        forced_keys, plain_keys,
        "a forced run recorded something in the ledger"
    );
    let settled = fx.artifacts();

    let after = fx.archive(&[]);
    assert_eq!(
        skipped(&after),
        3,
        "--rearchive outlived its run: the flag is per-run and nothing should \
         carry it forward: {after}"
    );
    assert_eq!(fx.artifacts(), settled);
}

/// **Orthogonal to `--full`, in all four combinations.** `--full` lifts the
/// `[scratch]` caps and adds nothing else (decision #8); `--rearchive` decides
/// whether a capture is reused. Neither may acquire the other's effect: a `--full`
/// run must still dedup, and a forced run must still apply the caps.
#[test]
fn p23_f_rearchive_and_full_are_orthogonal() {
    let fx = Fx::new("orthogonal");
    fx.write_plain_tree();
    fx.archive(&[]);

    // (--full, --rearchive) -> (expected skips, expected caps_lifted)
    let cases: &[(&[&str], u64, bool)] = &[
        (&[], 3, false),
        (&["--full"], 3, true),
        (&["--rearchive"], 0, false),
        (&["--full", "--rearchive"], 0, true),
    ];
    for (args, want_skipped, want_lifted) in cases {
        let r = fx.archive(args);
        assert_eq!(
            skipped(&r),
            *want_skipped,
            "{args:?}: --full and --rearchive are not independent — one of them \
             took on the other's effect: {r}"
        );
        let mf = fx.manifest();
        assert_eq!(
            mf.get("caps_lifted").and_then(|v| v.as_bool()) == Some(true),
            *want_lifted,
            "{args:?}: caps_lifted no longer reflects --full alone: {mf:#}"
        );
    }
}
