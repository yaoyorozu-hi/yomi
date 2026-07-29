//! P10 break tests: adversarial assault on U3 — `verify`'s scratch pass.
//!
//! U3's whole claim rests on a vocabulary: `violation` and `refused key` fail
//! the run, `unverifiable` and `foreign matter` do not. If a real defect can be
//! moved out of `violation`, the pass attests to nothing; if a healthy legacy
//! store can be moved into it, the pass is noise an operator learns to ignore.
//! These tests attack the boundary from both sides, then attack the two
//! properties the design calls structural: that no stored byte can reach the
//! output, and that the live tree is never read.
//!
//! Written to BREAK, not to confirm. Every fixture is fabricated under
//! `CARGO_TARGET_TMPDIR`; nothing is written to `/`, to the repository working
//! copy, or outside the build tree, and no real Claude Code data is touched.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

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
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "p10-{tag}-{}-{}",
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
            uuid: "11111111-2222-3333-4444-555555555555".to_string(),
            base,
        };
        std::fs::create_dir_all(fx.home.join(".claude/projects").join(&fx.slug)).unwrap();
        for d in [&fx.tmp_root, &fx.cache_home, &fx.proc_root, &fx.yomi_home] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::set_permissions(&fx.yomi_home, std::fs::Permissions::from_mode(0o700)).unwrap();
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

    fn archive(&self) {
        let out = self.run(&["archive", "--all", "--include", "scratch"]);
        assert!(
            out.status.success(),
            "archive failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn verify(&self) -> Verify {
        self.verify_args(&["verify", "--json"])
    }

    fn verify_args(&self, args: &[&str]) -> Verify {
        let out = self.run(args);
        let txt = String::from_utf8_lossy(&out.stdout).into_owned();
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        let v: serde_json::Value = serde_json::from_str(txt.trim()).unwrap_or_else(|e| {
            panic!("verify --json unparseable ({e}); stdout={txt:?} stderr={err:?}")
        });
        Verify {
            code: out.status.code().unwrap(),
            scratch: v["scratch"].clone(),
            stdout: txt,
            stderr: err,
        }
    }

    /// Human-facing (non-JSON) verify, for output-leak checks.
    fn verify_text(&self) -> (String, String) {
        let out = self.run(&["verify"]);
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn manifest_path(&self) -> PathBuf {
        self.store_dir().join("manifest.json")
    }

    fn manifest(&self) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(self.manifest_path()).unwrap()).unwrap()
    }

    fn write_manifest(&self, mf: &serde_json::Value) {
        std::fs::write(
            self.manifest_path(),
            serde_json::to_string_pretty(mf).unwrap(),
        )
        .unwrap();
    }

    /// Mutate every manifest entry in place.
    fn edit_entries(&self, f: impl Fn(&mut serde_json::Value)) {
        let mut mf = self.manifest();
        for e in mf["entries"].as_array_mut().unwrap() {
            f(e);
        }
        self.write_manifest(&mf);
    }
}

struct Verify {
    code: i32,
    scratch: serde_json::Value,
    stdout: String,
    stderr: String,
}

impl Verify {
    fn issues(&self, class: &str) -> Vec<String> {
        self.scratch[class]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|f| f["issue"].as_str().unwrap_or("?").to_string())
                    .collect()
            })
            .unwrap_or_default()
    }
    fn keys(&self) -> u64 {
        self.scratch["keys"].as_u64().unwrap()
    }
    fn verified(&self) -> u64 {
        self.scratch["verified"].as_u64().unwrap()
    }
    fn summary(&self) -> String {
        format!(
            "exit={} keys={} verified={} violations={:?} unverifiable={:?} foreign={:?} refused={:?}",
            self.code,
            self.keys(),
            self.verified(),
            self.issues("violations"),
            self.issues("unverifiable"),
            self.issues("foreign_matter"),
            self.issues("refused"),
        )
    }
}

fn zst_under(root: &Path) -> Vec<PathBuf> {
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
                Ok(_) if p.extension().and_then(|x| x.to_str()) == Some("zst") => out.push(p),
                _ => {}
            }
        }
    }
    out.sort();
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// A. The vocabulary boundary — both directions.
// ---------------------------------------------------------------------------

/// The population U3 exists to protect: a pre-D2/R1 store, every entry
/// `stored: true` with no `content_sha256`, every artifact genuinely present.
/// Nothing here is broken, so nothing may fail the run — a verify that exits 2
/// on this every night is a verify nobody reads.
#[test]
fn p10_healthy_legacy_store_exits_zero() {
    let fx = Fx::new("legacy");
    fx.write("scratchpad/a.md", b"content-a\n");
    fx.write("scratchpad/b.md", b"content-b\n");
    fx.archive();
    // Age the ledger into the pre-D2/R1 shape; artifacts untouched and valid.
    fx.edit_entries(|e| {
        e.as_object_mut().unwrap().remove("source_sha256");
        e.as_object_mut().unwrap().remove("content_sha256");
    });

    let v = fx.verify();
    assert_eq!(
        v.code,
        0,
        "a healthy pre-D2/R1 store failed the run: {}",
        v.summary()
    );
    assert!(v.issues("violations").is_empty(), "{}", v.summary());
    assert!(v.issues("refused").is_empty(), "{}", v.summary());
    assert_eq!(
        v.issues("unverifiable").len(),
        2,
        "both hashless entries should be reported as unverifiable: {}",
        v.summary()
    );
}

/// `unverifiable` and `foreign matter` together, with nothing else wrong, must
/// still exit 0 — both are statements about what cannot be concluded, not
/// defects.
#[test]
fn p10_unverifiable_and_foreign_matter_alone_do_not_fail() {
    let fx = Fx::new("classes");
    fx.write("scratchpad/a.md", b"content-a\n");
    fx.archive();
    fx.edit_entries(|e| {
        e.as_object_mut().unwrap().remove("content_sha256");
    });
    // A `*.zst` archive will neither claim nor remove: only an operator can.
    let foreign = fx.store_dir().join("scratchpad/planted.md.zst");
    std::os::unix::fs::symlink(fx.base.join("nowhere"), &foreign).unwrap();

    let v = fx.verify();
    assert_eq!(v.code, 0, "{}", v.summary());
    assert_eq!(
        v.issues("unverifiable"),
        vec!["NoContentHash"],
        "{}",
        v.summary()
    );
    assert_eq!(
        v.issues("foreign_matter"),
        vec!["ForeignArtifact"],
        "{}",
        v.summary()
    );
    assert!(v.issues("violations").is_empty(), "{}", v.summary());
}

/// Control: the same corruption *with* its hash present is a violation and does
/// fail the run. Without this the downgrade test below proves nothing.
#[test]
fn p10_corrupt_artifact_with_its_hash_is_a_violation() {
    let fx = Fx::new("corrupt");
    fx.write("scratchpad/a.md", b"content-a\n");
    fx.archive();
    std::fs::write(
        fx.store_dir().join("scratchpad/a.md.zst"),
        b"NOT-A-ZSTD-FRAME",
    )
    .unwrap();

    let v = fx.verify();
    assert_eq!(
        v.code,
        2,
        "corruption did not fail the run: {}",
        v.summary()
    );
    assert_eq!(
        v.issues("violations"),
        vec!["ContentMismatch"],
        "{}",
        v.summary()
    );
}

/// The downgrade: the *same* corrupt artifact, with `content_sha256` removed,
/// stops failing the run. Measured, not asserted to be a defect — S2 genuinely
/// does not apply without the hash, and a ledger that cannot prove content is
/// honestly reporting that it cannot. Pinned here because it is the sharpest
/// consequence of the vocabulary split: anyone who can write `manifest.json`
/// can move any real corruption out of `violation` by deleting one field, and
/// the store's own mode-700 boundary is the only thing preventing it.
#[test]
fn p10_removing_content_hash_downgrades_a_real_corruption() {
    let fx = Fx::new("downgrade");
    fx.write("scratchpad/a.md", b"content-a\n");
    fx.archive();
    std::fs::write(
        fx.store_dir().join("scratchpad/a.md.zst"),
        b"NOT-A-ZSTD-FRAME",
    )
    .unwrap();
    assert_eq!(fx.verify().code, 2, "control: corruption must fail first");

    fx.edit_entries(|e| {
        e.as_object_mut().unwrap().remove("content_sha256");
    });
    let v = fx.verify();
    assert_eq!(
        v.code,
        0,
        "behaviour changed — re-read the vocabulary note: {}",
        v.summary()
    );
    assert_eq!(
        v.issues("unverifiable"),
        vec!["NoContentHash"],
        "{}",
        v.summary()
    );
    // The corruption is still on disk; only the ledger's ability to see it went.
    assert_eq!(
        std::fs::read(fx.store_dir().join("scratchpad/a.md.zst")).unwrap(),
        b"NOT-A-ZSTD-FRAME",
        "fixture no longer holds a corrupt artifact"
    );
}

// ---------------------------------------------------------------------------
// B. N32 — the archive window.
// ---------------------------------------------------------------------------

/// `archive` writes the manifest and *then* reconciles, so between those two
/// steps the store holds artifacts the new ledger does not claim. That is
/// exactly `OrphanArtifact`, so a `verify` overlapping an `archive` reports
/// violations about a healthy store and exits 2.
///
/// Reconstructed deterministically here (no race): the state is the one archive
/// itself passes through. Confirmed live against a real concurrent run —
/// archive exit 0, reconcile complete, steady state clean, and a verify fired at
/// the manifest-rewrite instant reporting 59,800 `OrphanArtifact` violations.
///
/// **This test pins current behaviour, not desired behaviour.** 思兼 is deciding
/// how the window should be closed; when it is, the expectation here changes.
#[test]
fn p10_manifest_ahead_of_reconcile_reports_false_orphans() {
    let fx = Fx::new("n32");
    for n in ["a", "b", "c"] {
        fx.write(&format!("scratchpad/{n}.md"), b"x\n");
    }
    fx.archive();
    assert_eq!(zst_under(&fx.store_dir()).len(), 3);
    assert_eq!(fx.verify().code, 0, "fixture must start clean");

    // The mid-archive state: manifest rewritten to claim nothing, artifacts not
    // yet reconciled away.
    let mut mf = fx.manifest();
    mf["entries"] = serde_json::Value::Array(vec![]);
    fx.write_manifest(&mf);

    let v = fx.verify();
    assert_eq!(
        v.code,
        2,
        "the mid-archive window did not produce violations: {}",
        v.summary()
    );
    assert_eq!(
        v.issues("violations"),
        vec!["OrphanArtifact"; 3],
        "a store mid-reconcile is reported as defective: {}",
        v.summary()
    );
}

// ---------------------------------------------------------------------------
// C. Redaction non-exposure — claimed structural. Attacked.
// ---------------------------------------------------------------------------

/// A secret that was redacted on the way into the store must not come back out
/// through `verify`, on either stream, in either output mode — including on the
/// failure paths, where a naive implementation would quote the bytes it could
/// not match.
#[test]
fn p10_verify_output_never_carries_stored_content() {
    let fx = Fx::new("noexpose");
    let secret_line = format!("aws_access_key_id = {FIXTURE_AKIA}\n");
    fx.write("scratchpad/a.md", secret_line.as_bytes());
    fx.write("scratchpad/b.md", b"ordinary content that is not secret\n");
    fx.archive();

    // Force every failure path at once: one artifact corrupt (ContentMismatch),
    // one artifact replaced by a valid frame of the wrong bytes.
    std::fs::write(
        fx.store_dir().join("scratchpad/a.md.zst"),
        b"NOT-A-ZSTD-FRAME",
    )
    .unwrap();
    let wrong =
        yomi::archive::compress::compress_frame(b"WRONG-BYTES-THAT-ARE-DISTINCTIVE-abcdefghij\n")
            .unwrap();
    std::fs::write(fx.store_dir().join("scratchpad/b.md.zst"), &wrong).unwrap();

    let v = fx.verify();
    let (t_out, t_err) = fx.verify_text();
    assert_eq!(v.code, 2, "fixture did not reach the failure paths");

    for (label, text) in [
        ("json stdout", &v.stdout),
        ("json stderr", &v.stderr),
        ("text stdout", &t_out),
        ("text stderr", &t_err),
    ] {
        assert!(
            !contains(text.as_bytes(), FIXTURE_AKIA.as_bytes()),
            "{label} carried the secret"
        );
        assert!(
            !contains(text.as_bytes(), b"WRONG-BYTES-THAT-ARE-DISTINCTIVE"),
            "{label} carried stored artifact content"
        );
        assert!(
            !contains(text.as_bytes(), b"ordinary content that is not secret"),
            "{label} carried live file content"
        );
    }
}

/// `verify` must never open the live tree. Proved by difference: run it with the
/// live tree present, then with the tree deleted outright, and require identical
/// findings. If any live byte were consulted, removing the tree would change the
/// answer.
#[test]
fn p10_verify_never_reads_the_live_tree() {
    let fx = Fx::new("nolive");
    fx.write("scratchpad/a.md", b"content-a\n");
    fx.write("scratchpad/b.md", b"content-b\n");
    fx.archive();

    let with_tree = fx.verify();
    // Rewrite every live file to content that matches no recorded hash, and
    // make one unreadable: a pass that touched the tree would notice.
    fx.write("scratchpad/a.md", b"COMPLETELY-DIFFERENT-CONTENT\n");
    let b = fx.session_dir().join("scratchpad/b.md");
    std::fs::set_permissions(&b, std::fs::Permissions::from_mode(0o000)).unwrap();
    let drifted = fx.verify();
    std::fs::set_permissions(&b, std::fs::Permissions::from_mode(0o644)).unwrap();

    // And with no live tree at all.
    std::fs::remove_dir_all(fx.session_dir()).unwrap();
    let without_tree = fx.verify();

    assert_eq!(
        (with_tree.code, with_tree.verified()),
        (drifted.code, drifted.verified()),
        "live content drift changed the verdict: {} vs {}",
        with_tree.summary(),
        drifted.summary()
    );
    assert_eq!(
        (with_tree.code, with_tree.verified()),
        (without_tree.code, without_tree.verified()),
        "deleting the live tree changed the verdict: {} vs {}",
        with_tree.summary(),
        without_tree.summary()
    );
    assert_eq!(with_tree.code, 0);
    assert_eq!(with_tree.verified(), 2);
}

/// `quarantine/` holds the raw, un-redacted originals. `verify`'s scratch pass
/// must neither read them nor name them: they are the one place in the store
/// where a secret still exists verbatim.
#[test]
fn p10_verify_never_touches_quarantine() {
    let fx = Fx::new("quarantine");
    fx.write(
        "scratchpad/leak.md",
        format!("aws_access_key_id = {FIXTURE_AKIA}\n").as_bytes(),
    );
    fx.archive();

    let q = fx.yomi_home.join("quarantine");
    let originals: Vec<(PathBuf, Vec<u8>, i64)> = walk(&q)
        .into_iter()
        .map(|p| {
            let md = std::fs::metadata(&p).unwrap();
            (p.clone(), std::fs::read(&p).unwrap(), md.atime())
        })
        .collect();
    assert!(
        !originals.is_empty(),
        "fixture produced no quarantine originals; the reach test is vacuous"
    );
    assert!(
        originals
            .iter()
            .any(|(_, b, _)| contains(b, FIXTURE_AKIA.as_bytes())),
        "quarantine does not hold the raw secret; fixture is wrong"
    );

    // Corrupt the store so every failure path runs while quarantine sits beside it.
    for z in zst_under(&fx.store_dir()) {
        std::fs::write(&z, b"NOT-A-ZSTD-FRAME").unwrap();
    }
    let v = fx.verify();
    let (t_out, t_err) = fx.verify_text();

    for (label, text) in [
        ("json", &v.stdout),
        ("json stderr", &v.stderr),
        ("text", &t_out),
        ("text stderr", &t_err),
    ] {
        assert!(
            !contains(text.as_bytes(), FIXTURE_AKIA.as_bytes()),
            "{label} exposed the quarantined original"
        );
        assert!(
            !text.contains("quarantine"),
            "{label} named the quarantine tree: {text}"
        );
    }
    for (p, before, _) in &originals {
        assert_eq!(
            &std::fs::read(p).unwrap(),
            before,
            "verify modified a quarantined original"
        );
    }
}

/// The non-exposure claim is about *content*, not *names*. A filename is carried
/// verbatim into the manifest and printed back as `rel`, so a secret in a
/// filename reaches the output. Pinned so the boundary of the claim is explicit
/// and nobody later reads "structural non-exposure" as covering names.
#[test]
fn p10_non_exposure_covers_content_not_filenames() {
    let fx = Fx::new("names");
    fx.write(&format!("scratchpad/{FIXTURE_AKIA}.md"), b"body\n");
    fx.archive();
    std::fs::write(
        fx.store_dir()
            .join(format!("scratchpad/{FIXTURE_AKIA}.md.zst")),
        b"NOT-A-ZSTD-FRAME",
    )
    .unwrap();

    let v = fx.verify();
    assert_eq!(v.code, 2);
    assert!(
        contains(v.stdout.as_bytes(), FIXTURE_AKIA.as_bytes()),
        "behaviour changed: filenames no longer reach the output, so this note is \
         stale"
    );
}

/// `decompress_all` is `zstd::decode_all` into an unbounded `Vec`. The GC gate
/// caps a live re-read at 64MB and `read_source` caps a source at 256MB; this
/// path caps nothing, so a crafted artifact expands as far as it likes.
///
/// Held to a deliberately modest 64MB here — the point is the ratio (a ~2KB
/// artifact expanding 30,000x), not the absolute size, and an assertion that
/// allocated gigabytes would be an OOM-prone thing to put in CI. Current
/// behaviour is pinned: verify swallows it and reports a mismatch.
#[test]
fn p10_decompressing_an_artifact_is_unbounded() {
    let fx = Fx::new("bomb");
    fx.write("scratchpad/a.md", b"x\n");
    fx.archive();

    // 64 concatenated frames of 1MB of zeros — `decompress_all` reads
    // concatenated frames transparently, so this expands to 64MB.
    let frame = yomi::archive::compress::compress_frame(&vec![0u8; 1024 * 1024]).unwrap();
    let mut bomb = Vec::new();
    for _ in 0..64 {
        bomb.extend_from_slice(&frame);
    }
    let ratio = (64 * 1024 * 1024) / bomb.len().max(1);
    assert!(
        ratio > 1000,
        "fixture is not a compression bomb (ratio {ratio}:1)"
    );
    std::fs::write(fx.store_dir().join("scratchpad/a.md.zst"), &bomb).unwrap();

    let v = fx.verify();
    assert_eq!(
        v.issues("violations"),
        vec!["ContentMismatch"],
        "a {ratio}:1 artifact was not simply expanded and hashed: {}",
        v.summary()
    );
}

// ---------------------------------------------------------------------------
// D. Store-directory classification — the fourth caller.
// ---------------------------------------------------------------------------

/// A store directory that is a symlink is foreign evidence: refused, not read.
#[test]
fn p10_symlinked_store_dir_is_refused_not_read() {
    let fx = Fx::new("symkey");
    fx.write("scratchpad/a.md", b"a\n");
    fx.archive();

    let elsewhere = fx.base.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(
        elsewhere.join("manifest.json"),
        br#"{"entries":[{"path":"planted.md","bytes":1,"stored":true,"content_sha256":"dead"}]}"#,
    )
    .unwrap();
    std::fs::remove_dir_all(fx.store_dir()).unwrap();
    std::os::unix::fs::symlink(&elsewhere, fx.store_dir()).unwrap();

    let v = fx.verify();
    assert_eq!(
        v.issues("refused"),
        vec!["ForeignStoreDir"],
        "{}",
        v.summary()
    );
    assert_eq!(
        v.code,
        2,
        "a refused key must fail the run: {}",
        v.summary()
    );
    // Nothing from the foreign ledger may appear as a finding about the store.
    assert!(
        v.issues("violations").is_empty(),
        "findings were drawn from a foreign ledger: {}",
        v.summary()
    );
}

/// The same principle one level up: `archive/_scratch` itself replaced by a
/// symlink. `classify_store_dir` guards each key directory, but the root is
/// reached with a plain `read_dir`, which follows. Every key below is then
/// foreign, and the design's rule — a foreign ledger must not be read at all —
/// should apply to the root as much as to a key.
#[test]
fn p10_symlinked_scratch_root_is_not_read_as_our_store() {
    let fx = Fx::new("symroot");
    fx.write("scratchpad/a.md", b"a\n");
    fx.archive();

    // Move the real store aside and plant a foreign tree in its place.
    let foreign = fx.base.join("foreign_scratch");
    std::fs::rename(fx.yomi_home.join("archive/_scratch"), &foreign).unwrap();
    std::fs::write(
        foreign
            .join(format!("{}--{}", fx.slug, fx.uuid))
            .join("manifest.json"),
        br#"{"entries":[{"path":"planted.md","bytes":1,"stored":true,"content_sha256":"dead"}]}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(&foreign, fx.yomi_home.join("archive/_scratch")).unwrap();

    let v = fx.verify();
    assert!(
        v.issues("violations").is_empty(),
        "verify drew violations from a ledger outside the archive tree, reached \
         through a symlinked `_scratch` root — the per-key classifier does not \
         guard the root, which `read_dir` follows: {}",
        v.summary()
    );
}

// ---------------------------------------------------------------------------
// E. The three checks verify is forbidden to make.
// ---------------------------------------------------------------------------

/// `bytes` is a fact about the live tree and `source_sha256` a fact about a past
/// capture; neither is checkable from the store, and a salvaged entry legitimately
/// carries a current `bytes` beside an older capture's hashes. Corrupting both
/// must change nothing.
#[test]
fn p10_bytes_and_source_sha256_are_never_consulted() {
    let fx = Fx::new("forbidden");
    fx.write("scratchpad/a.md", b"content-a\n");
    fx.archive();
    let before = fx.verify();
    assert_eq!(before.code, 0);
    assert_eq!(before.verified(), 1);

    fx.edit_entries(|e| {
        e["bytes"] = serde_json::json!(999_999);
        e["source_sha256"] = serde_json::json!("00000000000000000000000000000000");
    });

    let after = fx.verify();
    assert_eq!(
        (after.code, after.verified()),
        (before.code, before.verified()),
        "a `bytes`/`source_sha256` mismatch changed the verdict — verify is \
         making a check it has no evidence for: {} vs {}",
        before.summary(),
        after.summary()
    );
    assert!(after.issues("violations").is_empty(), "{}", after.summary());
}

// ---------------------------------------------------------------------------
// F. Boundaries and session scoping.
// ---------------------------------------------------------------------------

/// A store that has never archived scratch is not a defect, and verifying it
/// must not bring `_scratch` into existence.
#[test]
fn p10_fresh_store_verifies_clean_and_creates_nothing() {
    let fx = Fx::new("fresh");
    fx.write("scratchpad/a.md", b"a\n");
    // Archive transcripts only, so the store exists but `_scratch` never does.
    let out = fx.run(&["archive", "--all", "--include", "transcript"]);
    assert!(
        out.status.success(),
        "fixture archive failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        fx.yomi_home.join("archive").is_dir(),
        "fixture did not initialize a store"
    );

    let v = fx.verify();
    assert_eq!(v.code, 0, "{}", v.summary());
    assert_eq!(v.keys(), 0, "{}", v.summary());
    assert!(
        !fx.yomi_home.join("archive/_scratch").exists(),
        "verify created the scratch store root"
    );
}

/// Degenerate store shapes: an empty key directory, a key with only a manifest,
/// and a key with only artifacts.
#[test]
fn p10_degenerate_store_shapes_are_classified() {
    let fx = Fx::new("shapes");
    fx.write("scratchpad/a.md", b"a\n");
    fx.archive();
    let root = fx.yomi_home.join("archive/_scratch");

    // Empty key dir → no manifest at all.
    std::fs::create_dir_all(root.join("-empty--key")).unwrap();
    // Manifest-only, claiming nothing.
    let mo = root.join("-manifest--only");
    std::fs::create_dir_all(&mo).unwrap();
    std::fs::write(mo.join("manifest.json"), br#"{"entries":[]}"#).unwrap();
    // Artifacts with no manifest.
    let ao = root.join("-artifacts--only");
    std::fs::create_dir_all(&ao).unwrap();
    std::fs::write(ao.join("stray.md.zst"), b"junk").unwrap();

    let v = fx.verify();
    let violations = v.issues("violations");
    assert_eq!(
        violations.iter().filter(|i| *i == "NoManifest").count(),
        2,
        "an empty key dir and an artifacts-only key must both be NoManifest: {}",
        v.summary()
    );
    assert_eq!(v.keys(), 4, "{}", v.summary());
    assert_eq!(v.code, 2, "{}", v.summary());
}

/// N33: a session whose store key is hex-encoded (because its slug or uuid is
/// not UTF-8) cannot be selected by its real uuid — `key.ends_with("--<uuid>")`
/// never matches the hex form. The run then reports zero keys and exits 0, which
/// is exactly what a clean verify of a healthy session looks like. An operator
/// scoping a nightly check to one session is told "all clear" about a store that
/// was never examined.
#[test]
fn p10_hex_key_session_scoping_is_not_silently_empty() {
    use std::os::unix::ffi::OsStringExt;
    let fx = Fx::new("n33");
    // A non-UTF-8 *slug* forces the hex key while leaving the uuid typeable.
    let mut slug = fx.tmp_root.clone().into_os_string().into_vec();
    slug.extend_from_slice(b"/-proj-\xff");
    let sess = PathBuf::from(std::ffi::OsString::from_vec(slug)).join(&fx.uuid);
    std::fs::create_dir_all(sess.join("scratchpad")).unwrap();
    std::fs::write(sess.join("scratchpad/a.md"), b"payload\n").unwrap();
    let _ = std::fs::remove_dir_all(fx.session_dir());
    fx.archive();

    let all = fx.verify();
    assert_eq!(
        all.keys(),
        1,
        "fixture produced no store: {}",
        all.summary()
    );
    assert_eq!(all.verified(), 1, "{}", all.summary());

    let scoped = fx.verify_args(&["verify", &fx.uuid, "--json"]);
    assert_eq!(
        scoped.keys(),
        1,
        "scoping to the session's real uuid examined {} store dirs instead of 1, \
         and exited {} — indistinguishable from a clean check of a healthy \
         session. The key is hex-encoded, so `--<uuid>` never matches it: {}",
        scoped.keys(),
        scoped.code,
        scoped.summary()
    );
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
