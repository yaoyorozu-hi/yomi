//! P12 break tests: adversarial assault on U4 — `yomi read --scratch`.
//!
//! U4's safety is claimed as **type-level impossibility**: `ScratchStore` cannot
//! exist without its root and key having been classified, `StoredEntry` has no
//! public constructor, and `read()` takes no arguments — so there is no function
//! anywhere that turns user input into a path. These tests take that claim
//! seriously and attack what it does *not* cover: what happens after a path the
//! manifest supplied is handed to the filesystem.
//!
//! Written to BREAK, not to confirm. Every fixture is fabricated under
//! `CARGO_TARGET_TMPDIR`; nothing is written to `/`, to the repository working
//! copy, or outside the build tree, and no real Claude Code data is touched.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
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
        Self::with_config(tag, "")
    }

    fn with_config(tag: &str, cfg: &str) -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "p12-{tag}-{}-{}",
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
            uuid: "s1".to_string(),
            base,
        };
        std::fs::create_dir_all(fx.home.join(".claude/projects").join(&fx.slug)).unwrap();
        for d in [&fx.tmp_root, &fx.cache_home, &fx.proc_root, &fx.yomi_home] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::set_permissions(&fx.yomi_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        if !cfg.is_empty() {
            std::fs::write(fx.yomi_home.join("config.toml"), cfg).unwrap();
        }
        std::fs::create_dir_all(fx.session_dir().join("scratchpad")).unwrap();
        fx
    }

    fn key(&self) -> String {
        format!("{}--{}", self.slug, self.uuid)
    }

    fn session_dir(&self) -> PathBuf {
        self.tmp_root.join(&self.slug).join(&self.uuid)
    }

    fn store_dir(&self) -> PathBuf {
        self.yomi_home.join("archive/_scratch").join(self.key())
    }

    fn write(&self, rel: &str, bytes: &[u8]) {
        let p = self.session_dir().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    fn run_os(&self, args: &[&OsStr]) -> Out {
        let out = Command::new(BIN)
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
            code: out.status.code().unwrap(),
            stdout: out.stdout,
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn run(&self, args: &[&str]) -> Out {
        let os: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        self.run_os(&os)
    }

    fn archive(&self) {
        let o = self.run(&["archive", "--all", "--include", "scratch"]);
        assert_eq!(o.code, 0, "archive failed: {}", o.stderr);
    }

    /// `read --scratch <key> --file <rel>` with `rel` as raw bytes.
    fn read_file_os(&self, rel: &OsStr) -> Out {
        let key = self.key();
        self.run_os(&[
            OsStr::new("read"),
            OsStr::new("--scratch"),
            OsStr::new(&key),
            OsStr::new("--file"),
            rel,
        ])
    }

    fn read_file(&self, rel: &str) -> Out {
        self.read_file_os(OsStr::new(rel))
    }

    fn read_file_json(&self, rel: &str) -> Out {
        let key = self.key();
        self.run(&["read", "--scratch", &key, "--file", rel, "--json"])
    }

    fn listing_json(&self) -> serde_json::Value {
        let key = self.key();
        let o = self.run(&["read", "--scratch", &key, "--json"]);
        serde_json::from_slice(&o.stdout)
            .unwrap_or_else(|e| panic!("listing json ({e}): {}", o.text()))
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
}

struct Out {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
}

impl Out {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
    /// Everything a caller could see, for leak checks.
    fn all(&self) -> Vec<u8> {
        let mut v = self.stdout.clone();
        v.extend_from_slice(self.stderr.as_bytes());
        v
    }
    fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.stdout).ok()
    }
    fn summary(&self) -> String {
        format!(
            "exit={} stdout={:?} stderr={:?}",
            self.code,
            String::from_utf8_lossy(&self.stdout)
                .chars()
                .take(200)
                .collect::<String>(),
            self.stderr.trim()
        )
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
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

// ---------------------------------------------------------------------------
// A. What the type claim does not cover: the path is safe, the *file* is not.
// ---------------------------------------------------------------------------

/// `read()` opens `<store dir>/<rel>.zst` with `std::fs::read`, which **follows
/// symlinks**. The path is unimpeachable — derived from the manifest, all
/// components `Normal` — but the object at the end of it is never classified, so
/// a symlink planted at an artifact makes `read --file` emit bytes from outside
/// the archive tree, presented as that entry's stored content.
///
/// `verify` already refuses exactly this object as `ForeignArtifact`, on the
/// stated ground that acting on it "would widen the authority past the artifacts
/// we stored". The retrieval path does not apply the same rule, so the two
/// layers disagree about what an artifact is.
#[test]
fn p12_symlinked_artifact_is_not_followed_out_of_the_store() {
    let fx = Fx::new("symartifact");
    fx.write("scratchpad/a.md", b"REAL-STORED-CONTENT\n");
    fx.archive();

    // A valid zstd frame that yomi never stored for this entry, outside the tree.
    let outside = fx.base.join("outside.zst");
    std::fs::write(
        &outside,
        yomi::archive::compress::compress_frame(b"CONTENT-FROM-OUTSIDE-THE-ARCHIVE\n").unwrap(),
    )
    .unwrap();

    let artifact = fx.store_dir().join("scratchpad/a.md.zst");
    std::fs::remove_file(&artifact).unwrap();
    std::os::unix::fs::symlink(&outside, &artifact).unwrap();

    let o = fx.read_file("scratchpad/a.md");
    assert!(
        !contains(&o.stdout, b"CONTENT-FROM-OUTSIDE-THE-ARCHIVE"),
        "read followed a symlinked artifact and emitted bytes from {} as this \
         entry's stored content. `verify` classifies the same object \
         ForeignArtifact and refuses it; retrieval applies no such check. {}",
        outside.display(),
        o.summary()
    );
}

/// The same asymmetry stated as a contract: whatever `verify` refuses to treat
/// as an artifact, `read` must also refuse. Runs both against one store so the
/// disagreement is visible in a single fixture.
#[test]
fn p12_verify_and_read_agree_on_what_an_artifact_is() {
    let fx = Fx::new("agree");
    fx.write("scratchpad/a.md", b"REAL\n");
    fx.archive();
    let outside = fx.base.join("outside.zst");
    std::fs::write(
        &outside,
        yomi::archive::compress::compress_frame(b"OUTSIDE\n").unwrap(),
    )
    .unwrap();
    let artifact = fx.store_dir().join("scratchpad/a.md.zst");
    std::fs::remove_file(&artifact).unwrap();
    std::os::unix::fs::symlink(&outside, &artifact).unwrap();

    let v = fx.run(&["verify", "--json"]);
    let vj = v.json().expect("verify json");
    let refused_by_verify = !vj["scratch"]["foreign_matter"]
        .as_array()
        .unwrap()
        .is_empty();
    let read = fx.read_file("scratchpad/a.md");
    let served_by_read = read.code == 0 && !read.stdout.is_empty();

    assert!(
        !(refused_by_verify && served_by_read),
        "verify refuses this object as foreign matter while read serves its \
         contents (exit {}, {} bytes). One store, two answers.",
        read.code,
        read.stdout.len()
    );
}

// ---------------------------------------------------------------------------
// B. The output contract on the failure paths.
// ---------------------------------------------------------------------------

/// A manifest that claims an artifact the store does not hold — `verify`'s
/// `MissingArtifact` violation, and the state a concurrent `archive` passes
/// through when it reconciles away what an older ledger claimed (N41).
///
/// Every other refusal in `read --scratch` is a structured `{error, reason}` at
/// EXIT_PARTIAL. This one escapes as a raw `anyhow` chain at exit 1, and
/// `--json` prints no JSON at all — so a JSON consumer gets an unparseable
/// stream and an exit code the documented vocabulary does not contain.
///
/// **Pins current behaviour.** If the window is closed or the error is given a
/// code, this expectation changes.
#[test]
fn p12_missing_artifact_refuses_in_the_documented_vocabulary() {
    let fx = Fx::new("missing");
    fx.write("scratchpad/a.md", b"x\n");
    fx.archive();
    std::fs::remove_file(fx.store_dir().join("scratchpad/a.md.zst")).unwrap();

    let j = fx.read_file_json("scratchpad/a.md");
    assert!(
        j.json().is_some(),
        "`--file --json` emitted no JSON for a missing artifact, so a JSON \
         consumer cannot tell what happened: {}",
        j.summary()
    );
    assert_eq!(
        j.code,
        2,
        "a missing artifact exits {} rather than EXIT_PARTIAL: {}",
        j.code,
        j.summary()
    );
}

/// Whatever the exit code, the failure must not leak the store's absolute
/// layout into an operator-facing error more than the other refusals do.
/// Documents what the raw error currently exposes.
#[test]
fn p12_missing_artifact_error_names_no_content() {
    let fx = Fx::new("missing-leak");
    fx.write("scratchpad/a.md", format!("{FIXTURE_AKIA}\n").as_bytes());
    fx.archive();
    std::fs::remove_file(fx.store_dir().join("scratchpad/a.md.zst")).unwrap();

    for o in [
        fx.read_file("scratchpad/a.md"),
        fx.read_file_json("scratchpad/a.md"),
    ] {
        assert!(
            !contains(&o.all(), FIXTURE_AKIA.as_bytes()),
            "the missing-artifact error carried content: {}",
            o.summary()
        );
    }
}

// ---------------------------------------------------------------------------
// C. N40 — the reconstructed reason.
// ---------------------------------------------------------------------------

/// `not_stored_reason` reconstructs the cause from the **current** config, but
/// the outcome it explains was decided under the config in force at capture.
/// Widening `file_cap` afterwards silently rewrites history: the entry that was
/// rejected for being over the cap is now explained as one the globs declined.
///
/// The globs never declined it — `*.md` admits it, then and now.
#[test]
fn p12_not_stored_reason_survives_a_config_change() {
    let fx = Fx::with_config("n40", "[scratch]\nfile_cap = \"1KB\"\n");
    fx.write("scratchpad/big.md", &vec![b'B'; 5000]);
    fx.archive();

    let under_capture_config = fx.read_file_json("scratchpad/big.md");
    let first = under_capture_config.json().expect("json");
    assert!(
        first["reason"].as_str().unwrap().contains("file_cap"),
        "fixture did not reproduce an over-file_cap rejection: {first}"
    );

    // The operator widens the cap later. The store is untouched.
    std::fs::write(
        fx.yomi_home.join("config.toml"),
        "[scratch]\nfile_cap = \"10MB\"\n",
    )
    .unwrap();
    let after = fx.read_file_json("scratchpad/big.md");
    let second = after.json().expect("json");

    assert_eq!(
        first["reason"],
        second["reason"],
        "the explanation for an unchanged store changed when the config did: \
         {:?} -> {:?}. The cause is reconstructed from the config in force *now*, \
         not the one in force at capture, so a widened cap makes yomi blame the \
         globs for a rejection they had no part in.",
        first["reason"].as_str(),
        second["reason"].as_str()
    );
}

/// The four causes must be told apart. `capture_failed` outranks policy, the
/// tree cap outranks the per-file rules, and the globs are what is left.
#[test]
fn p12_the_four_not_stored_causes_are_distinguished() {
    // (i) over total_cap
    let over = Fx::with_config("cause-total", "[scratch]\ntotal_cap = \"1KB\"\n");
    over.write("scratchpad/a.md", &vec![b'a'; 800]);
    over.write("scratchpad/b.md", &vec![b'b'; 800]);
    over.archive();
    let r = over.read_file_json("scratchpad/a.md");
    let j = r.json().expect("json");
    assert!(
        j["reason"].as_str().unwrap().contains("total_cap"),
        "over-cap entry not explained by the tree cap: {j}"
    );

    // (ii) over file_cap
    let big = Fx::with_config("cause-file", "[scratch]\nfile_cap = \"1KB\"\n");
    big.write("scratchpad/a.md", &vec![b'a'; 5000]);
    big.archive();
    let j = big.read_file_json("scratchpad/a.md").json().expect("json");
    assert!(
        j["reason"].as_str().unwrap().contains("file_cap"),
        "over-file_cap entry not explained by the file cap: {j}"
    );

    // (iii) globs
    let denied = Fx::new("cause-glob");
    denied.write("scratchpad/a.bin", b"binary\n");
    denied.archive();
    let j = denied
        .read_file_json("scratchpad/a.bin")
        .json()
        .expect("json");
    assert!(
        j["reason"].as_str().unwrap().contains("globs"),
        "deny-listed entry not explained by the globs: {j}"
    );
    // Each cause must be distinct prose, or the dispatch is decorative.
    let all = [
        over.read_file_json("scratchpad/a.md").json().unwrap()["reason"]
            .as_str()
            .unwrap()
            .to_string(),
        big.read_file_json("scratchpad/a.md").json().unwrap()["reason"]
            .as_str()
            .unwrap()
            .to_string(),
        j["reason"].as_str().unwrap().to_string(),
    ];
    let uniq: std::collections::HashSet<&String> = all.iter().collect();
    assert_eq!(uniq.len(), 3, "causes are not distinguished: {all:?}");
}

// ---------------------------------------------------------------------------
// D. Non-exposure — the boundary is narrower here than in verify.
// ---------------------------------------------------------------------------

/// `--file` must serve the **stored** bytes, never the live file. Proved by
/// making them disagree: archive, then rewrite the live source, then read.
#[test]
fn p12_file_serves_stored_bytes_not_the_live_source() {
    let fx = Fx::new("stored-not-live");
    fx.write("scratchpad/a.md", b"ORIGINAL-ARCHIVED-CONTENT\n");
    fx.archive();
    fx.write("scratchpad/a.md", b"LIVE-REWRITTEN-AFTER-ARCHIVE\n");

    let o = fx.read_file("scratchpad/a.md");
    assert_eq!(o.code, 0, "{}", o.summary());
    assert_eq!(
        o.stdout,
        b"ORIGINAL-ARCHIVED-CONTENT\n",
        "read served the live source instead of the stored bytes: {}",
        o.summary()
    );
    // And with the live tree gone entirely, the answer must not change.
    std::fs::remove_dir_all(fx.session_dir()).unwrap();
    let after = fx.read_file("scratchpad/a.md");
    assert_eq!(
        after.stdout, o.stdout,
        "deleting the live tree changed what read returned"
    );
}

/// A secret redacted on the way in must come back redacted, and the quarantined
/// original — the one place the raw bytes still exist — must be neither read nor
/// named nor modified.
#[test]
fn p12_read_serves_redacted_bytes_and_never_quarantine() {
    let fx = Fx::new("redaction");
    fx.write(
        "scratchpad/leak.md",
        format!("aws_access_key_id = {FIXTURE_AKIA}\n").as_bytes(),
    );
    fx.archive();

    let q = fx.yomi_home.join("quarantine");
    let before: Vec<(PathBuf, Vec<u8>)> = walk(&q)
        .into_iter()
        .map(|p| (p.clone(), std::fs::read(&p).unwrap()))
        .collect();
    assert!(
        before
            .iter()
            .any(|(_, b)| contains(b, FIXTURE_AKIA.as_bytes())),
        "fixture produced no quarantined original holding the raw secret"
    );

    let outs = [
        fx.read_file("scratchpad/leak.md"),
        fx.read_file_json("scratchpad/leak.md"),
        fx.run(&["read", "--scratch", &fx.key()]),
        fx.run(&["read", "--scratch", &fx.key(), "--json"]),
    ];
    for o in &outs {
        assert!(
            !contains(&o.all(), FIXTURE_AKIA.as_bytes()),
            "the raw secret reached the output: {}",
            o.summary()
        );
        assert!(
            !o.all().windows(10).any(|w| w == b"quarantine"),
            "output named the quarantine tree: {}",
            o.summary()
        );
    }
    for (p, b) in &before {
        assert_eq!(
            &std::fs::read(p).unwrap(),
            b,
            "read modified a quarantined original"
        );
    }
}

/// `decompress_all` is `zstd::decode_all` into an unbounded `Vec`, and the
/// retrieval path reaches it with no size check — the same gap measured in
/// `verify` (U3), present here too. Held to 64MB deliberately: the point is the
/// ratio, and an assertion that allocated gigabytes would be an OOM-prone thing
/// to leave in CI. Current behaviour pinned.
#[test]
fn p12_reading_an_artifact_is_unbounded() {
    let fx = Fx::new("bomb");
    fx.write("scratchpad/a.md", b"x\n");
    fx.archive();

    let frame = yomi::archive::compress::compress_frame(&vec![0u8; 1024 * 1024]).unwrap();
    let mut bomb = Vec::new();
    for _ in 0..64 {
        bomb.extend_from_slice(&frame);
    }
    let ratio = (64 * 1024 * 1024) / bomb.len().max(1);
    assert!(ratio > 1000, "fixture is not a bomb (ratio {ratio}:1)");
    std::fs::write(fx.store_dir().join("scratchpad/a.md.zst"), &bomb).unwrap();

    let o = fx.read_file("scratchpad/a.md");
    assert_eq!(
        o.stdout.len(),
        64 * 1024 * 1024,
        "a {ratio}:1 artifact was not simply expanded and written out: {}",
        o.summary()
    );
}

// ---------------------------------------------------------------------------
// E. Traversal — the "unrepresentable" claim.
// ---------------------------------------------------------------------------

/// Hostile `--file` values must match no entry and open nothing. `find` is a
/// byte comparison against the ledger, so none of these can name anything; the
/// point is that none of them errors in a way that reveals a path was built.
#[test]
fn p12_hostile_file_values_match_nothing() {
    let fx = Fx::new("traversal");
    fx.write("scratchpad/a.md", b"secret-ish\n");
    fx.archive();
    let canary = fx.base.join("canary.txt");
    std::fs::write(&canary, b"MUST-NOT-BE-READ\n").unwrap();

    let hostile: Vec<OsString> = vec![
        OsString::from("../../../etc/passwd"),
        OsString::from("/etc/passwd"),
        OsString::from("../../outside.zst"),
        OsString::from(canary.to_string_lossy().to_string()),
        OsString::from("scratchpad/../scratchpad/a.md"),
        OsString::from("./scratchpad/a.md"),
        OsString::from("scratchpad//a.md"),
        OsString::from("scratchpad/a.md/"),
        OsString::from("scratchpad/a.md.zst"),
        OsString::from("scratchpad/a.m"),
        OsString::from("scratchpad/a.mdX"),
        OsString::from(""),
        OsString::from("."),
        OsString::from(".."),
        OsString::from("/"),
        // No NUL case: argv is NUL-terminated, so `Command` refuses to spawn
        // with one at all. A NUL never reaches yomi's argument parsing on any
        // Unix, which is a stronger guarantee than anything yomi could add.
        OsString::from_vec(b"scratchpad/\xff.md".to_vec()),
    ];
    for h in &hostile {
        let o = fx.read_file_os(h);
        assert_ne!(o.code, 0, "hostile --file {h:?} succeeded: {}", o.summary());
        assert!(
            !contains(&o.all(), b"MUST-NOT-BE-READ"),
            "hostile --file {h:?} read the canary: {}",
            o.summary()
        );
        assert!(
            !contains(&o.all(), b"root:x:"),
            "hostile --file {h:?} read /etc/passwd: {}",
            o.summary()
        );
    }
}

/// The same attack from inside the ledger: a forged manifest whose `path` and
/// `path_hex` carry traversal. `ScratchRel::from_manifest` admits only `Normal`
/// components, so such an entry must decode to nothing and be unaddressable.
#[test]
fn p12_forged_manifest_traversal_is_unaddressable() {
    let fx = Fx::new("forged");
    fx.write("scratchpad/a.md", b"real\n");
    fx.archive();
    let canary = fx.base.join("canary.zst");
    std::fs::write(
        &canary,
        yomi::archive::compress::compress_frame(b"CANARY-CONTENT\n").unwrap(),
    )
    .unwrap();

    let mut mf = fx.manifest();
    let hex_of = |s: &str| {
        s.as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    for (path, hex) in [
        ("../canary".to_string(), None),
        ("../../canary".to_string(), None),
        ("/etc/passwd".to_string(), None),
        ("x".to_string(), Some(hex_of("../canary"))),
        ("x".to_string(), Some(hex_of("/etc/passwd"))),
    ] {
        let mut e = serde_json::json!({
            "path": path, "bytes": 1, "stored": true,
            "content_sha256": "dead", "source_sha256": "beef",
        });
        if let Some(h) = hex {
            e["path_hex"] = serde_json::Value::String(h);
        }
        mf["entries"].as_array_mut().unwrap().push(e);
    }
    fx.write_manifest(&mf);

    for probe in ["../canary", "../../canary", "/etc/passwd", "x"] {
        let o = fx.read_file(probe);
        assert_ne!(
            o.code,
            0,
            "forged entry {probe:?} was served: {}",
            o.summary()
        );
        assert!(
            !contains(&o.all(), b"CANARY-CONTENT"),
            "forged entry {probe:?} reached outside the store: {}",
            o.summary()
        );
    }
    // The genuine entry must still work — the forgery must not break the store.
    let good = fx.read_file("scratchpad/a.md");
    assert_eq!(good.code, 0, "{}", good.summary());
    assert_eq!(good.stdout, b"real\n");
}

// ---------------------------------------------------------------------------
// F. Selector resolution.
// ---------------------------------------------------------------------------

/// A hex key is addressed by the session's real bytes, and a plain-looking
/// string that merely resembles a hex field must not reach it. The shared
/// resolver dispatches on form; it must not try both.
#[test]
fn p12_hex_key_is_not_addressable_by_its_hex_text() {
    let fx = Fx::new("hexsel");
    // Non-UTF-8 slug forces the hex key while leaving the uuid typeable.
    let mut slug = fx.tmp_root.clone().into_os_string().into_vec();
    slug.extend_from_slice(b"/-proj-\xff");
    let sess = PathBuf::from(OsString::from_vec(slug)).join("u1");
    std::fs::create_dir_all(sess.join("scratchpad")).unwrap();
    std::fs::write(sess.join("scratchpad/a.md"), b"payload\n").unwrap();
    let _ = std::fs::remove_dir_all(fx.session_dir());
    fx.archive();

    let root = fx.yomi_home.join("archive/_scratch");
    let key = std::fs::read_dir(&root)
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .file_name()
        .to_string_lossy()
        .into_owned();
    assert!(
        key.starts_with("_hex--"),
        "fixture produced no hex key: {key}"
    );

    // The real uuid resolves it.
    let by_uuid = fx.run(&["read", "--scratch", "u1", "--json"]);
    assert_eq!(
        by_uuid.code,
        0,
        "hex key unreachable by its uuid: {}",
        by_uuid.summary()
    );
    // The full key resolves it.
    let by_key = fx.run(&["read", "--scratch", &key, "--json"]);
    assert_eq!(by_key.code, 0, "{}", by_key.summary());
    // The hex *text* of the uuid field must not.
    let hex_uuid: String = "u1".bytes().map(|b| format!("{b:02x}")).collect();
    let by_hextext = fx.run(&["read", "--scratch", &hex_uuid, "--json"]);
    assert_ne!(
        by_hextext.code,
        0,
        "the hex text {hex_uuid:?} resolved a store; the resolver is trying both \
         forms: {}",
        by_hextext.summary()
    );
}

/// A duplicated identity in the ledger: `find` returns the first match, so a
/// shadowing `stored: false` twin makes a genuinely stored file unreadable.
/// The store still holds the bytes and `verify` still passes them.
#[test]
fn p12_duplicate_ledger_identity_does_not_shadow_the_real_entry() {
    let fx = Fx::new("dup");
    fx.write("scratchpad/a.md", b"REAL-CONTENT\n");
    fx.archive();
    assert_eq!(fx.read_file("scratchpad/a.md").stdout, b"REAL-CONTENT\n");

    let mut mf = fx.manifest();
    let mut twin = mf["entries"][0].clone();
    twin["stored"] = serde_json::Value::Bool(false);
    twin.as_object_mut().unwrap().remove("source_sha256");
    twin.as_object_mut().unwrap().remove("content_sha256");
    mf["entries"].as_array_mut().unwrap().insert(0, twin);
    fx.write_manifest(&mf);

    let o = fx.read_file("scratchpad/a.md");
    assert_eq!(
        o.stdout,
        b"REAL-CONTENT\n",
        "a duplicated ledger entry shadowed the real one, so stored bytes that \
         are still on disk became unreachable: {}",
        o.summary()
    );
}

// ---------------------------------------------------------------------------
// G. Store classification at retrieval.
// ---------------------------------------------------------------------------

/// A symlinked store **root** must be refused. `verify` reaches its root with a
/// plain `read_dir` and follows it; retrieval classifies the root first, so this
/// is the layer that gets it right. Pinned so a later refactor cannot quietly
/// align them the wrong way.
#[test]
fn p12_symlinked_store_root_is_refused_at_retrieval() {
    let fx = Fx::new("symroot");
    fx.write("scratchpad/a.md", b"x\n");
    fx.archive();

    let foreign = fx.base.join("foreign_root");
    std::fs::rename(fx.yomi_home.join("archive/_scratch"), &foreign).unwrap();
    std::os::unix::fs::symlink(&foreign, fx.yomi_home.join("archive/_scratch")).unwrap();

    let o = fx.run(&["read", "--scratch", &fx.key(), "--json"]);
    let j = o.json().expect("json");
    assert_eq!(
        j["error"],
        "ForeignStoreRoot",
        "a symlinked store root was read through: {}",
        o.summary()
    );
    assert_ne!(o.code, 0, "{}", o.summary());
}

/// A symlinked store **directory** must be refused with its own reason, and
/// never confused with "not found" — the store exists, it is just not ours.
#[test]
fn p12_symlinked_store_dir_is_refused_distinctly() {
    let fx = Fx::new("symdir");
    fx.write("scratchpad/a.md", b"x\n");
    fx.archive();
    let elsewhere = fx.base.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("manifest.json"), br#"{"entries":[]}"#).unwrap();
    std::fs::remove_dir_all(fx.store_dir()).unwrap();
    std::os::unix::fs::symlink(&elsewhere, fx.store_dir()).unwrap();

    let o = fx.run(&["read", "--scratch", &fx.key(), "--json"]);
    let j = o.json().expect("json");
    assert_eq!(
        j["error"],
        "ForeignStoreDir",
        "expected a distinct refusal, not {}: {}",
        j["error"],
        o.summary()
    );
}

/// An ambiguous selector must name the candidates and refuse, never guess.
#[test]
fn p12_ambiguous_selector_is_refused_with_its_candidates() {
    let fx = Fx::new("ambig");
    let _ = std::fs::remove_dir_all(fx.session_dir());
    for slug in ["-a--u1", "-b"] {
        let d = fx.tmp_root.join(slug).join("u1").join("scratchpad");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("f.md"), b"x\n").unwrap();
    }
    fx.archive();

    let o = fx.run(&["read", "--scratch", "u1", "--json"]);
    let j = o.json().expect("json");
    assert_eq!(j["error"], "Ambiguous", "{}", o.summary());
    let reason = j["reason"].as_str().unwrap();
    assert!(
        reason.contains("-a--u1--u1") && reason.contains("-b--u1"),
        "the refusal does not name both candidates: {reason}"
    );
    assert_ne!(o.code, 0, "{}", o.summary());
}

/// Non-UTF-8 entries: the listing's `rel_hex` says which bytes to ask for, and
/// asking with those raw bytes retrieves them. `rel_hex` is an *identifier*, not
/// an input encoding — passing the hex text must not silently resolve.
#[test]
fn p12_non_utf8_entry_is_retrievable_only_by_its_raw_bytes() {
    let fx = Fx::new("nonutf8");
    let mut p = fx
        .session_dir()
        .join("scratchpad")
        .into_os_string()
        .into_vec();
    p.extend_from_slice(b"/n-\xff.md");
    std::fs::write(PathBuf::from(OsString::from_vec(p)), b"NONUTF8-PAYLOAD\n").unwrap();
    fx.archive();

    let listing = fx.listing_json();
    let e = &listing["entries"][0];
    let hex = e["rel_hex"].as_str().expect("listing has no rel_hex");

    // Raw bytes retrieve it.
    let raw = OsString::from_vec(b"scratchpad/n-\xff.md".to_vec());
    let by_bytes = fx.read_file_os(&raw);
    assert_eq!(
        by_bytes.stdout,
        b"NONUTF8-PAYLOAD\n",
        "the entry the listing advertises is not retrievable by its raw bytes: {}",
        by_bytes.summary()
    );
    // The hex text is an identifier, not a selector.
    let by_hex = fx.read_file(hex);
    assert_ne!(
        by_hex.code,
        0,
        "the hex text resolved an entry; `find` is not a pure byte comparison: {}",
        by_hex.summary()
    );
}

// ---------------------------------------------------------------------------
// H. Retained and absent entries.
// ---------------------------------------------------------------------------

/// A retained entry (`present: false` — its live file vanished) is exactly the
/// case retrieval exists for: the archive is the only remaining copy. It must
/// still be readable, and the listing must say the file is gone.
#[test]
fn p12_retained_entry_is_still_retrievable() {
    let fx = Fx::new("retained");
    fx.write("scratchpad/gone.md", b"LAST-REMAINING-COPY\n");
    fx.archive();
    std::fs::remove_file(fx.session_dir().join("scratchpad/gone.md")).unwrap();
    fx.archive();

    let listing = fx.listing_json();
    let e = listing["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["rel"] == "scratchpad/gone.md")
        .expect("retained entry missing from the listing");
    assert_eq!(e["present"], false, "retained entry not marked absent: {e}");

    let o = fx.read_file("scratchpad/gone.md");
    assert_eq!(
        o.stdout,
        b"LAST-REMAINING-COPY\n",
        "the only remaining copy of a vanished file is not retrievable: {}",
        o.summary()
    );
}
