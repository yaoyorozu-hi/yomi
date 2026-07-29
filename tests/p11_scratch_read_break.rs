//! P11: `yomi read --scratch` — the retrieval path.
//!
//! GC deletes a scratch tree because the archive covers it. An archive with no
//! way to get the bytes back is not an archive, so this command is what makes
//! "scratch is archived, not disposable" true rather than asserted.
//!
//! Two properties are meant to be **structural**, not checked, and this file
//! attacks them as such:
//!
//! * **Non-exposure.** The only thing the command opens is a stored `.zst`. It
//!   never reads the live source and never reads `quarantine/`, so there is no
//!   input from which an un-redacted byte could reach the output. A scratch
//!   `.zst` holds `scan.redacted` as of capture — redacted text, or the opaque
//!   `‹QUARANTINED:…›` marker.
//! * **Path traversal.** `--file <rel>` is compared byte-wise against the
//!   manifest and the opened path comes from the *matched entry*. User input
//!   never becomes a path, and `ScratchRel` cannot represent `..` or an absolute
//!   path in the first place.
//!
//! Every fixture is fabricated under `CARGO_TARGET_TMPDIR`.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_yomi");
/// A fabricated AWS example key (public documentation value, not a credential).
const FIXTURE_AKIA: &str = "AKIAIOSFODNN7EXAMPLE";
const QUARANTINE_MARKER: &str = "\u{2039}QUARANTINED:";

fn unique() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// Root ignores the mode bits the capture-failure fixture depends on.
fn is_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    static ROOT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ROOT.get_or_init(|| {
        let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("p11-uid-{}", unique()));
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
    fn with_config(tag: &str, config: &str) -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "p11-{tag}-{}-{}",
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
        std::fs::set_permissions(&fx.yomi_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(fx.yomi_home.join("config.toml"), config).unwrap();
        fx
    }

    fn new(tag: &str) -> Self {
        Fx::with_config(tag, "[scratch]\ntotal_cap = \"1MB\"\n")
    }

    /// One ordinary file, one holding a secret, one binary, one deny-listed.
    fn seeded(tag: &str) -> Self {
        let fx = Fx::new(tag);
        fx.write("scratchpad/ok.md", b"plain text\n");
        fx.write(
            "scratchpad/secret.md",
            format!("aws_access_key_id = {FIXTURE_AKIA}\n").as_bytes(),
        );
        fx.write("scratchpad/data.log", b"\x00\x01\xff\xfe binary \x80\n");
        fx.write("scratchpad/blob.bin", b"denied junk\n");
        fx.archive();
        fx
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

    /// `read <selector> --scratch [--file <rel>]`, raw output preserved.
    fn read(&self, args: &[&str]) -> std::process::Output {
        let mut v = vec!["read", &self.uuid, "--scratch"];
        v.extend_from_slice(args);
        self.run(&v)
    }

    fn read_json(&self, args: &[&str]) -> (i32, serde_json::Value) {
        let mut v: Vec<&str> = args.to_vec();
        v.push("--json");
        let out = self.read(&v);
        let txt = String::from_utf8_lossy(&out.stdout);
        let j = serde_json::from_str(txt.trim()).unwrap_or_else(|e| {
            panic!(
                "read --json unparseable ({e}): stdout={txt:?} stderr={:?}",
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code().unwrap(), j)
    }

    /// What the store actually holds for an entry, decompressed independently of
    /// the command under test.
    fn stored_bytes(&self, rel: &str) -> Vec<u8> {
        let raw = std::fs::read(self.store_dir().join(format!("{rel}.zst"))).unwrap();
        yomi::archive::compress::decompress_all(&raw).unwrap()
    }
}

/// Every regular file under `root`, as (relative path, bytes).
fn snapshot(root: &Path) -> Vec<(String, Vec<u8>)> {
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
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// A. Listing and retrieval.
// ---------------------------------------------------------------------------

/// The listing must name every entry and show `present` / `capture_failed`
/// rather than folding them into `stored`: those are the two states where "why
/// can I not get these bytes?" has a different answer and a different remedy.
#[test]
fn p11_listing_names_every_entry_and_its_state() {
    let fx = Fx::seeded("listing");
    let (code, v) = fx.read_json(&[]);
    assert_eq!(code, 0);
    assert_eq!(v["key"], fx.key());
    assert!(v["captured_at"].as_str().is_some(), "{v:#}");
    assert_eq!(v["over_total_cap"], false);
    assert!(v["total_bytes"].as_u64().unwrap() > 0);

    let rels: Vec<&str> = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["rel"].as_str().unwrap())
        .collect();
    for want in [
        "scratchpad/ok.md",
        "scratchpad/secret.md",
        "scratchpad/data.log",
        "scratchpad/blob.bin",
    ] {
        assert!(rels.contains(&want), "{want} missing from listing: {v:#}");
    }
    let ok = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["rel"] == "scratchpad/ok.md")
        .unwrap();
    for field in [
        "bytes",
        "stored",
        "present",
        "capture_failed",
        "source_sha256",
        "content_sha256",
    ] {
        assert!(!ok[field].is_null(), "{field} missing: {ok}");
    }

    // The human form carries the same facts.
    let text = String::from_utf8(fx.read(&[]).stdout).unwrap();
    assert!(text.contains(&fx.key()), "{text}");
    assert!(text.contains("scratchpad/blob.bin"), "{text}");
    assert!(text.contains("not stored"), "{text}");
}

/// The bytes handed to stdout must be exactly the stored bytes — written raw,
/// not through a lossy string conversion.
#[test]
fn p11_stored_bytes_are_written_raw_and_byte_exact() {
    let fx = Fx::seeded("exact");
    let out = fx.read(&["--file", "scratchpad/ok.md"]);
    assert_eq!(out.status.code().unwrap(), 0);
    assert_eq!(
        out.stdout,
        fx.stored_bytes("scratchpad/ok.md"),
        "stdout is not byte-identical to the stored artifact"
    );
    assert!(out.stderr.is_empty(), "content path wrote to stderr");
}

/// `--json` never puts invalid UTF-8 inside a JSON string: non-UTF-8 stored
/// bytes come back hex-encoded, with the same encoder `path_hex` uses, so no
/// dependency is added.
#[test]
fn p11_non_utf8_stored_bytes_round_trip_through_hex() {
    let fx = Fx::seeded("hex");
    // Planted directly: what the scanner would or would not store is P1's
    // business; this isolates the *output* contract for non-UTF-8 stored bytes.
    let payload: &[u8] = b"\x00\x01\xff\xfe not utf-8 \x80\n";
    let dest = fx.store_dir().join("scratchpad/ok.md.zst");
    std::fs::write(
        &dest,
        yomi::archive::compress::compress_frame(payload).unwrap(),
    )
    .unwrap();

    let out = fx.read(&["--file", "scratchpad/ok.md"]);
    assert_eq!(out.stdout, payload, "raw stdout was not byte-exact");

    let (code, v) = fx.read_json(&["--file", "scratchpad/ok.md"]);
    assert_eq!(code, 0);
    assert_eq!(v["encoding"], "hex", "{v:#}");
    assert_eq!(v["content_bytes"], payload.len());
    let decoded: Vec<u8> = v["content"]
        .as_str()
        .unwrap()
        .as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    assert_eq!(decoded, payload, "hex content did not round-trip");
}

/// A non-UTF-8 *name* is listed lossily — it has to be, JSON strings are UTF-8 —
/// so the listing also emits `rel_hex`, which says exactly which bytes to hand
/// back to `--file`.
#[test]
fn p11_non_utf8_entry_is_addressable_by_its_bytes() {
    use std::ffi::OsStr;
    let fx = Fx::new("oddname");
    let pad = fx.session_dir().join("scratchpad");
    std::fs::create_dir_all(&pad).unwrap();
    std::fs::write(pad.join(OsStr::from_bytes(b"note-\xff.md")), b"odd\n").unwrap();
    fx.archive();

    let (_, v) = fx.read_json(&[]);
    let e = &v["entries"][0];
    assert!(
        e["rel_hex"].as_str().is_some(),
        "no rel_hex to address: {v:#}"
    );
    let raw: Vec<u8> = e["rel_hex"]
        .as_str()
        .unwrap()
        .as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    assert_eq!(raw, b"scratchpad/note-\xff.md");

    let out = Command::new(BIN)
        .args(["read", &fx.uuid, "--scratch", "--file"])
        .arg(OsStr::from_bytes(&raw))
        .arg("--home")
        .arg(&fx.yomi_home)
        .env("HOME", &fx.home)
        .env("YOMI_TMP_ROOT", &fx.tmp_root)
        .env("YOMI_CACHE_HOME", &fx.cache_home)
        .env("YOMI_PROC_ROOT", &fx.proc_root)
        .env_remove("YOMI_HOME")
        .env_remove("YOMI_CLAUDE_HOME")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code().unwrap(),
        0,
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"odd\n");
}

// ---------------------------------------------------------------------------
// B. Non-exposure — structural, and attacked as such.
// ---------------------------------------------------------------------------

/// A secret redacted on the way into the store must come back redacted. The
/// stored `.zst` holds `scan.redacted`; there is no other input.
#[test]
fn p11_redacted_file_reads_back_redacted() {
    let fx = Fx::seeded("redacted");
    let out = fx.read(&["--file", "scratchpad/secret.md"]);
    assert_eq!(out.status.code().unwrap(), 0);
    assert!(
        !contains(&out.stdout, FIXTURE_AKIA.as_bytes()),
        "the raw secret came back out: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        contains(&out.stdout, b"REDACTED:"),
        "the redaction placeholder is missing: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    // The live source still holds the secret, so there was something to leak.
    let live = std::fs::read(fx.session_dir().join("scratchpad/secret.md")).unwrap();
    assert!(contains(&live, FIXTURE_AKIA.as_bytes()));
}

/// A whole-quarantined artifact reads as the opaque marker, never as the raw
/// original — the raw lives in `quarantine/`, which this command does not open.
#[test]
fn p11_whole_quarantined_file_reads_as_the_marker() {
    let fx = Fx::seeded("quarantined");
    let out = fx.read(&["--file", "scratchpad/data.log"]);
    assert_eq!(out.status.code().unwrap(), 0);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        text.contains(QUARANTINE_MARKER),
        "expected a quarantine marker, got {text:?}"
    );
    assert!(
        !contains(&out.stdout, b"\xff\xfe binary"),
        "the raw quarantined bytes came back out"
    );
}

/// The command must not read `quarantine/` at all — proven by leaving it
/// byte-for-byte untouched across every form of the command, while the raw
/// secret it holds never appears on either stream.
#[test]
fn p11_read_never_touches_quarantine() {
    let fx = Fx::seeded("quarantine-untouched");
    let qdir = fx.yomi_home.join("quarantine");
    let before = snapshot(&qdir);
    assert!(
        before
            .iter()
            .any(|(_, b)| contains(b, FIXTURE_AKIA.as_bytes())),
        "fixture quarantined no raw secret, so this test proves nothing"
    );

    for args in [
        vec![],
        vec!["--json"],
        vec!["--file", "scratchpad/secret.md"],
        vec!["--file", "scratchpad/secret.md", "--json"],
        vec!["--file", "scratchpad/data.log"],
        vec!["--file", "scratchpad/data.log", "--json"],
    ] {
        let out = fx.read(&args);
        for (stream, bytes) in [("stdout", &out.stdout), ("stderr", &out.stderr)] {
            assert!(
                !contains(bytes, FIXTURE_AKIA.as_bytes()),
                "{args:?} leaked the raw secret on {stream}"
            );
        }
    }
    assert_eq!(
        snapshot(&qdir),
        before,
        "the read path modified quarantine/"
    );
}

// ---------------------------------------------------------------------------
// C. Path traversal — unrepresentable, not merely rejected.
// ---------------------------------------------------------------------------

/// `--file` is compared against the manifest and the opened path comes from the
/// matched entry, so a traversal value matches nothing. `ScratchRel` cannot hold
/// `..` or an absolute path either, so no code path turns these into an open.
#[test]
fn p11_traversal_values_match_nothing_and_open_nothing() {
    let fx = Fx::seeded("traversal");
    let decoy = fx.base.join("outside-secret.txt");
    std::fs::write(&decoy, b"OUTSIDE-DECOY-CONTENT\n").unwrap();

    for probe in [
        "../../../etc/passwd",
        "../../outside-secret.txt",
        "..",
        "/etc/passwd",
        "scratchpad/../scratchpad/ok.md",
        "./scratchpad/ok.md",
        "",
    ] {
        let out = fx.read(&["--file", probe]);
        assert_eq!(
            out.status.code().unwrap(),
            2,
            "{probe:?} was not refused: {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            out.stdout.is_empty(),
            "{probe:?} produced output: {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            !contains(&out.stdout, b"OUTSIDE-DECOY-CONTENT"),
            "{probe:?} read a file outside the store"
        );
    }
    assert_eq!(std::fs::read(&decoy).unwrap(), b"OUTSIDE-DECOY-CONTENT\n");
}

// ---------------------------------------------------------------------------
// D. `stored: false` — refused with the reason, never a bare "not found".
// ---------------------------------------------------------------------------

/// Each cause gets its own answer, because each has a different remedy.
#[test]
fn p11_not_stored_names_the_cause() {
    // Deny-listed by the default globs.
    let fx = Fx::seeded("why-deny");
    let (code, v) = fx.read_json(&["--file", "scratchpad/blob.bin"]);
    assert_eq!(code, 2);
    assert_eq!(v["error"], "NotStored", "{v:#}");
    assert!(
        v["reason"].as_str().unwrap().contains("allow/deny globs"),
        "{v:#}"
    );

    // Over the per-file cap.
    let fx = Fx::with_config(
        "why-filecap",
        "[scratch]\nfile_cap = \"10B\"\ntotal_cap = \"1MB\"\n",
    );
    fx.write("scratchpad/big.md", &[b'x'; 64]);
    fx.archive();
    let (code, v) = fx.read_json(&["--file", "scratchpad/big.md"]);
    assert_eq!(code, 2);
    assert!(v["reason"].as_str().unwrap().contains("file_cap"), "{v:#}");

    // Over the whole-tree cap.
    let fx = Fx::with_config("why-totalcap", "[scratch]\ntotal_cap = \"1B\"\n");
    fx.write("scratchpad/a.md", b"aaaa\n");
    fx.archive();
    let (code, v) = fx.read_json(&["--file", "scratchpad/a.md"]);
    assert_eq!(code, 2);
    assert!(v["reason"].as_str().unwrap().contains("total_cap"), "{v:#}");
}

/// The capture-failure case is the one where nothing was *ever* read, and its
/// remedy is different again: make the file readable and re-archive.
#[test]
fn p11_capture_failure_is_named_as_such() {
    if is_root() {
        return;
    }
    let fx = Fx::new("why-capture");
    fx.write("scratchpad/locked.md", b"never read\n");
    let locked = fx.session_dir().join("scratchpad/locked.md");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    fx.archive();
    let (code, v) = fx.read_json(&["--file", "scratchpad/locked.md"]);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(code, 2);
    assert_eq!(v["error"], "NotStored", "{v:#}");
    assert!(
        v["reason"].as_str().unwrap().contains("capture failed"),
        "{v:#}"
    );
}

/// A name no entry carries is "not found" — distinct from "not stored", which
/// says the entry exists and why its bytes do not.
#[test]
fn p11_absent_entry_is_not_found_not_not_stored() {
    let fx = Fx::seeded("absent");
    let (code, v) = fx.read_json(&["--file", "scratchpad/never-existed.md"]);
    assert_eq!(code, 2);
    assert_eq!(v["error"], "NotFound", "{v:#}");
}

// ---------------------------------------------------------------------------
// E. Selector resolution and store classification.
// ---------------------------------------------------------------------------

/// A hex-encoded key must still be reachable by the session's real uuid — the
/// shared resolver, not a suffix test, decides.
#[test]
fn p11_hex_key_session_resolves_by_its_uuid() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let fx = Fx::new("hexkey");
    let mut slug = fx.tmp_root.clone().into_os_string().into_vec();
    slug.extend_from_slice(b"/-proj-\xff");
    let sess = PathBuf::from(OsString::from_vec(slug)).join(&fx.uuid);
    std::fs::create_dir_all(sess.join("scratchpad")).unwrap();
    std::fs::write(sess.join("scratchpad/a.md"), b"hexed\n").unwrap();
    let _ = std::fs::remove_dir_all(fx.session_dir());
    fx.archive();

    let (code, v) = fx.read_json(&[]);
    assert_eq!(
        code, 0,
        "a hex-encoded key could not be addressed by its uuid: {v:#}"
    );
    assert!(v["key"].as_str().unwrap().starts_with("_hex--"), "{v:#}");
    let out = fx.read(&["--file", "scratchpad/a.md"]);
    assert_eq!(out.stdout, b"hexed\n");
}

/// A full store key names itself.
#[test]
fn p11_full_store_key_selects_its_own_store() {
    let fx = Fx::seeded("bykey");
    let out = fx.run(&["read", &fx.key(), "--scratch", "--json"]);
    assert_eq!(out.status.code().unwrap(), 0);
    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap();
    assert_eq!(v["key"], fx.key());
}

/// A selector that resolves to nothing, and a store that must not be read
/// through, are different answers — never a bare "not found" for a refusal.
#[test]
fn p11_missing_and_foreign_stores_give_distinct_reasons() {
    let fx = Fx::seeded("selectors");
    let (code, v) = fx.run_json_read("ffffffff-0000-0000-0000-000000000000");
    assert_eq!(code, 2);
    assert_eq!(v["error"], "NotFound", "{v:#}");

    // A store directory yomi does not own is refused, not read through.
    let outside = fx.base.join("relocated");
    std::fs::rename(fx.store_dir(), &outside).unwrap();
    std::os::unix::fs::symlink(&outside, fx.store_dir()).unwrap();
    let (code, v) = fx.read_json(&[]);
    assert_eq!(code, 2);
    assert_eq!(v["error"], "ForeignStoreDir", "{v:#}");

    // And the root above it, which every key resolves through.
    std::fs::remove_file(fx.store_dir()).unwrap();
    let root = fx.yomi_home.join("archive/_scratch");
    std::fs::remove_dir_all(&root).unwrap();
    std::os::unix::fs::symlink(&outside, &root).unwrap();
    let (code, v) = fx.read_json(&[]);
    assert_eq!(code, 2);
    assert_eq!(v["error"], "ForeignStoreRoot", "{v:#}");
}

impl Fx {
    fn run_json_read(&self, selector: &str) -> (i32, serde_json::Value) {
        let out = self.run(&["read", selector, "--scratch", "--json"]);
        let txt = String::from_utf8_lossy(&out.stdout);
        (
            out.status.code().unwrap(),
            serde_json::from_str(txt.trim()).unwrap_or_else(|e| panic!("{e}: {txt:?}")),
        )
    }
}

/// A home that has never archived scratch says so, and does not create the store.
#[test]
fn p11_fresh_home_reports_no_store_and_creates_nothing() {
    let fx = Fx::new("fresh");
    let (code, v) = fx.read_json(&[]);
    assert_eq!(code, 2);
    assert_eq!(v["error"], "NoScratchStore", "{v:#}");
    assert!(
        !fx.yomi_home.join("archive").exists(),
        "a read-only command created the store"
    );
}

// ---------------------------------------------------------------------------
// F. CLI shape.
// ---------------------------------------------------------------------------

/// `--scratch` reads a different ledger than the transcript flags; accepting
/// both and silently honouring one is the failure mode `--all` had.
#[test]
fn p11_scratch_conflicts_with_the_transcript_flags() {
    let fx = Fx::seeded("conflicts");
    for flag in [
        vec!["--raw"],
        vec!["--agents"],
        vec!["--entry", "x"],
        vec!["--grep", "x"],
    ] {
        let mut args = vec!["read", &fx.uuid, "--scratch"];
        args.extend_from_slice(&flag);
        let out = fx.run(&args);
        assert_ne!(
            out.status.code().unwrap(),
            0,
            "{flag:?} was accepted beside --scratch"
        );
    }
    // `--file` without `--scratch` is likewise a usage error, not a no-op.
    let out = fx.run(&["read", &fx.uuid, "--file", "scratchpad/ok.md"]);
    assert_ne!(out.status.code().unwrap(), 0);

    // The positional accepts hyphen-leading values so a real store key can be
    // named — but omitting it entirely must still be a usage error rather than
    // `--scratch` being swallowed as the selector.
    let out = fx.run(&["read", "--scratch"]);
    assert_ne!(out.status.code().unwrap(), 0);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("required"),
        "a missing selector was consumed as a value: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}
