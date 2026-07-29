//! P14 break tests: adversarial assault on U5-B2 — law Q's checks (§5).
//!
//! The load-bearing claim is a **cost boundary**: Q0/Q1/Q2 run by default and
//! never open a file containing a raw secret; Q3 does open one and is reachable
//! only through `--quarantine`. If the default pass can be made to open an
//! original, the routine nightly command becomes a leak surface. That is
//! attacked first, then the legacy recognition that decides whether an operator
//! sees a real signal or a nightly false alarm.
//!
//! Written to BREAK, not to confirm. Fixtures live under `CARGO_TARGET_TMPDIR`.
//!
//! **Fixture secrets are the public AWS documentation example key**, which
//! authenticates nothing. Assertions name paths, issues and counts — never file
//! contents — so a failure cannot print an original.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const BIN: &str = env!("CARGO_BIN_EXE_yomi");
const FIXTURE_AKIA: &str = "AKIAIOSFODNN7EXAMPLE";

fn unique() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn is_root() -> bool {
    static ROOT: OnceLock<bool> = OnceLock::new();
    *ROOT.get_or_init(|| {
        let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("p14-uid-{}", unique()));
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
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "p14-{tag}-{}-{}",
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
        std::fs::create_dir_all(fx.session_dir().join("scratchpad")).unwrap();
        fx
    }

    fn session_dir(&self) -> PathBuf {
        self.tmp_root.join(&self.slug).join(&self.uuid)
    }
    fn quarantine(&self) -> PathBuf {
        self.yomi_home.join("quarantine")
    }
    fn scratch_key(&self) -> String {
        format!("{}--{}", self.slug, self.uuid)
    }

    fn write_secret(&self, rel: &str) {
        let p = self.session_dir().join("scratchpad").join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("aws_access_key_id = {FIXTURE_AKIA}\n")).unwrap();
    }

    /// A transcript whose content trips the scanner, so a *session* artifact
    /// gets quarantined too.
    fn write_secret_transcript(&self, session_uuid: &str) {
        let line = serde_json::json!({
            "type": "user", "uuid": "u-1", "parentUuid": null,
            "timestamp": "2026-07-12T10:00:00.000Z", "cwd": "/home/test",
            "gitBranch": "main", "version": "2.1.207", "sessionId": session_uuid,
            "message": {"role": "user", "content": format!("aws_access_key_id = {FIXTURE_AKIA}")}
        });
        std::fs::write(
            self.home
                .join(".claude/projects")
                .join(&self.slug)
                .join(format!("{session_uuid}.jsonl")),
            line.to_string() + "\n",
        )
        .unwrap();
    }

    fn run(&self, args: &[&str]) -> Out {
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
            stderr: out.stderr,
        }
    }

    fn archive_scratch(&self) {
        let o = self.run(&["archive", "--all", "--include", "scratch"]);
        assert_eq!(o.code, 0, "archive failed: {}", o.err());
    }
    fn archive_all(&self) {
        let o = self.run(&["archive", "--all"]);
        assert_eq!(o.code, 0, "archive failed: {}", o.err());
    }

    fn verify(&self) -> Q {
        self.verify_args(&["verify", "--json"])
    }
    fn verify_q(&self) -> Q {
        self.verify_args(&["verify", "--quarantine", "--json"])
    }
    fn verify_args(&self, args: &[&str]) -> Q {
        let o = self.run(args);
        let v: serde_json::Value = serde_json::from_slice(&o.stdout)
            .unwrap_or_else(|e| panic!("verify --json ({e}); stderr={}", o.err()));
        Q {
            code: o.code,
            q: v["quarantine"].clone(),
            scratch: v["scratch"].clone(),
            raw: o,
        }
    }

    /// Every file under `quarantine/`, with its bytes, for tamper detection.
    fn originals(&self) -> Vec<(PathBuf, Vec<u8>)> {
        walk_files(&self.quarantine())
            .into_iter()
            .map(|p| {
                let b = std::fs::read(&p).unwrap_or_default();
                (p, b)
            })
            .collect()
    }

    /// Plant a file at a quarantine-relative path, creating parents.
    fn plant(&self, rel: &str, body: &str) -> PathBuf {
        let p = self.quarantine().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("{body}\n{FIXTURE_AKIA}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        p
    }
}

struct Out {
    code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}
impl Out {
    fn err(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
    fn all(&self) -> Vec<u8> {
        let mut v = self.stdout.clone();
        v.extend_from_slice(&self.stderr);
        v
    }
}

struct Q {
    code: i32,
    q: serde_json::Value,
    scratch: serde_json::Value,
    raw: Out,
}

impl Q {
    fn issues(&self, class: &str) -> Vec<String> {
        self.q[class]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|f| f["issue"].as_str().unwrap_or("?").to_string())
                    .collect()
            })
            .unwrap_or_default()
    }
    fn n(&self, k: &str) -> u64 {
        self.q[k].as_u64().unwrap_or_default()
    }
    fn opened(&self) -> bool {
        self.q["opened_originals"].as_bool().unwrap_or(true)
    }
    fn summary(&self) -> String {
        format!(
            "exit={} claims={} present={} legacy={} files={} opened={} viol={:?} foreign={:?} refused={:?} unver={:?}",
            self.code,
            self.n("claims"),
            self.n("present"),
            self.n("legacy"),
            self.n("files"),
            self.opened(),
            self.issues("violations"),
            self.issues("foreign_matter"),
            self.issues("refused"),
            self.issues("unverifiable"),
        )
    }
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

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// A. The cost boundary — Q3 must be unreachable without the flag.
// ---------------------------------------------------------------------------

/// The default pass must not open an original, and the proof is behavioural, not
/// a reported flag: make every original unreadable and the default pass must be
/// completely unaffected. Anything that opened one would notice.
///
/// Skipped under uid 0, which ignores the mode bits.
#[test]
fn p14_default_pass_is_unaffected_by_unreadable_originals() {
    if is_root() {
        return;
    }
    let fx = Fx::new("q3-closed");
    fx.write_secret("leak.md");
    fx.archive_scratch();
    let before = fx.verify();
    assert_eq!(
        before.n("claims"),
        1,
        "fixture quarantined nothing: {}",
        before.summary()
    );
    assert!(
        !before.opened(),
        "default pass reported opening: {}",
        before.summary()
    );

    let files: Vec<PathBuf> = walk_files(&fx.quarantine());
    assert!(!files.is_empty());
    for p in &files {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    let after = fx.verify();
    for p in &files {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    assert_eq!(
        (
            after.code,
            after.n("present"),
            after.issues("violations").len()
        ),
        (
            before.code,
            before.n("present"),
            before.issues("violations").len()
        ),
        "making every original unreadable changed the default pass's verdict, so \
         it opened one: {} vs {}",
        before.summary(),
        after.summary()
    );
    assert!(!after.opened(), "{}", after.summary());
}

/// The converse: `--quarantine` must actually open them, or the flag is
/// decorative and Q3 is not being run at all.
#[test]
fn p14_the_flag_actually_opens_and_only_the_flag_does() {
    if is_root() {
        return;
    }
    let fx = Fx::new("q3-open");
    fx.write_secret("leak.md");
    fx.archive_scratch();

    let files = walk_files(&fx.quarantine());
    for p in &files {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    let default = fx.verify();
    let flagged = fx.verify_q();
    for p in &files {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    assert!(
        !default.opened() && default.code == 0,
        "{}",
        default.summary()
    );
    assert!(
        flagged.opened(),
        "--quarantine did not open originals: {}",
        flagged.summary()
    );
    assert!(
        flagged
            .issues("violations")
            .contains(&"QuarantineMismatch".to_string()),
        "--quarantine did not notice an unreadable original: {}",
        flagged.summary()
    );
    assert_eq!(flagged.code, 2, "{}", flagged.summary());
}

/// Q3's finding names a path and a mismatch. Neither the matching nor the
/// mismatching case may put a byte of an original into any stream.
#[test]
fn p14_q3_reports_a_mismatch_without_carrying_content() {
    let fx = Fx::new("q3-noleak");
    fx.write_secret("leak.md");
    fx.archive_scratch();

    // Corrupt one original so Q3 has something to report, with a distinctive
    // body that must not appear either.
    let p = walk_files(&fx.quarantine()).remove(0);
    std::fs::write(&p, format!("TAMPERED-{FIXTURE_AKIA}-DISTINCTIVE\n")).unwrap();

    let flagged = fx.verify_q();
    assert!(
        flagged
            .issues("violations")
            .contains(&"QuarantineMismatch".to_string()),
        "{}",
        flagged.summary()
    );
    let all = flagged.raw.all();
    assert!(
        !contains(&all, FIXTURE_AKIA.as_bytes()),
        "Q3 output carried the secret"
    );
    assert!(
        !contains(&all, b"TAMPERED-"),
        "Q3 output carried the original's bytes"
    );
}

/// Every routine command must leave the tree byte-identical, including the
/// default verify that now walks it with `readdir` and `stat`.
#[test]
fn p14_routine_commands_leave_originals_byte_identical() {
    let fx = Fx::new("untouched");
    fx.write_secret("leak.md");
    fx.archive_scratch();
    let before = fx.originals();
    assert!(!before.is_empty(), "fixture quarantined nothing");

    let key = fx.scratch_key();
    for c in [
        vec!["verify"],
        vec!["verify", "--json"],
        vec!["verify", "--quarantine"],
        vec!["status"],
        vec!["gc", "--targets", "scratch"],
        vec!["read", "--scratch", &key],
    ] {
        fx.run(&c);
    }
    assert_eq!(
        fx.originals(),
        before,
        "a command modified the quarantine tree"
    );
}

/// The narrower form of the concern the p10 test carried before law Q landed:
/// the **scratch** pass still has no business naming `quarantine/`. Law Q's own
/// section is where those paths belong.
#[test]
fn p14_the_scratch_pass_findings_never_name_quarantine() {
    let fx = Fx::new("scratch-pass");
    fx.write_secret("leak.md");
    fx.archive_scratch();
    // Break the store so the scratch pass has findings to emit.
    for z in walk_files(&fx.yomi_home.join("archive/_scratch")) {
        if z.extension().and_then(|e| e.to_str()) == Some("zst") {
            std::fs::write(&z, b"NOT-A-ZSTD-FRAME").unwrap();
        }
    }
    let v = fx.verify();
    assert!(
        !v.issues("violations").is_empty()
            || !v.scratch["violations"].as_array().unwrap().is_empty(),
        "fixture produced no findings: {}",
        v.summary()
    );
    let scratch_text = serde_json::to_string(&v.scratch).unwrap();
    assert!(
        !scratch_text.contains("quarantine"),
        "the scratch pass named the quarantine tree: {scratch_text}"
    );
}

// ---------------------------------------------------------------------------
// B. Q0 — the check that catches the collision and opens nothing.
// ---------------------------------------------------------------------------

/// Two artifacts deriving one quarantine path. Built by giving the catalog a row
/// whose `stored_path` collides with a scratch entry's — the shape a future
/// writer bug would produce, and the one Q1 provably cannot catch.
#[test]
fn p14_q0_catches_a_real_collision() {
    let fx = Fx::new("q0");
    fx.write_secret("leak.md");
    fx.archive_scratch();
    let clean = fx.verify();
    assert_eq!(
        clean.code,
        0,
        "fixture is not clean to start: {}",
        clean.summary()
    );

    // A catalog row claiming an original at the *same* derived path.
    let colliding = format!("_scratch/{}/scratchpad/leak.md.zst", fx.scratch_key());
    let db = fx.yomi_home.join("state/catalog.db");
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute(
        "INSERT INTO sessions (uuid, project_slug, cwd, git_branch, cc_version, first_seen, last_archived)
         VALUES ('collide-uuid','-home-test','/x','main','1','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO artifacts
           (session_uuid, role, source_path, source_sha256, source_bytes, last_src_offset,
            stored_path, stored_sha256, stored_bytes, content_sha256, redacted, quarantined, updated_at)
         VALUES ('collide-uuid','transcript','/src/x','aa',1,0,?1,'bb',1,'cc',0,1,
                 '2026-01-01T00:00:00Z')",
        [&colliding],
    )
    .unwrap();
    drop(conn);

    let v = fx.verify();
    assert!(
        v.issues("violations")
            .contains(&"QuarantineCollision".to_string()),
        "two artifacts derive one quarantine path and Q0 did not report it — \
         Q1 cannot, because the path exists and satisfies existence for both \
         while one original is gone: {}",
        v.summary()
    );
    assert_eq!(v.code, 2, "{}", v.summary());
    assert!(!v.opened(), "Q0 opened something: {}", v.summary());
}

/// A collision is only a collision when **both** artifacts claim an original.
/// One quarantined and one not is two artifacts sharing a derived path with
/// nothing overwritten, and reporting "one overwrote the other" would be false.
#[test]
fn p14_q0_does_not_fire_when_only_one_side_is_quarantined() {
    let fx = Fx::new("q0-single");
    fx.write_secret("leak.md");
    fx.archive_scratch();

    let colliding = format!("_scratch/{}/scratchpad/leak.md.zst", fx.scratch_key());
    let conn = rusqlite::Connection::open(fx.yomi_home.join("state/catalog.db")).unwrap();
    conn.execute(
        "INSERT INTO sessions (uuid, project_slug, cwd, git_branch, cc_version, first_seen, last_archived)
         VALUES ('nq-uuid','-home-test','/x','main','1','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
        [],
    ).unwrap();
    // quarantined = 0 — this artifact claims no original.
    conn.execute(
        "INSERT INTO artifacts
           (session_uuid, role, source_path, source_sha256, source_bytes, last_src_offset,
            stored_path, stored_sha256, stored_bytes, content_sha256, redacted, quarantined, updated_at)
         VALUES ('nq-uuid','transcript','/src/y','aa',1,0,?1,'bb',1,'cc',0,0,
                 '2026-01-01T00:00:00Z')",
        [&colliding],
    ).unwrap();
    drop(conn);

    let v = fx.verify();
    assert!(
        !v.issues("violations")
            .contains(&"QuarantineCollision".to_string()),
        "Q0 reported a collision where only one artifact claims an original, so \
         nothing overwrote anything: {}",
        v.summary()
    );
}

/// Q0 is a computation over the ledger. It must run with no tree at all — a
/// store whose quarantine directory was deleted out from under a ledger that
/// claims originals must not pass silently.
#[test]
fn p14_ledger_claims_survive_a_deleted_tree() {
    let fx = Fx::new("q0-notree");
    fx.write_secret("leak.md");
    fx.archive_scratch();
    assert_eq!(fx.verify().n("claims"), 1);

    std::fs::remove_dir_all(fx.quarantine()).unwrap();
    let v = fx.verify();
    assert_eq!(
        v.n("claims"),
        1,
        "the ledger's claims vanished with the tree: {}",
        v.summary()
    );
    assert!(
        v.issues("violations")
            .contains(&"QuarantineMissing".to_string()),
        "a ledger claiming an original passed silently after the whole tree was \
         deleted: {}",
        v.summary()
    );
    assert_eq!(v.code, 2, "{}", v.summary());
}

// ---------------------------------------------------------------------------
// C. Q1's legacy fallback — the widest blast radius if it is wrong.
// ---------------------------------------------------------------------------

/// An original written by the **old session writer** (`<uuid>/<session-rel>`)
/// must be recognised as a legacy layout, not reported missing. Getting this
/// wrong makes every pre-B1 store exit 2 every night.
#[test]
fn p14_legacy_session_layout_is_recognised_not_missing() {
    let fx = Fx::new("legacy-session");
    let su = "11111111-2222-3333-4444-555555555555";
    fx.write_secret_transcript(su);
    fx.archive_all();

    // Move the original to where the old session writer put it.
    let cur = fx
        .quarantine()
        .join(&fx.slug)
        .join(su)
        .join("transcript.jsonl");
    assert!(cur.exists(), "fixture did not quarantine the transcript");
    let body = std::fs::read(&cur).unwrap();
    std::fs::remove_file(&cur).unwrap();
    let old = fx.quarantine().join(su).join("transcript.jsonl");
    std::fs::create_dir_all(old.parent().unwrap()).unwrap();
    std::fs::write(&old, &body).unwrap();

    let v = fx.verify();
    assert!(
        !v.issues("violations")
            .contains(&"QuarantineMissing".to_string()),
        "an original at the old session path was reported missing — every store \
         with pre-B1 history would exit 2 nightly: {}",
        v.summary()
    );
    assert!(
        v.issues("foreign_matter")
            .contains(&"QuarantineLegacyLayout".to_string()),
        "the legacy original was not reported as a legacy layout: {}",
        v.summary()
    );
    assert_eq!(
        v.code,
        0,
        "a store whose originals are all in a legacy layout must exit 0: {}",
        v.summary()
    );
}

/// The **old rescan** shape for the same artifact — the doubled level
/// (`<uuid>/<slug>/<uuid>/…`). Both writers' shapes must be recognised or half
/// the population still alarms.
#[test]
fn p14_legacy_rescan_layout_is_recognised() {
    let fx = Fx::new("legacy-rescan");
    let su = "11111111-2222-3333-4444-555555555555";
    fx.write_secret_transcript(su);
    fx.archive_all();

    let cur = fx
        .quarantine()
        .join(&fx.slug)
        .join(su)
        .join("transcript.jsonl");
    let body = std::fs::read(&cur).unwrap();
    std::fs::remove_file(&cur).unwrap();
    let old = fx
        .quarantine()
        .join(su)
        .join(&fx.slug)
        .join(su)
        .join("transcript.jsonl");
    std::fs::create_dir_all(old.parent().unwrap()).unwrap();
    std::fs::write(&old, &body).unwrap();

    let v = fx.verify();
    assert!(
        !v.issues("violations")
            .contains(&"QuarantineMissing".to_string()),
        "the old rescan layout was reported missing: {}",
        v.summary()
    );
    assert_eq!(v.code, 0, "{}", v.summary());
}

/// The **old scratch** shape: the key doubled and the name run through
/// `to_string_lossy`.
#[test]
fn p14_legacy_scratch_layout_is_recognised() {
    let fx = Fx::new("legacy-scratch");
    fx.write_secret("leak.md");
    fx.archive_scratch();

    let k = fx.scratch_key();
    let cur = fx
        .quarantine()
        .join("_scratch")
        .join(&k)
        .join("scratchpad/leak.md");
    let body = std::fs::read(&cur).unwrap();
    std::fs::remove_file(&cur).unwrap();
    let old = fx
        .quarantine()
        .join(format!("_scratch--{k}"))
        .join(&k)
        .join("scratchpad/leak.md");
    std::fs::create_dir_all(old.parent().unwrap()).unwrap();
    std::fs::write(&old, &body).unwrap();

    let v = fx.verify();
    assert!(
        !v.issues("violations")
            .contains(&"QuarantineMissing".to_string()),
        "the old scratch layout was reported missing: {}",
        v.summary()
    );
    assert_eq!(v.code, 0, "{}", v.summary());
}

/// An original that exists at **neither** the current nor any superseded path is
/// genuinely missing, and must fail. Without this the fallback could swallow
/// real loss.
#[test]
fn p14_a_genuinely_absent_original_still_fails() {
    let fx = Fx::new("really-missing");
    fx.write_secret("leak.md");
    fx.archive_scratch();
    for p in walk_files(&fx.quarantine()) {
        std::fs::remove_file(&p).unwrap();
    }
    let v = fx.verify();
    assert!(
        v.issues("violations")
            .contains(&"QuarantineMissing".to_string()),
        "a deleted original was not reported missing: {}",
        v.summary()
    );
    assert_eq!(v.code, 2, "{}", v.summary());
}

// ---------------------------------------------------------------------------
// D. Q2 — strays, legacy recognition, and the un-quarantined artifact.
// ---------------------------------------------------------------------------

/// A file under `quarantine/` that no artifact and no legacy shape explains is a
/// stray — advisory, since only an operator can resolve it, and requiring
/// exclusion because a concurrent archive quarantines before it writes the
/// ledger.
#[test]
fn p14_an_unexplained_file_is_a_stray_and_advisory() {
    let fx = Fx::new("stray");
    fx.write_secret("leak.md");
    fx.archive_scratch();
    fx.plant("no-such-shape/whatever.txt", "STRAY");

    let v = fx.verify();
    let foreign = v.issues("foreign_matter");
    let unver = v.issues("unverifiable");
    assert!(
        foreign.contains(&"QuarantineStray".to_string())
            || unver.contains(&"QuarantineStray".to_string()),
        "an unexplained file was not reported as a stray: {}",
        v.summary()
    );
    assert!(
        !v.issues("violations")
            .contains(&"QuarantineStray".to_string()),
        "a stray was classed as a violation: {}",
        v.summary()
    );
    assert_eq!(
        v.code,
        0,
        "a stray alone must not fail the run: {}",
        v.summary()
    );
}

/// The un-quarantining case: an artifact whose `quarantined` flag is cleared
/// still explains the original beside it, because the claimed set is taken over
/// **all** artifacts rather than only the quarantined ones. Otherwise clearing a
/// flag turns a real original into a stray.
#[test]
fn p14_clearing_the_quarantined_flag_does_not_create_a_stray() {
    let fx = Fx::new("unquarantined");
    fx.write_secret("leak.md");
    fx.archive_scratch();
    let before = fx.verify();
    assert_eq!(before.n("claims"), 1, "{}", before.summary());

    // Clear the ledger's claim, leaving the original where it is.
    let store = fx.yomi_home.join("archive/_scratch").join(fx.scratch_key());
    let mfp = store.join("manifest.json");
    let mut mf: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&mfp).unwrap()).unwrap();
    for e in mf["entries"].as_array_mut().unwrap() {
        e.as_object_mut().unwrap().remove("quarantined");
    }
    std::fs::write(&mfp, serde_json::to_string_pretty(&mf).unwrap()).unwrap();

    let v = fx.verify();
    assert!(
        !v.issues("foreign_matter")
            .contains(&"QuarantineStray".to_string())
            && !v
                .issues("unverifiable")
                .contains(&"QuarantineStray".to_string()),
        "clearing `quarantined` turned a real original into a stray — the \
         claimed set must be every artifact, not only the quarantined ones: {}",
        v.summary()
    );
}

// ---------------------------------------------------------------------------
// E. The root guard.
// ---------------------------------------------------------------------------

/// `stat` and `readdir` both follow links, so a quarantine root that is not a
/// directory this run owns means every fact drawn through it is about some other
/// tree. Refused, and failing — the same rule every other store path in this
/// design gets.
#[test]
fn p14_symlinked_quarantine_root_is_refused() {
    let fx = Fx::new("foreign-root");
    fx.write_secret("leak.md");
    fx.archive_scratch();

    let elsewhere = fx.base.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::rename(fx.quarantine(), elsewhere.join("q")).unwrap();
    std::os::unix::fs::symlink(elsewhere.join("q"), fx.quarantine()).unwrap();

    let v = fx.verify();
    assert!(
        v.issues("refused")
            .contains(&"QuarantineForeignRoot".to_string()),
        "a symlinked quarantine root was attested to rather than refused: {}",
        v.summary()
    );
    assert_eq!(
        v.code,
        2,
        "a refused root must fail the run: {}",
        v.summary()
    );
    assert!(!v.opened(), "{}", v.summary());
}

/// A store with no claims is not a defect, and `verify` — a read command — must
/// not create the tree. (`ensure_layout` creates `quarantine/` on every *write*
/// command, so the root is removed here first: the question is whether verify
/// puts it back.)
#[test]
fn p14_absent_root_with_no_claims_is_clean_and_verify_creates_nothing() {
    let fx = Fx::new("absent");
    let p = fx.session_dir().join("scratchpad/plain.md");
    std::fs::write(&p, b"nothing secret here\n").unwrap();
    fx.archive_scratch();
    let _ = std::fs::remove_dir_all(fx.quarantine());

    let v = fx.verify();
    assert_eq!(v.n("claims"), 0, "{}", v.summary());
    assert_eq!(v.code, 0, "{}", v.summary());
    assert!(
        v.issues("violations").is_empty() && v.issues("refused").is_empty(),
        "an absent root with no claims produced findings: {}",
        v.summary()
    );
    assert!(
        !fx.quarantine().exists(),
        "verify created the quarantine root"
    );
}

// ---------------------------------------------------------------------------
// F. Exclusion and exit codes.
// ---------------------------------------------------------------------------

/// A store whose originals are all in legacy layouts is the common upgrade case.
/// It must be advisory end to end: reported, counted, and exit 0.
#[test]
fn p14_a_legacy_heavy_store_exits_zero() {
    let fx = Fx::new("legacy-heavy");
    for n in ["a", "b", "c"] {
        fx.write_secret(&format!("{n}.md"));
    }
    fx.archive_scratch();
    let k = fx.scratch_key();
    for n in ["a", "b", "c"] {
        let cur = fx
            .quarantine()
            .join("_scratch")
            .join(&k)
            .join(format!("scratchpad/{n}.md"));
        let body = std::fs::read(&cur).unwrap();
        std::fs::remove_file(&cur).unwrap();
        let old = fx
            .quarantine()
            .join(format!("_scratch--{k}"))
            .join(&k)
            .join(format!("scratchpad/{n}.md"));
        std::fs::create_dir_all(old.parent().unwrap()).unwrap();
        std::fs::write(&old, &body).unwrap();
    }

    let v = fx.verify();
    assert_eq!(
        v.code,
        0,
        "a store with three legacy originals failed the run; this is the ordinary \
         upgrade state and would alarm nightly: {}",
        v.summary()
    );
    assert!(
        v.issues("violations").is_empty(),
        "legacy originals produced violations: {}",
        v.summary()
    );
    assert_eq!(
        v.n("legacy"),
        3,
        "legacy originals were not counted: {}",
        v.summary()
    );
}

/// Only `QuarantineStray` and `QuarantineMismatch` need exclusion. Q0 and Q1
/// must therefore stay sound against a concurrent `archive`: Q0 is a
/// computation over one ledger snapshot, and every writer quarantines *before*
/// it writes the ledger, so a claim's file is already there when the claim
/// appears.
///
/// Asserted in the direction that holds under **every** interleaving — no Q0/Q1
/// violation, ever. Deliberately not asserted: that a transient stray *is*
/// observed, which depends on the scheduler.
#[test]
fn p14_a_concurrent_archive_never_produces_a_false_q0_or_q1() {
    let fx = Fx::new("concurrent");
    for n in ["a", "b", "c", "d", "e"] {
        fx.write_secret(&format!("{n}.md"));
    }
    fx.archive_scratch();

    for round in 0..6 {
        // Fresh secrets each round so archive has real quarantine work to do.
        fx.write_secret(&format!("r{round}.md"));
        let mut child = Command::new(BIN)
            .args(["archive", "--all", "--include", "scratch", "--home"])
            .arg(&fx.yomi_home)
            .env("HOME", &fx.home)
            .env("YOMI_TMP_ROOT", &fx.tmp_root)
            .env("YOMI_CACHE_HOME", &fx.cache_home)
            .env("YOMI_PROC_ROOT", &fx.proc_root)
            .env_remove("YOMI_HOME")
            .env_remove("YOMI_CLAUDE_HOME")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn archive");
        while child.try_wait().expect("wait").is_none() {
            let v = fx.verify();
            for bad in ["QuarantineCollision", "QuarantineMissing"] {
                assert!(
                    !v.issues("violations").contains(&bad.to_string()),
                    "round {round}: a concurrent archive produced a false {bad}. \
                     Q0 reads one ledger snapshot and Q1's files are written \
                     before the claims that name them, so neither should need \
                     exclusion: {}",
                    v.summary()
                );
            }
        }
    }
    // And the store settles clean once nothing is running.
    let settled = fx.verify();
    assert_eq!(
        settled.code,
        0,
        "the store did not settle clean after concurrent archives: {}",
        settled.summary()
    );
}

/// A duplicated ledger identity must be reported once and account its artifact
/// once — a double count would make Q1 or Q2 arithmetic wrong for every store
/// with a corrupt manifest.
#[test]
fn p14_duplicate_identity_is_not_double_counted() {
    let fx = Fx::new("dup");
    fx.write_secret("leak.md");
    fx.archive_scratch();
    let base = fx.verify();

    let store = fx.yomi_home.join("archive/_scratch").join(fx.scratch_key());
    let mfp = store.join("manifest.json");
    let mut mf: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&mfp).unwrap()).unwrap();
    let twin = mf["entries"][0].clone();
    mf["entries"].as_array_mut().unwrap().push(twin);
    std::fs::write(&mfp, serde_json::to_string_pretty(&mf).unwrap()).unwrap();

    let v = fx.verify();
    assert_eq!(
        v.n("claims"),
        base.n("claims"),
        "a duplicated identity was counted twice as a claim: {} vs {}",
        base.summary(),
        v.summary()
    );
    assert_eq!(
        v.n("present"),
        base.n("present"),
        "a duplicated identity accounted its original twice: {}",
        v.summary()
    );
    assert!(
        !v.issues("violations")
            .contains(&"QuarantineCollision".to_string()),
        "one identity listed twice was reported as two artifacts colliding: {}",
        v.summary()
    );
}
