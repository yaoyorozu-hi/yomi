//! P13 break tests: adversarial assault on U5-B1 — quarantine identity (§4).
//!
//! This unit writes **raw, unredacted secrets** to new paths and sets modes on a
//! new directory hierarchy. Two originals landing on one path destroys one of
//! them, and for a source GC has since deleted that was the only copy anywhere.
//! So injectivity is attacked hardest, then the tree's boundary.
//!
//! Written to BREAK, not to confirm. Every fixture is fabricated under
//! `CARGO_TARGET_TMPDIR` — deliberately not `std::env::temp_dir()`, which
//! `tests/e2e.rs` uses and which leaves `/tmp/yomi-e2e-*` behind (N5).
//!
//! **Fixture secrets are the public AWS documentation example key**, which is
//! not a live credential. Assertion messages below name paths, counts and
//! markers — never file contents — so a failure can never print an original.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const BIN: &str = env!("CARGO_BIN_EXE_yomi");

/// Public AWS documentation example key — cannot authenticate anything.
const FIXTURE_AKIA: &str = "AKIAIOSFODNN7EXAMPLE";

fn unique() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// uid 0, read off a file this process just created.
fn is_root() -> bool {
    static ROOT: OnceLock<bool> = OnceLock::new();
    *ROOT.get_or_init(|| {
        let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("p13-uid-{}", unique()));
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
            "p13-{tag}-{}-{}",
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

    fn session_dir(&self) -> PathBuf {
        self.tmp_root.join(&self.slug).join(&self.uuid)
    }

    fn quarantine(&self) -> PathBuf {
        self.yomi_home.join("quarantine")
    }

    /// A scratch file whose content trips the secret scanner, tagged so the two
    /// originals of a collision test are distinguishable without printing them.
    fn write_secret(&self, rel: &str, tag: &str) {
        self.write_secret_raw(
            self.session_dir().join("scratchpad").join(rel).as_os_str(),
            tag,
        );
    }

    fn write_secret_raw(&self, abs: &std::ffi::OsStr, tag: &str) {
        let p = PathBuf::from(abs);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            format!("aws_access_key_id = {FIXTURE_AKIA}\nTAG-{tag}\n"),
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

    fn archive(&self) {
        let o = self.run(&["archive", "--all", "--include", "scratch"]);
        assert_eq!(
            o.code,
            0,
            "archive failed: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }

    /// Quarantine-relative paths of every original, as raw bytes.
    fn originals(&self) -> Vec<Vec<u8>> {
        let q = self.quarantine();
        let mut v: Vec<Vec<u8>> = walk_files(&q)
            .into_iter()
            .map(|p| {
                p.strip_prefix(&q)
                    .unwrap()
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec()
            })
            .collect();
        v.sort();
        v
    }

    fn manifest(&self) -> serde_json::Value {
        let dir = self
            .yomi_home
            .join("archive/_scratch")
            .join(format!("{}--{}", self.slug, self.uuid));
        serde_json::from_str(&std::fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap()
    }
}

struct Out {
    code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Out {
    fn all(&self) -> Vec<u8> {
        let mut v = self.stdout.clone();
        v.extend_from_slice(&self.stderr);
        v
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

/// Which tag a quarantined original carries, without ever returning its bytes.
fn tag_of(path: &Path) -> Option<String> {
    let b = std::fs::read(path).ok()?;
    let i = b.windows(4).position(|w| w == b"TAG-")?;
    let rest = &b[i + 4..];
    let end = rest.iter().position(|c| *c == b'\n').unwrap_or(rest.len());
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

// ---------------------------------------------------------------------------
// A. Injectivity — Q0. The defect this whole rule exists to end.
// ---------------------------------------------------------------------------

/// Two non-UTF-8 names sharing one lossy form, **both secret-bearing**. Under
/// the old rule their originals collided at `U+FFFD` and one overwrote the
/// other, in the one place the lost object has no other copy.
///
/// The implementer verified this ad hoc and reported no permanent test existed.
/// This is that test.
#[test]
fn p13_lossy_colliding_scratch_names_keep_distinct_originals() {
    let fx = Fx::new("inj-lossy");
    let pad = fx
        .session_dir()
        .join("scratchpad")
        .into_os_string()
        .into_vec();
    for (suffix, tag) in [(&b"note-\xff.md"[..], "FF"), (&b"note-\xfe.md"[..], "FE")] {
        let mut p = pad.clone();
        p.push(b'/');
        p.extend_from_slice(suffix);
        fx.write_secret_raw(&OsString::from_vec(p), tag);
    }
    fx.archive();

    let originals = fx.originals();
    assert_eq!(
        originals.len(),
        2,
        "two secret-bearing originals produced {} quarantine files — one \
         overwrote the other, and an unredacted original has no second copy. \
         Paths: {:?}",
        originals.len(),
        originals
            .iter()
            .map(|b| String::from_utf8_lossy(b))
            .collect::<Vec<_>>()
    );
    // And each file must still hold its *own* original, not two copies of one.
    let mut tags: Vec<String> = walk_files(&fx.quarantine())
        .iter()
        .filter_map(|p| tag_of(p))
        .collect();
    tags.sort();
    assert_eq!(
        tags,
        vec!["FE".to_string(), "FF".to_string()],
        "the two quarantine files do not hold the two distinct originals"
    );
}

/// A scratch file literally named `a.md.zst` sits at `<rel>.zst.zst` in the
/// store, so stripping one suffix must land it on `a.md.zst` — distinct from
/// the original of a sibling actually named `a.md`. Removing more than one
/// suffix, or removing it from the wrong end, merges them.
#[test]
fn p13_a_zst_named_file_does_not_collide_with_its_stem() {
    let fx = Fx::with_config("inj-zst", "[scratch]\nallow = [\"*.md\",\"*.zst\"]\n");
    fx.write_secret("a.md", "PLAIN");
    fx.write_secret("a.md.zst", "ZSTNAME");
    fx.archive();

    let originals = fx.originals();
    assert_eq!(
        originals.len(),
        2,
        "two originals collapsed to {}: {:?}",
        originals.len(),
        originals
            .iter()
            .map(|b| String::from_utf8_lossy(b))
            .collect::<Vec<_>>()
    );
    let q = fx.quarantine().join("_scratch");
    let a = walk_files(&q)
        .into_iter()
        .find(|p| p.file_name().unwrap() == "a.md")
        .expect("no original for a.md");
    let z = walk_files(&q)
        .into_iter()
        .find(|p| p.file_name().unwrap() == "a.md.zst")
        .expect("no original for a.md.zst");
    assert_eq!(
        tag_of(&a).as_deref(),
        Some("PLAIN"),
        "a.md holds the wrong original"
    );
    assert_eq!(
        tag_of(&z).as_deref(),
        Some("ZSTNAME"),
        "a.md.zst holds the wrong original"
    );
}

/// A scratch file named `x.meta.json` — the shape the injectivity argument
/// reserves for uncompressed subagent metas. It is stored compressed, so its
/// original must land at `x.meta.json` under `_scratch/`, a subtree no session
/// artifact can reach.
#[test]
fn p13_meta_json_named_scratch_file_stays_in_its_own_subtree() {
    let fx = Fx::with_config("inj-meta", "[scratch]\nallow = [\"*.json\"]\n");
    fx.write_secret("x.meta.json", "SCRATCHMETA");
    fx.archive();

    let originals = fx.originals();
    assert_eq!(
        originals.len(),
        1,
        "unexpected original count: {originals:?}"
    );
    let p = String::from_utf8_lossy(&originals[0]).into_owned();
    assert!(
        p.starts_with("_scratch/"),
        "a scratch original escaped the _scratch subtree: {p}"
    );
    assert!(
        p.ends_with("x.meta.json"),
        "the .meta.json suffix was altered: {p}"
    );
}

// ---------------------------------------------------------------------------
// B. The tree boundary — N4, self-reported and unfixed.
// ---------------------------------------------------------------------------

/// `quarantine_original` builds its hierarchy with `create_dir_all` and
/// `set_permissions`, both of which **follow symlinks**. A symlink planted at
/// any mirrored level therefore sends the unredacted original — and a 700 —
/// wherever it points.
///
/// The store has `classify_store_dir` for exactly this; quarantine has no
/// equivalent. This is heavier than the store-side version of the same gap
/// because the bytes being written *are* the secret.
#[test]
fn p13_symlinked_quarantine_level_does_not_redirect_the_original() {
    let fx = Fx::new("sym-level");
    fx.write_secret("leak.md", "LEAK");

    let evil = fx.base.join("evil");
    std::fs::create_dir_all(&evil).unwrap();
    std::fs::set_permissions(&evil, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mode_before = std::fs::metadata(&evil).unwrap().permissions().mode() & 0o777;

    std::fs::create_dir_all(fx.quarantine()).unwrap();
    std::fs::set_permissions(fx.quarantine(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&evil, fx.quarantine().join("_scratch")).unwrap();

    fx.archive();

    let escaped = walk_files(&evil);
    let mode_after = std::fs::metadata(&evil).unwrap().permissions().mode() & 0o777;
    let leaked = escaped.iter().any(|p| {
        std::fs::read(p)
            .map(|b| contains(&b, FIXTURE_AKIA.as_bytes()))
            .unwrap_or(false)
    });

    assert!(
        escaped.is_empty(),
        "the unredacted original was written outside quarantine/ through a \
         symlinked level: {} file(s) under {}, secret present: {leaked}. The \
         symlink target was also re-moded {mode_before:o} -> {mode_after:o}. \
         `create_dir_all` and `set_permissions` both follow links, and \
         quarantine has no `classify_store_dir` equivalent.",
        escaped.len(),
        evil.display()
    );
    assert_eq!(
        mode_after, mode_before,
        "an unrelated directory was chmod'd through the symlink"
    );
}

/// The same attack one level deeper, at a directory the mirrored layout newly
/// creates: `_scratch/<K>/`. The old two-level layout never made this level, so
/// it is new surface.
#[test]
fn p13_symlinked_scratch_key_level_does_not_redirect_the_original() {
    let fx = Fx::new("sym-key");
    fx.write_secret("leak.md", "LEAK");

    let evil = fx.base.join("evil2");
    std::fs::create_dir_all(&evil).unwrap();
    let qk = fx.quarantine().join("_scratch");
    std::fs::create_dir_all(&qk).unwrap();
    std::os::unix::fs::symlink(&evil, qk.join(format!("{}--{}", fx.slug, fx.uuid))).unwrap();

    fx.archive();

    let escaped = walk_files(&evil);
    assert!(
        escaped.is_empty(),
        "the unredacted original escaped through a symlink at the <K> level, \
         which the mirrored layout newly introduces: {} file(s) under {}",
        escaped.len(),
        evil.display()
    );
}

// ---------------------------------------------------------------------------
// C. Permissions — every level, not just the first.
// ---------------------------------------------------------------------------

/// The mirrored layout is deeper than the two-level one it replaced, and
/// `Archiver` is a library type usable without `ensure_layout` having tightened
/// the umask. Every directory must be 700 and every original 600 regardless.
#[test]
fn p13_every_quarantine_level_is_owner_only_under_a_wide_umask() {
    let fx = Fx::new("perm");
    fx.write_secret("leak.md", "A");
    fx.write_secret("x/y/z/deep.md", "B");

    // A shell so the child really starts with umask 000.
    let sh = format!(
        "umask 000; exec {} archive --all --include scratch --home {}",
        shq(BIN),
        shq(&fx.yomi_home.to_string_lossy())
    );
    let out = Command::new("/bin/sh")
        .arg("-c")
        .arg(&sh)
        .env("HOME", &fx.home)
        .env("YOMI_TMP_ROOT", &fx.tmp_root)
        .env("YOMI_CACHE_HOME", &fx.cache_home)
        .env("YOMI_PROC_ROOT", &fx.proc_root)
        .env_remove("YOMI_HOME")
        .env_remove("YOMI_CLAUDE_HOME")
        .output()
        .expect("archive under umask 000");
    assert!(out.status.success(), "archive under umask 000 failed");

    let mut loose = Vec::new();
    let mut stack = vec![fx.quarantine()];
    let mut seen_dirs = 0;
    while let Some(p) = stack.pop() {
        let md = std::fs::symlink_metadata(&p).unwrap();
        let mode = md.permissions().mode() & 0o777;
        if md.is_dir() {
            seen_dirs += 1;
            if mode != 0o700 {
                loose.push(format!("{} = {mode:o} (dir)", p.display()));
            }
            for e in std::fs::read_dir(&p).unwrap().flatten() {
                stack.push(e.path());
            }
        } else if mode != 0o600 {
            loose.push(format!("{} = {mode:o} (file)", p.display()));
        }
    }
    assert!(
        seen_dirs >= 5,
        "fixture did not exercise the deep layout ({seen_dirs} dirs)"
    );
    assert!(
        loose.is_empty(),
        "quarantine entries not owner-only under umask 000: {loose:#?}"
    );
}

fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

// ---------------------------------------------------------------------------
// D. Salvage carries the flag — the implementer's untested completion.
// ---------------------------------------------------------------------------

/// When a capture fails and an earlier capture is salvaged, `quarantined` must
/// be carried with `stored` and the hashes. Dropping it makes the ledger deny an
/// original that is still on disk, which law Q2 reads as a stray.
///
/// Skipped under uid 0, which ignores the mode bits this fixture relies on.
#[test]
fn p13_salvage_carries_the_quarantined_flag() {
    if is_root() {
        return;
    }
    let fx = Fx::new("salvage");
    fx.write_secret("leak.md", "LEAK");
    fx.archive();

    let first = fx.manifest();
    let e0 = &first["entries"][0];
    assert_eq!(
        e0["quarantined"], true,
        "fixture did not quarantine on the first archive: {e0}"
    );
    let originals_before = fx.originals();
    assert_eq!(originals_before.len(), 1);

    // The live file becomes unreadable: capture fails, the earlier capture is
    // salvaged, and the original written last time is still there.
    let leak = fx.session_dir().join("scratchpad/leak.md");
    std::fs::set_permissions(&leak, std::fs::Permissions::from_mode(0o000)).unwrap();
    fx.archive();
    let after = fx.manifest();
    std::fs::set_permissions(&leak, std::fs::Permissions::from_mode(0o644)).unwrap();

    let e1 = &after["entries"][0];
    assert_eq!(
        e1["capture_failed"], true,
        "fixture did not reach the salvage path: {e1}"
    );
    assert_eq!(e1["stored"], true, "salvage dropped the stored claim: {e1}");
    assert_eq!(
        e1["quarantined"], true,
        "salvage kept `stored` and the hashes but dropped `quarantined`, so the \
         ledger now denies an original that is still on disk: {e1}"
    );
    assert_eq!(
        fx.originals(),
        originals_before,
        "the salvage run disturbed the quarantine tree"
    );
}

// ---------------------------------------------------------------------------
// E. Non-exposure — the boundary moved: never open, name, or point at.
// ---------------------------------------------------------------------------

/// No routine command may emit a raw secret, name the quarantine tree, or emit a
/// path from which a quarantine path is derivable. `read`'s per-entry
/// `quarantined` flag was removed for exactly this reason; nothing else may
/// reintroduce the pointer.
#[test]
fn p13_no_routine_command_points_at_the_quarantine_tree() {
    let fx = Fx::new("noexpose");
    fx.write_secret("leak.md", "LEAK");
    fx.archive();
    assert_eq!(fx.originals().len(), 1, "fixture quarantined nothing");

    let key = format!("{}--{}", fx.slug, fx.uuid);
    let cmds: Vec<Vec<&str>> = vec![
        vec!["read", "--scratch", &key],
        vec!["read", "--scratch", &key, "--json"],
        vec!["read", "--scratch", &key, "--file", "scratchpad/leak.md"],
        vec!["verify"],
        vec!["verify", "--json"],
        vec!["status"],
        vec!["status", "--json"],
        vec!["status", "--secrets"],
        vec!["gc", "--targets", "scratch"],
        vec!["gc", "--targets", "scratch", "--json"],
    ];
    for c in &cmds {
        let o = fx.run(c);
        let all = o.all();
        assert!(
            !contains(&all, FIXTURE_AKIA.as_bytes()),
            "`{}` emitted the raw secret",
            c.join(" ")
        );
        assert!(
            !contains(&all, b"quarantine/"),
            "`{}` named a path under quarantine/",
            c.join(" ")
        );
    }

    // The per-entry pointer specifically. `status` carries a store-wide
    // `"quarantined": N` count, which is a different granularity — it says some
    // originals exist, not that *this* entry has one at a path derivable from
    // its own identity. The flag that was removed is the per-entry one in
    // `read --scratch`'s listing, and only that is asserted here.
    let listing = fx.run(&["read", "--scratch", &key, "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&listing.stdout).expect("listing json");
    for e in v["entries"].as_array().expect("entries") {
        assert!(
            e.get("quarantined").is_none(),
            "`read --scratch --json` reintroduced the per-entry `quarantined` \
             pointer: under the mirror rule an entry's quarantine path is \
             derivable from its identity, so the flag points at the tree. {e}"
        );
    }
    // The stored bytes answer the reader's question instead: the marker.
    let f = fx.run(&["read", "--scratch", &key, "--file", "scratchpad/leak.md"]);
    assert!(
        contains(&f.stdout, "REDACTED".as_bytes()) || contains(&f.stdout, "QUARANTINED".as_bytes()),
        "a quarantined entry did not read back as an opaque marker"
    );
}

// ---------------------------------------------------------------------------
// F. D-S8 — archive and rescan derive one path for one artifact.
// ---------------------------------------------------------------------------

/// The two writers used to differ by how much of the path the `<uuid>` level had
/// already consumed, so one artifact could hold originals at two paths with
/// neither canonical. Both routes are run over identical input and must land on
/// the same quarantine-relative path.
#[test]
fn p13_archive_and_rescan_agree_on_the_quarantine_path() {
    let session_uuid = "11111111-2222-3333-4444-555555555555";
    let transcript = |fx: &Fx| {
        let line = serde_json::json!({
            "type": "user", "uuid": "u-1", "parentUuid": null,
            "timestamp": "2026-07-12T10:00:00.000Z", "cwd": "/home/test",
            "gitBranch": "main", "version": "2.1.207", "sessionId": session_uuid,
            "message": {"role": "user", "content": format!("aws_access_key_id = {FIXTURE_AKIA}")}
        });
        std::fs::write(
            fx.home
                .join(".claude/projects")
                .join(&fx.slug)
                .join(format!("{session_uuid}.jsonl")),
            line.to_string() + "\n",
        )
        .unwrap();
    };

    // Route 1: archive scans and quarantines.
    let a = Fx::new("ds8-archive");
    transcript(&a);
    assert_eq!(a.run(&["archive", "--all"]).code, 0);
    let by_archive = a.originals();

    // Route 2: archive defers, rescan quarantines.
    let r = Fx::new("ds8-rescan");
    transcript(&r);
    assert_eq!(r.run(&["archive", "--all", "--no-scan"]).code, 0);
    assert_eq!(r.run(&["index"]).code, 0);
    r.run(&["rescan", "--commit"]);
    let by_rescan = r.originals();

    assert!(
        !by_archive.is_empty(),
        "the archive route quarantined nothing; the comparison is vacuous"
    );
    assert_eq!(
        by_archive
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect::<Vec<_>>(),
        by_rescan
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect::<Vec<_>>(),
        "archive and rescan derived different quarantine paths for the same \
         artifact, so one artifact can hold originals at two paths"
    );
}

// ---------------------------------------------------------------------------
// G. Legacy trees are never touched.
// ---------------------------------------------------------------------------

/// There is no migration code, deliberately: a legacy original may be the only
/// copy that exists. Every command must leave both old layouts byte-identical.
#[test]
fn p13_legacy_quarantine_layouts_are_never_disturbed() {
    let fx = Fx::new("legacy");
    fx.write_secret("leak.md", "NEW");

    // Both historical shapes.
    let old_session = fx.quarantine().join("OLDUUID/subdir");
    let old_scratch = fx.quarantine().join("_scratch--OLDK/OLDK");
    for d in [&old_session, &old_scratch] {
        std::fs::create_dir_all(d).unwrap();
    }
    let legacy = [old_session.join("old.jsonl"), old_scratch.join("old.md")];
    for (i, p) in legacy.iter().enumerate() {
        std::fs::write(p, format!("legacy-{i} {FIXTURE_AKIA}\nTAG-LEGACY{i}\n")).unwrap();
    }
    let before: Vec<(PathBuf, Vec<u8>)> = legacy
        .iter()
        .map(|p| (p.clone(), std::fs::read(p).unwrap()))
        .collect();

    let key = format!("{}--{}", fx.slug, fx.uuid);
    for c in [
        vec!["archive", "--all", "--include", "scratch"],
        vec!["index"],
        vec!["rescan", "--commit"],
        vec!["verify"],
        vec!["gc", "--targets", "scratch", "--commit"],
        vec!["read", "--scratch", &key],
    ] {
        fx.run(&c);
    }

    for (p, b) in &before {
        assert!(p.exists(), "a legacy original was removed: {}", p.display());
        assert_eq!(
            &std::fs::read(p).unwrap(),
            b,
            "a legacy original was modified: {}",
            p.display()
        );
    }
    // And the new-rule original landed beside them without disturbing them.
    assert!(
        fx.quarantine().join("_scratch").is_dir(),
        "the mirrored tree was not created alongside the legacy ones"
    );
}
