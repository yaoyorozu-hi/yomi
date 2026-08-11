//! P20 break tests: `archive --full`.
//!
//! `--full` adds **exactly two** things to `archive`: every source family when no
//! `--include` narrows it, and the `[scratch]` caps lifted. Everything else about
//! the run is unchanged, and most of this file is about what it must *not* touch:
//!
//! * **`--include all` keeps the caps.** It selected all eight families before
//!   `--full` existed and it still does, under the caps. A `--full` that redefined
//!   it would make every existing `--include all` caller start hoarding silently,
//!   and would delete the useful "every family, caps still applied" combination.
//! * **the allow/deny globs are not lifted.** `--full` lifts caps, not policy: a
//!   `.git` tree is no more archivable with it than without it.
//! * **`--include` still decides the families.** `--full --include transcript`
//!   archives transcripts and no scratch at all — the cap lift is then inert.
//!
//! And one thing it *must* do beyond storing bytes: **name the narrowing it makes
//! possible.** A `--full` run stores N artifacts; a later plain
//! `--include scratch` run applies the caps, finds them unclaimed, and
//! reconciliation removes them. That removal is store law S working as specified —
//! the store holds what current policy stores — but a removal whose cause has no
//! name is indistinguishable from a defect, so the manifest records `caps_lifted`
//! and the run says which rule dropped what.
//!
//! Every fixture is fabricated under `CARGO_TARGET_TMPDIR` and removed when the
//! fixture drops. No real Claude Code data, no `~/.yomi`, no `/tmp` (issue #48).

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const BIN: &str = env!("CARGO_BIN_EXE_yomi");

/// Two allow-listed files of this size each: over a 1KB `total_cap` together,
/// under it individually, so only the *tree* cap can be what declines them.
const FILE_BYTES: usize = 801;

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
    fn new(tag: &str) -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "p20-{tag}-{}-{}",
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

    /// `ScratchConfig` is `#[serde(default)]`, so the allow/deny globs keep their
    /// design values and the caps are the only variables.
    fn set_caps(&self, file_cap: &str, total_cap: &str) {
        std::fs::write(
            self.yomi_home.join("config.toml"),
            format!("[scratch]\nfile_cap = \"{file_cap}\"\ntotal_cap = \"{total_cap}\"\n"),
        )
        .unwrap();
    }

    fn session_dir(&self) -> PathBuf {
        self.tmp_root.join(&self.slug).join(&self.uuid)
    }

    fn key(&self) -> String {
        format!("{}--{}", self.slug, self.uuid)
    }

    fn store_root(&self) -> PathBuf {
        self.yomi_home.join("archive/_scratch")
    }

    fn store_dir(&self) -> PathBuf {
        self.store_root().join(self.key())
    }

    fn write(&self, rel: &str, bytes: &[u8]) {
        let p = self.session_dir().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
    }

    /// A transcript, so the session families have real work to do and a run can be
    /// shown to have continued past (or stopped at) the scratch family.
    fn write_transcript(&self) {
        let p = self
            .home
            .join(".claude/projects")
            .join(&self.slug)
            .join(format!("{}.jsonl", self.uuid));
        std::fs::write(
            &p,
            serde_json::json!({"type": "user", "message": {"role": "user", "content": "hi"}})
                .to_string()
                + "\n",
        )
        .unwrap();
    }

    /// Two allow-listed files, each under any `file_cap` used here, together over
    /// the 1KB `total_cap`.
    fn write_over_cap_tree(&self) {
        self.write("scratchpad/a.md", &[b'A'; FILE_BYTES]);
        self.write("scratchpad/b.md", &[b'B'; FILE_BYTES]);
    }

    fn run_at(&self, tmp_root: &Path, args: &[&str]) -> Out {
        let o = Command::new(BIN)
            .args(args)
            .arg("--home")
            .arg(&self.yomi_home)
            .env("HOME", &self.home)
            .env("YOMI_TMP_ROOT", tmp_root)
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

    fn run(&self, args: &[&str]) -> Out {
        self.run_at(&self.tmp_root, args)
    }

    /// A successful `archive`, as its `--json` report.
    fn archive(&self, args: &[&str]) -> serde_json::Value {
        let mut v = vec!["archive"];
        v.extend_from_slice(args);
        v.push("--json");
        let out = self.run(&v);
        assert_eq!(out.code, 0, "archive {args:?} failed: {}", out.summary());
        out.json()
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

    fn keys(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.store_root())
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
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
            .unwrap_or_else(|e| panic!("archive --json unparseable ({e}): {}", self.summary()))
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
// A. What `--full` must not change.
// ---------------------------------------------------------------------------

/// **The regression that matters most.** `--include all` selected every family
/// under the caps before `--full` existed, and its meaning is untouched: an
/// over-cap tree is still manifest-only. Anything else and every existing
/// `--include all` caller — cron entries, scripts — silently starts hoarding.
#[test]
fn p20_a_include_all_keeps_the_caps() {
    let fx = Fx::new("include-all");
    fx.set_caps("5MB", "1KB");
    fx.write_transcript();
    fx.write_over_cap_tree();

    let r = fx.archive(&["--all", "--include", "all"]);

    let mf = fx.manifest();
    assert_eq!(
        mf["over_total_cap"], true,
        "--include all stopped applying total_cap: {mf:#}"
    );
    assert!(
        entries(&mf).iter().all(|e| e["stored"] == false),
        "an over-cap tree stored entries under --include all: {mf:#}"
    );
    assert_eq!(
        fx.stored_zst(),
        Vec::<String>::new(),
        "--include all stored an over-cap tree's bytes"
    );
    assert!(
        mf.get("caps_lifted").is_none(),
        "--include all recorded lifted caps: {mf:#}"
    );
    // The families really were all selected, so this is not a vacuous pass.
    assert_eq!(r["sessions"], 1, "--include all archived no session: {r:#}");
    assert_eq!(
        fx.keys(),
        vec![fx.key()],
        "scratch was not enumerated at all"
    );
}

/// `--full` lifts the caps, not the policy. The allow/deny globs are the whole of
/// `[scratch]` policy that says *what kind of file* is archive-worthy, and a `.git`
/// object under a flag named "full" is exactly the 134M-clone hoarding decision #4
/// exists to refuse.
#[test]
fn p20_a_full_does_not_lift_the_allow_deny_globs() {
    let fx = Fx::new("globs");
    fx.set_caps("5MB", "20MB");
    // `.git/x.json` matches an allow glob *and* a deny glob — the only way to
    // reach `Denied`, since `allow` is tested first.
    fx.write(".git/x.json", b"{}\n");
    fx.write("data.dat", b"not an allowed extension\n");
    fx.write("scratchpad/keep.md", b"kept\n");

    fx.archive(&["--full", "--include", "scratch"]);

    let mf = fx.manifest();
    assert_eq!(mf["caps_lifted"], true, "the fixture did not run --full");
    for (path, reason) in [(".git/x.json", "denied"), ("data.dat", "not_allowed")] {
        let e = entry(&mf, path);
        assert_eq!(
            e["stored"], false,
            "--full stored a file the globs refused ({path}): {mf:#}"
        );
        assert_eq!(
            e["not_stored"], reason,
            "the recorded cause moved for {path}: {mf:#}"
        );
    }
    assert_eq!(
        fx.stored_zst(),
        vec!["scratchpad/keep.md.zst"],
        "only the allow-listed file may have an artifact under --full"
    );
}

/// `--include` decides the families; `--full` only supplies a default. With
/// `transcript` named, no scratch is enumerated and the cap lift is inert.
#[test]
fn p20_a_full_with_an_explicit_include_archives_only_that_family() {
    let fx = Fx::new("narrow-include");
    fx.set_caps("5MB", "1KB");
    fx.write_transcript();
    fx.write_over_cap_tree();

    let r = fx.archive(&["--all", "--full", "--include", "transcript"]);

    assert_eq!(r["sessions"], 1, "the transcript was not archived: {r:#}");
    assert!(
        fx.keys().is_empty(),
        "--full --include transcript enumerated scratch: {:?}",
        fx.keys()
    );
}

// ---------------------------------------------------------------------------
// B. What `--full` does.
// ---------------------------------------------------------------------------

/// The tree cap is lifted: a tree over `total_cap` stores every allow-listed file,
/// `over_total_cap` is false because no cap was applied, and `total_bytes` is still
/// measured — lifting a cap is not a reason to stop knowing what it would have
/// decided.
#[test]
fn p20_b_full_lifts_the_total_cap() {
    let fx = Fx::new("total-cap");
    fx.set_caps("5MB", "1KB");
    fx.write_over_cap_tree();

    fx.archive(&["--full", "--include", "scratch"]);

    let mf = fx.manifest();
    assert_eq!(
        mf["over_total_cap"], false,
        "--full left the tree cap applied: {mf:#}"
    );
    assert_eq!(
        mf["total_bytes"],
        (2 * FILE_BYTES) as u64,
        "--full stopped measuring the tree: {mf:#}"
    );
    assert_eq!(
        fx.stored_zst(),
        vec!["scratchpad/a.md.zst", "scratchpad/b.md.zst"],
        "an over-cap tree stored nothing under --full: {mf:#}"
    );
    assert!(
        entries(&mf).iter().all(|e| e["stored"] == true),
        "an entry stayed unstored under --full: {mf:#}"
    );
}

/// The per-file cap is lifted too, and the `file_cap` cause disappears with it —
/// `not_stored: "file_cap"` is a decision, and under `--full` no such decision is
/// taken.
#[test]
fn p20_b_full_lifts_the_file_cap() {
    let fx = Fx::new("file-cap");
    fx.set_caps("100B", "20MB");
    fx.write("scratchpad/big.md", &[b'B'; FILE_BYTES]);

    // Control: the cap is real, and it is the cap that declines the file.
    fx.archive(&["--all", "--include", "scratch"]);
    let mf = fx.manifest();
    assert_eq!(entry(&mf, "scratchpad/big.md")["not_stored"], "file_cap");
    assert_eq!(fx.stored_zst(), Vec::<String>::new());

    fx.archive(&["--full", "--include", "scratch"]);

    let mf = fx.manifest();
    let e = entry(&mf, "scratchpad/big.md");
    assert_eq!(e["stored"], true, "--full left file_cap applied: {mf:#}");
    assert!(
        e.get("not_stored").is_none(),
        "--full stored the file and still recorded a cause for not storing it: {mf:#}"
    );
    assert_eq!(fx.stored_zst(), vec!["scratchpad/big.md.zst"]);
}

/// `--full` implies `--all` when nothing else selects. `yomi archive --full` is
/// what an operator types for "archive everything"; reaching the selector bail
/// would make the flag's own spelling an error.
#[test]
fn p20_b_full_implies_a_selector_when_none_is_given() {
    let fx = Fx::new("implied-selector");
    fx.set_caps("5MB", "1KB");
    fx.write_transcript();
    fx.write_over_cap_tree();

    let out = fx.run(&["archive", "--full", "--json"]);
    assert_eq!(
        out.code,
        0,
        "--full alone did not archive: {}",
        out.summary()
    );
    let r = out.json();
    assert_eq!(r["sessions"], 1, "no session was discovered: {r:#}");
    assert_eq!(
        fx.stored_zst(),
        vec!["scratchpad/a.md.zst", "scratchpad/b.md.zst"],
        "the scratch family did not run under a bare --full"
    );

    // The bail it stands in for is otherwise unchanged: without `--full` and
    // without a selector, the run still refuses rather than guessing.
    let bare = fx.run(&["archive", "--include", "transcript", "--json"]);
    assert_ne!(
        bare.code,
        0,
        "a selector-less run without --full succeeded: {}",
        bare.summary()
    );
    assert!(
        bare.stderr.contains("--all"),
        "the selector refusal lost its message: {}",
        bare.summary()
    );
}

/// A session selector still narrows under `--full`: the flag fills an *empty*
/// selector, it does not widen an explicit one.
#[test]
fn p20_b_full_does_not_widen_an_explicit_selector() {
    let fx = Fx::new("explicit-selector");
    fx.set_caps("5MB", "1KB");
    fx.write_transcript();
    let other = "bbbb2222-3333-4444-5555-666666666666";
    std::fs::write(
        fx.home
            .join(".claude/projects")
            .join(&fx.slug)
            .join(format!("{other}.jsonl")),
        serde_json::json!({"type": "user", "message": {"role": "user", "content": "other"}})
            .to_string()
            + "\n",
    )
    .unwrap();

    let r = fx.archive(&["--full", "--session", other, "--include", "transcript"]);
    assert_eq!(
        r["sessions"], 1,
        "--full widened an explicit --session to every session: {r:#}"
    );
}

// ---------------------------------------------------------------------------
// C. `caps_lifted`, and the narrowing it names.
// ---------------------------------------------------------------------------

/// The field is recorded when the caps were lifted, absent when they were not, and
/// a manifest written before it existed parses as `false` rather than failing.
#[test]
fn p20_c_caps_lifted_is_recorded_and_is_additive() {
    let fx = Fx::new("caps-lifted-field");
    fx.set_caps("5MB", "20MB");
    fx.write("scratchpad/a.md", b"a\n");

    fx.archive(&["--all", "--include", "scratch"]);
    let capped = fx.manifest();
    assert!(
        capped.get("caps_lifted").is_none(),
        "a capped run wrote the field, so a pre-field manifest is no longer \
         byte-identical: {capped:#}"
    );

    fx.archive(&["--full", "--include", "scratch"]);
    assert_eq!(
        fx.manifest()["caps_lifted"],
        true,
        "--full did not record that it lifted the caps"
    );

    // A ledger from before the field: it parses, and reads as "caps were in
    // force" — the conservative side, since claiming a lift would attribute a
    // later narrowing to a run that never happened.
    let pre_field = serde_json::json!({
        "key": fx.key(),
        "slug_hex": "",
        "uuid_hex": "",
        "captured_at": "2026-01-01T00:00:00Z",
        "total_bytes": 2,
        "over_total_cap": false,
        "entries": [],
    });
    let mf: yomi::scratch::ScratchManifest =
        serde_json::from_str(&pre_field.to_string()).expect("a pre-field manifest must parse");
    assert!(
        !mf.caps_lifted,
        "a manifest with no caps_lifted field read as lifted"
    );
}

/// **The data-loss path `--full` opens, and the fix.** Store under `--full`, then
/// run a plain `--include scratch`: the caps apply, the ledger no longer claims
/// those artifacts, and reconciliation removes them. Store law S is upheld — the
/// behaviour is deliberate — so what this pins is that the loss is *named*: the
/// counts separate the cap from every other reason an artifact can go, and the
/// human output says which rule dropped what, and that the previous run had the
/// caps lifted.
#[test]
fn p20_c_a_narrowing_run_names_the_rule_that_dropped_the_artifacts() {
    let fx = Fx::new("narrowing");
    fx.set_caps("5MB", "1KB");
    fx.write_over_cap_tree();

    fx.archive(&["--full", "--include", "scratch"]);
    assert_eq!(
        fx.stored_zst(),
        vec!["scratchpad/a.md.zst", "scratchpad/b.md.zst"],
        "the fixture stored nothing, so there is nothing to narrow"
    );

    // Visible *before* it happens: a dry run reports the same loss and its cause,
    // and removes nothing. An operator can only avoid this by being told in
    // advance, and `--dry-run` is where they would look.
    let d = fx.archive(&["--all", "--include", "scratch", "--dry-run"]);
    assert_eq!(d["scratch_orphans_removed"], 2, "{d:#}");
    assert_eq!(
        d["scratch_orphans_cap_declined"], 2,
        "a dry run withheld the cause of a loss it predicted: {d:#}"
    );
    assert_eq!(d["scratch_keys_caps_reimposed"], 1, "{d:#}");
    assert_eq!(
        fx.stored_zst().len(),
        2,
        "a dry run removed the artifacts it was only supposed to predict"
    );

    let r = fx.archive(&["--all", "--include", "scratch"]);

    assert_eq!(
        fx.stored_zst(),
        Vec::<String>::new(),
        "the caps came back and the artifacts they decline stayed: the store holds \
         bytes the ledger denies"
    );
    assert_eq!(
        r["scratch_orphans_removed"], 2,
        "the removal was not reported: {r:#}"
    );
    assert_eq!(
        r["scratch_orphans_cap_declined"], 2,
        "the removal was reported without naming the caps as its cause, so it is \
         indistinguishable from an operator's glob edit: {r:#}"
    );
    assert_eq!(
        r["scratch_keys_caps_reimposed"], 1,
        "the run that stored those bytes had the caps lifted and the report does \
         not say so: {r:#}"
    );

    // The same facts on the human path, which is the one an operator reads.
    let fx = Fx::new("narrowing-human");
    fx.set_caps("5MB", "1KB");
    fx.write_over_cap_tree();
    fx.archive(&["--full", "--include", "scratch"]);
    let out = fx.run(&["archive", "--all", "--include", "scratch"]);
    assert_eq!(out.code, 0, "{}", out.summary());
    for needle in [
        "2 stored scratch artifacts were removed",
        "the [scratch] caps declined 2 of them",
        "1 of those store keys had a --full run as their last archive",
        "Re-run with --full",
    ] {
        assert!(
            out.stdout.contains(needle),
            "the narrowing message does not say {needle:?}: {}",
            out.summary()
        );
    }
}

/// The cause is attributed to the rule that actually applied. A glob edit removes
/// an artifact too, and it must **not** be reported as a cap — the remedies are
/// opposite (widen a cap or re-run `--full`, versus edit `allow`/`deny`).
#[test]
fn p20_c_a_glob_narrowing_is_not_attributed_to_the_caps() {
    let fx = Fx::new("glob-narrowing");
    fx.set_caps("5MB", "20MB");
    fx.write("scratchpad/a.md", b"a\n");
    fx.write("scratchpad/b.md", b"b\n");

    fx.archive(&["--all", "--include", "scratch"]);
    assert_eq!(fx.stored_zst().len(), 2, "fixture stored nothing");

    std::fs::write(
        fx.yomi_home.join("config.toml"),
        "[scratch]\nallow = [\"b.md\"]\n",
    )
    .unwrap();
    let r = fx.archive(&["--all", "--include", "scratch"]);

    assert_eq!(r["scratch_orphans_removed"], 1, "{r:#}");
    assert_eq!(
        r["scratch_orphans_cap_declined"], 0,
        "a glob narrowing was blamed on the caps: {r:#}"
    );
    assert_eq!(r["scratch_keys_caps_reimposed"], 0, "{r:#}");
}

// ---------------------------------------------------------------------------
// D. The foreign source root, under `--full`.
// ---------------------------------------------------------------------------

fn euid() -> u32 {
    static UID: OnceLock<u32> = OnceLock::new();
    *UID.get_or_init(|| {
        let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("p20-uid-{}", unique()));
        std::fs::write(&p, b"").unwrap();
        let uid = std::fs::metadata(&p).unwrap().uid();
        let _ = std::fs::remove_file(&p);
        uid
    })
}

/// A real directory on this host owned by another uid, standing in for a poisoned
/// `YOMI_TMP_ROOT` (fabricating one needs root). `None` when this process is root:
/// nothing is foreign to uid 0, so there is no guard to exercise. See P19.
fn foreign_root() -> Option<PathBuf> {
    if euid() == 0 {
        return None;
    }
    let root = ["/var/empty", "/root"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| {
            std::fs::metadata(p)
                .map(|md| md.is_dir() && md.uid() != euid())
                .unwrap_or(false)
        });
    assert!(
        root.is_some(),
        "no foreign-owned directory found on this host; nothing here can be proven"
    );
    root
}

/// `--full` inherits the source-root refusal unchanged (P19): a `tmp_root` this
/// user does not own archives no scratch, says so in its own register, and does not
/// end the run — the other families come off `claude_home` and have nothing to do
/// with where `tmp_root` points. "Full" is not an authority to archive another
/// user's files.
#[test]
fn p20_d_full_still_refuses_a_foreign_source_root() {
    let Some(foreign) = foreign_root() else {
        return;
    };
    let fx = Fx::new("foreign-root");
    fx.set_caps("5MB", "1KB");
    fx.write_transcript();
    // Under the fixture's own root, which is *not* the root the run is given:
    // nothing here may be archived either.
    fx.write_over_cap_tree();

    let out = fx.run_at(&foreign, &["archive", "--full", "--json"]);
    assert_eq!(
        out.code,
        0,
        "a foreign root ended the run: {}",
        out.summary()
    );
    assert!(
        out.stderr
            .contains("scratch source root is not owned by this user"),
        "the refusal was not reported: {}",
        out.summary()
    );
    assert!(
        !out.stderr.contains("skip unreadable source"),
        "a foreign root was reported as an unreadable source: {}",
        out.summary()
    );
    assert!(
        fx.keys().is_empty(),
        "a foreign root produced store keys {:?}",
        fx.keys()
    );
    assert_eq!(
        out.json()["sessions"],
        1,
        "the session sources were dropped along with scratch: {}",
        out.summary()
    );
}
