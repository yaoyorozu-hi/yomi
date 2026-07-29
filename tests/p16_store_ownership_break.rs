//! P16 break tests: adversarial assault on U7 — store-root ownership and the
//! two predicates (§3 "Ownership depth", §5).
//!
//! Three changes answering one question: what counts as evidence that a store is
//! here and ours. So the attacks are — can a path yomi asserts it owns be made
//! foreign after the assertion; can the lock gate be made to create a store on a
//! fresh home; and what does withholding Q2 on a lost catalog cost.
//!
//! Written to BREAK, not to confirm. Fixtures live under `CARGO_TARGET_TMPDIR`.
//! Secret fixtures use the public AWS documentation example key, which
//! authenticates nothing.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_yomi");
const FIXTURE_AKIA: &str = "AKIAIOSFODNN7EXAMPLE";
const SESSION: &str = "11111111-2222-3333-4444-555555555555";

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
}

impl Fx {
    fn new(tag: &str) -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "p16-{tag}-{}-{}",
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
            base,
        };
        std::fs::create_dir_all(fx.home.join(".claude/projects/-p")).unwrap();
        std::fs::create_dir_all(fx.tmp_root.join("-p/s1/scratchpad")).unwrap();
        for d in [&fx.cache_home, &fx.proc_root, &fx.yomi_home] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::set_permissions(&fx.yomi_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        fx
    }

    /// A transcript and a scratch file, both secret-bearing, so a run produces
    /// both a catalog row and a quarantine original.
    fn seed(&self) {
        std::fs::write(
            self.tmp_root.join("-p/s1/scratchpad/leak.md"),
            format!("aws_access_key_id = {FIXTURE_AKIA}\n"),
        )
        .unwrap();
        let line = serde_json::json!({
            "type": "user", "uuid": "u-1", "parentUuid": null,
            "timestamp": "2026-07-12T10:00:00.000Z", "cwd": "/x",
            "gitBranch": "m", "version": "1", "sessionId": SESSION,
            "message": {"role": "user", "content": format!("aws_access_key_id = {FIXTURE_AKIA}")}
        });
        std::fs::write(
            self.home
                .join(".claude/projects/-p")
                .join(format!("{SESSION}.jsonl")),
            line.to_string() + "\n",
        )
        .unwrap();
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
            stdout: o.stdout,
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }

    fn archive(&self) -> Out {
        self.run(&["archive", "--all"])
    }

    /// Scratch is not in `--all`'s default include set, so a fixture that wants
    /// a scratch ledger must ask for it by name.
    fn archive_with_scratch(&self) -> Out {
        self.run(&["archive", "--all", "--include", "transcript,scratch"])
    }

    fn verify_json(&self) -> serde_json::Value {
        let o = self.run(&["verify", "--json"]);
        serde_json::from_slice(&o.stdout)
            .unwrap_or_else(|e| panic!("verify --json ({e}); stderr={}", o.stderr))
    }

    /// The paths `ensure_layout` asserts yomi owns, outermost first.
    ///
    /// **Four, not five.** `archive/_scratch/` was removed from the set: it is
    /// the root of one artifact family, not of the store, so a symlink there
    /// leaves transcript capture, the catalog and the quarantine tree entirely
    /// sound — and aborting the run would interrupt provably safe work. Its
    /// containment is per-key instead, at the five call sites that already
    /// classify it (`p16_a_foreign_scratch_root_is_contained_without_aborting`).
    fn owned(&self) -> [PathBuf; 4] {
        [
            self.yomi_home.clone(),
            self.yomi_home.join("archive"),
            self.yomi_home.join("quarantine"),
            self.yomi_home.join("state"),
        ]
    }

    fn snapshot(&self) -> Vec<(PathBuf, u64)> {
        let mut v: Vec<(PathBuf, u64)> = walk(&self.yomi_home)
            .into_iter()
            .map(|p| {
                let len = std::fs::symlink_metadata(&p).map(|m| m.len()).unwrap_or(0);
                (p, len)
            })
            .collect();
        v.sort();
        v
    }
}

struct Out {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
}
impl Out {
    fn summary(&self) -> String {
        format!(
            "exit={} stdout={:?} stderr={:?}",
            self.code,
            String::from_utf8_lossy(&self.stdout)
                .chars()
                .take(160)
                .collect::<String>(),
            self.stderr.trim()
        )
    }
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
            out.push(p.clone());
            if std::fs::symlink_metadata(&p)
                .map(|m| m.is_dir())
                .unwrap_or(false)
            {
                stack.push(p);
            }
        }
    }
    out.sort();
    out
}

fn q(v: &serde_json::Value) -> &serde_json::Value {
    &v["quarantine"]
}

fn stray_count(v: &serde_json::Value) -> usize {
    ["foreign_matter", "unverifiable"]
        .iter()
        .flat_map(|c| q(v)[*c].as_array().cloned().unwrap_or_default())
        .filter(|f| f["issue"] == "QuarantineStray")
        .count()
}

// ---------------------------------------------------------------------------
// A. The ownership assertion.
// ---------------------------------------------------------------------------

/// Each of the five levels, independently: a symlink there must refuse the run,
/// leave the link itself in place, and write nothing through it. Repairing it
/// automatically would orphan whatever an operator deliberately put on another
/// volume.
#[test]
fn p16_every_owned_level_refuses_a_symlink_and_writes_nothing_through_it() {
    // Bound taken from the set itself, so removing or adding an owned level
    // cannot leave this loop testing a path that is no longer asserted.
    for level in 0..Fx::new("probe").owned().len() {
        let fx = Fx::new(&format!("sym{level}"));
        fx.seed();
        let elsewhere = fx.base.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();

        let target = fx.owned()[level].clone();
        if level == 0 {
            std::fs::remove_dir_all(&target).unwrap();
        } else {
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        }
        std::os::unix::fs::symlink(&elsewhere, &target).unwrap();

        let out = fx.archive();
        assert_eq!(
            out.code,
            3,
            "level {level} ({}) was not refused: {}",
            target.display(),
            out.summary()
        );
        assert!(
            std::fs::symlink_metadata(&target)
                .unwrap()
                .file_type()
                .is_symlink(),
            "level {level}: the link was replaced rather than refused"
        );
        assert_eq!(
            std::fs::read_dir(&elsewhere).unwrap().count(),
            0,
            "level {level}: something was written through the link"
        );
    }
}

/// A regular file or a device where a directory is expected is equally not a
/// directory yomi owns, and equally must not be silently replaced.
#[test]
fn p16_a_non_directory_at_an_owned_level_refuses_and_survives() {
    for (label, make) in [("regular file", 0), ("fifo", 1)] {
        let fx = Fx::new(&format!("nondir{make}"));
        fx.seed();
        let at = fx.yomi_home.join("archive");
        if make == 0 {
            std::fs::write(&at, b"not a directory\n").unwrap();
        } else {
            let st = Command::new("mkfifo").arg(&at).status().expect("mkfifo");
            assert!(st.success(), "could not create a fifo fixture");
        }

        let out = fx.archive();
        assert_eq!(out.code, 3, "{label} was not refused: {}", out.summary());
        assert!(
            std::fs::symlink_metadata(&at).is_ok(),
            "{label} was replaced instead of refused"
        );
        assert!(
            !std::fs::symlink_metadata(&at).unwrap().is_dir(),
            "{label} was turned into a directory"
        );
    }
}

/// Read-side commands never call `ensure_layout`, so per-use classification is
/// the whole of their guarantee. On a foreign layout they must still create
/// nothing — including the layout they would otherwise have asserted.
#[test]
fn p16_read_side_commands_create_nothing_on_a_foreign_layout() {
    let fx = Fx::new("readside");
    fx.seed();
    assert_eq!(fx.archive().code, 0);

    // Make the scratch root foreign. `ensure_layout` no longer creates it, so
    // the fixture must ensure the parent exists and plant the link itself —
    // depending on the layout to have made it is what left this test's subject
    // unexercised when `_scratch` left the fixed set.
    let scratch = fx.yomi_home.join("archive/_scratch");
    let elsewhere = fx.base.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::create_dir_all(scratch.parent().unwrap()).unwrap();
    let _ = std::fs::remove_dir_all(&scratch);
    std::os::unix::fs::symlink(&elsewhere, &scratch).unwrap();
    assert!(
        std::fs::symlink_metadata(&scratch)
            .unwrap()
            .file_type()
            .is_symlink(),
        "fixture failed to plant the foreign scratch root"
    );

    let before = fx.snapshot();
    for cmd in [
        vec!["verify"],
        vec!["verify", "--json"],
        vec!["status"],
        vec!["status", "--json"],
        vec!["read", SESSION, "--raw"],
        vec!["search", "aws"],
    ] {
        fx.run(&cmd);
    }
    assert_eq!(
        fx.snapshot(),
        before,
        "a read-side command changed the store while the layout was foreign"
    );
    assert_eq!(
        std::fs::read_dir(&elsewhere).unwrap().count(),
        0,
        "a read-side command wrote through the foreign link"
    );
}

// ---------------------------------------------------------------------------
// B. The two predicates.
// ---------------------------------------------------------------------------

/// The lock gate exists so a read-side command does not *create* a store on a
/// fresh home. Nothing may appear, and the run must not report exclusion it
/// never attempted as though it had failed to get it.
#[test]
fn p16_a_fresh_home_gains_no_store_from_read_commands() {
    let fx = Fx::new("fresh");
    fx.seed();
    // Never archived: the home directory exists but holds no store.
    let before = fx.snapshot();
    assert!(before.is_empty(), "fixture is not fresh: {before:?}");

    for cmd in [
        vec!["verify"],
        vec!["verify", "--json"],
        vec!["status"],
        vec!["read", SESSION, "--raw"],
        vec!["search", "aws"],
    ] {
        let o = fx.run(&cmd);
        assert_ne!(
            o.code,
            1,
            "`{}` errored on a fresh home: {}",
            cmd.join(" "),
            o.summary()
        );
    }
    assert_eq!(
        fx.snapshot(),
        before,
        "a read-side command created something on a fresh home"
    );

    let v = fx.verify_json();
    assert_eq!(
        v["exclusion"], "not_attempted",
        "a fresh home reported exclusion as attempted-and-failed: {v}"
    );
}

/// `store_exists()` is a disjunction, and each disjunct alone must be enough:
/// a store that lost its marker and its catalog while `archive/` survives is
/// entirely present, and gating on bookkeeping is what left `exclusive` false
/// there forever.
#[test]
fn p16_each_store_exists_disjunct_alone_takes_the_lock() {
    for (label, keep) in [("marker", 0), ("archive", 1), ("state", 2)] {
        let fx = Fx::new(&format!("disj{keep}"));
        fx.seed();
        assert_eq!(fx.archive().code, 0);

        let marker = fx.yomi_home.join(".yomi-store");
        let archive = fx.yomi_home.join("archive");
        let state = fx.yomi_home.join("state");
        match keep {
            0 => {
                std::fs::remove_dir_all(&archive).unwrap();
                std::fs::remove_dir_all(&state).unwrap();
            }
            1 => {
                std::fs::remove_file(&marker).unwrap();
                std::fs::remove_dir_all(&state).unwrap();
            }
            _ => {
                std::fs::remove_file(&marker).unwrap();
                std::fs::remove_dir_all(&archive).unwrap();
            }
        }

        let v = fx.verify_json();
        assert_eq!(
            v["exclusion"], "held",
            "with only `{label}` present the lock was not attempted, so the pass \
             can confirm but never accuse: {v}"
        );
    }

    // And with none of the three, the lock is correctly not attempted.
    let fx = Fx::new("disj-none");
    fx.seed();
    assert_eq!(fx.archive().code, 0);
    for p in [".yomi-store", "archive", "state", "quarantine"] {
        let t = fx.yomi_home.join(p);
        let _ = std::fs::remove_file(&t);
        let _ = std::fs::remove_dir_all(&t);
    }
    assert_eq!(
        fx.verify_json()["exclusion"],
        "not_attempted",
        "an empty home attempted the lock"
    );
}

/// The three exclusion states must say three different things. The old wording
/// asserted a concurrent archive might be mid-write, which is simply false when
/// the lock was never attempted.
#[test]
fn p16_the_three_exclusion_states_are_distinguishable() {
    let fx = Fx::new("excl");
    fx.seed();
    assert_eq!(fx.archive().code, 0);

    let held = fx.run(&["verify"]);
    assert_eq!(fx.verify_json()["exclusion"], "held");

    // Fresh home: not attempted.
    let fresh = Fx::new("excl-fresh");
    fresh.seed();
    let na = fresh.run(&["verify"]);
    assert_eq!(fresh.verify_json()["exclusion"], "not_attempted");

    // The two must not print the same advisory line.
    assert_ne!(
        held.stdout, na.stdout,
        "a store with the lock held and a fresh home print identically"
    );
    let na_text = String::from_utf8_lossy(&na.stdout).to_lowercase();
    assert!(
        !na_text.contains("mid-write") && !na_text.contains("concurrent archive"),
        "a home where the lock was never attempted claims a concurrent archive \
         may be writing: {na_text}"
    );
}

// ---------------------------------------------------------------------------
// C. Fresh, Present and Lost.
// ---------------------------------------------------------------------------

/// A store that lost `catalog.db` beside a populated `archive/` is not a fresh
/// home. Reading it as one made law Q report every session original as a stray,
/// and `exclusive: false` then demoted those false accusations out of sight.
#[test]
fn p16_a_lost_catalog_withholds_the_sweep_instead_of_accusing() {
    let fx = Fx::new("lost");
    fx.seed();
    assert_eq!(fx.archive().code, 0);

    let present = fx.verify_json();
    assert_eq!(q(&present)["claims"].as_u64(), Some(1), "{present}");
    assert_eq!(stray_count(&present), 0, "a healthy store reported strays");
    assert_eq!(present["exclusion"], "held");

    std::fs::remove_file(fx.yomi_home.join("state/catalog.db")).unwrap();
    let lost = fx.verify_json();

    assert_eq!(
        q(&lost)["sweep_skipped"],
        "catalog_missing",
        "a lost catalog did not withhold the sweep: {lost}"
    );
    assert_eq!(
        stray_count(&lost),
        0,
        "a lost catalog produced false strays for artifacts whose ledger is \
         simply gone: {lost}"
    );
    assert_eq!(
        lost["exclusion"], "held",
        "the store lost its bookkeeping and the lock gate stopped attempting: \
         {lost}"
    );
}

/// Scratch keeps its ledger in the manifest, not the catalog, so a lost catalog
/// must not take its claims with it — the output has to show that what was lost
/// is the session side only.
#[test]
fn p16_scratch_claims_survive_a_lost_catalog() {
    let fx = Fx::new("lost-scratch");
    fx.seed();
    assert_eq!(fx.archive_with_scratch().code, 0);

    let before = fx.verify_json();
    let scratch_keys = before["scratch"]["keys"].as_u64().unwrap();
    assert!(
        scratch_keys >= 1,
        "fixture produced no scratch store; the claim it is about does not exist: \
         {before}"
    );
    let claims_before = q(&before)["claims"].as_u64().unwrap();
    assert!(claims_before >= 2, "expected both sides to claim: {before}");

    std::fs::remove_dir_all(fx.yomi_home.join("state")).unwrap();
    let after = fx.verify_json();

    // The scratch side keeps its ledger — it lives in the manifest.
    assert_eq!(
        after["scratch"]["keys"].as_u64(),
        Some(scratch_keys),
        "the scratch store vanished with the catalog, which does not hold it: \
         {after}"
    );
    // And it keeps claiming its original, so what was lost is the session side
    // alone. A reader must be able to see that from the output.
    assert!(
        q(&after)["claims"].as_u64().unwrap() >= 1,
        "every claim vanished with the catalog, including the scratch ledger's \
         own, so the output cannot show that only the session side was lost: \
         {after}"
    );
    assert!(
        q(&after)["claims"].as_u64().unwrap() < claims_before,
        "the claim count did not drop at all, so the session side's loss is \
         invisible: {after}"
    );
}

/// **The cost of withholding.** Q2 is the only check that finds a file under
/// `quarantine/` nobody claims, so declining it on a lost catalog also hides a
/// *genuine* stray. Safe — an accusation drawn from a missing ledger is worse —
/// but it is a real loss of coverage and the operator has to be told the sweep
/// did not run, not merely shown a clean report.
#[test]
fn p16_withholding_the_sweep_also_hides_a_genuine_stray() {
    let fx = Fx::new("lost-cost");
    fx.seed();
    assert_eq!(fx.archive().code, 0);

    // A file no artifact will ever claim, in the current layout.
    let stray = fx.yomi_home.join("quarantine/-p/definitely-a-stray.txt");
    std::fs::create_dir_all(stray.parent().unwrap()).unwrap();
    std::fs::write(&stray, b"unclaimed\n").unwrap();

    let seen = fx.verify_json();
    assert_eq!(
        stray_count(&seen),
        1,
        "the genuine stray was not reported while the catalog was present: {seen}"
    );

    std::fs::remove_file(fx.yomi_home.join("state/catalog.db")).unwrap();
    let hidden = fx.verify_json();
    assert_eq!(
        stray_count(&hidden),
        0,
        "fixture assumption changed: the sweep is no longer withheld"
    );
    // The loss must be *stated*, not silent — a clean-looking report with no
    // note is the failure mode this whole distinction exists to avoid.
    assert_eq!(
        q(&hidden)["sweep_skipped"],
        "catalog_missing",
        "the sweep was skipped without saying so: {hidden}"
    );
    let text = String::from_utf8_lossy(&fx.run(&["verify"]).stdout).to_lowercase();
    assert!(
        text.contains("sweep") || text.contains("catalog"),
        "the human-facing report does not mention that the sweep was withheld, \
         so a hidden stray looks like no stray: {text}"
    );
    assert!(stray.exists(), "verify removed the stray");
}

/// Once any mutating command has run, the home can never read as `Fresh` again —
/// `archive/` alone satisfies `store_exists()`. Pinned, with the question that
/// matters: is the way out stated anywhere an operator would look?
#[test]
fn p16_a_store_never_returns_to_fresh_once_mutated() {
    let fx = Fx::new("no-return");
    fx.seed();
    assert_eq!(fx.archive().code, 0);

    // Remove every scrap of bookkeeping; the directories remain.
    let _ = std::fs::remove_file(fx.yomi_home.join(".yomi-store"));
    let _ = std::fs::remove_file(fx.yomi_home.join("state/catalog.db"));
    let v = fx.verify_json();
    assert_eq!(
        v["exclusion"], "held",
        "the home reverted to fresh after its bookkeeping was removed: {v}"
    );

    // Only removing the directories themselves gets back to fresh.
    for p in ["archive", "state", "quarantine"] {
        let _ = std::fs::remove_dir_all(fx.yomi_home.join(p));
    }
    assert_eq!(
        fx.verify_json()["exclusion"],
        "not_attempted",
        "removing the store directories did not restore the fresh reading"
    );
}

// ---------------------------------------------------------------------------
// D. The behaviour change — 思兼 is ruling on this.
// ---------------------------------------------------------------------------

/// A foreign `archive/_scratch` is **contained, not escalated**.
///
/// This test previously asserted the opposite — whole-run refusal at exit 3 —
/// and flagged that the ruling could change it. It did: `_scratch` is the root
/// of one artifact family, so a symlink there leaves transcript capture, the
/// catalog and the quarantine tree untouched, and aborting would interrupt work
/// that is provably safe. The four levels in `owned()` still abort, because a
/// foreign one of those makes every later operation untrustworthy.
///
/// What must hold: the run is not aborted, transcripts are still captured,
/// nothing is written through the link, the link is not replaced, and the
/// scratch pass refuses that key on its own.
#[test]
fn p16_a_foreign_scratch_root_is_contained_without_aborting() {
    let fx = Fx::new("contained");
    fx.seed();

    // Foreign from the very first run, so nothing depends on a prior layout.
    let scratch = fx.yomi_home.join("archive/_scratch");
    let elsewhere = fx.base.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::create_dir_all(scratch.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &scratch).unwrap();

    for cmd in [
        vec!["archive", "--all", "--include", "transcript,scratch"],
        vec!["index"],
        vec!["rescan", "--commit"],
        vec!["gc", "--targets", "transcripts", "--commit"],
    ] {
        let o = fx.run(&cmd);
        assert_ne!(
            o.code,
            3,
            "`{}` aborted the whole run for one foreign artifact-family root: {}",
            cmd.join(" "),
            o.summary()
        );
    }

    // The safe work actually happened: the stored artifact is under `archive/`.
    // (Counting names across the whole store would also catch the quarantine
    // original of the same transcript, which this fixture's secret produces.)
    let stored: Vec<PathBuf> = walk(&fx.yomi_home.join("archive"))
        .into_iter()
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("zst"))
        .collect();
    assert_eq!(
        stored.len(),
        1,
        "the transcript was not captured despite the foreign root being \
         irrelevant to it: {stored:?}"
    );
    assert!(
        fx.yomi_home.join("state/catalog.db").exists(),
        "the catalog was not written"
    );

    // And the containment held.
    assert_eq!(
        std::fs::read_dir(&elsewhere).unwrap().count(),
        0,
        "something was written through the foreign link"
    );
    assert!(
        std::fs::symlink_metadata(&scratch)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the foreign link was replaced rather than refused"
    );

    // The scratch pass refuses it per key — the containment is stated, not silent.
    let v = fx.verify_json();
    let refused: Vec<String> = v["scratch"]["refused"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["issue"].as_str().unwrap().to_string())
        .collect();
    assert!(
        refused.contains(&"ForeignStoreDir".to_string()),
        "the scratch pass did not refuse the foreign root: {v}"
    );
}

/// **The cost of leaving the fixed set.** The four owned levels are re-asserted
/// on every mutating run; `archive/_scratch` is not, so its mode is only claimed
/// by the run that first archives scratch. Until then a directory another
/// process created loosely keeps whatever mode it was given — `create_dir_all`
/// does not tighten an existing directory.
///
/// Measured: the window is the whole lifetime of a store that has never archived
/// scratch, and the first scratch archive closes it.
#[test]
fn p16_the_scratch_root_mode_is_only_claimed_by_the_first_scratch_archive() {
    let fx = Fx::new("modewindow");
    fx.seed();

    // Another process gets there first, with a permissive mode.
    let scratch = fx.yomi_home.join("archive/_scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o777)).unwrap();
    let mode = || std::fs::metadata(&scratch).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(), 0o777, "fixture did not plant a loose mode");

    // A mutating run that does not touch scratch leaves it alone.
    assert_eq!(fx.archive().code, 0);
    let after_archive = mode();

    // So do the read-side commands.
    for cmd in [vec!["verify"], vec!["status"], vec!["verify", "--json"]] {
        fx.run(&cmd);
    }
    let after_reads = mode();

    // The first run that archives scratch claims it.
    assert_eq!(fx.archive_with_scratch().code, 0);
    assert_eq!(
        mode(),
        0o700,
        "the first scratch archive did not claim the mode; the window never \
         closes (was {after_archive:o} after archive, {after_reads:o} after reads)"
    );
}
