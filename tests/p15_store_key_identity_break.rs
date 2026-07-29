//! P15 break tests: adversarial assault on U6 — recorded store-key identity (§3).
//!
//! `store_key`'s plain form is **not injective**: `store_key("a", "-b") ==
//! store_key("a-", "b") == "a---b"`, in pure ASCII, from directory names any
//! process with the same uid can create under `/tmp/claude-<uid>/`. U6 does not
//! make the key injective; it records the identity and refuses whoever does not
//! match. So the attacks are: make two trees collide and see whether one
//! overwrites the other, and then try to get past the check that stops it.
//!
//! Written to BREAK, not to confirm. Fixtures live under `CARGO_TARGET_TMPDIR`;
//! key-length fixtures are built from the *component* names only, so nothing here
//! depends on how long that directory happens to be.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const BIN: &str = env!("CARGO_BIN_EXE_yomi");

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
        let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("p15-uid-{}", unique()));
        std::fs::write(&p, b"").unwrap();
        let uid = std::fs::metadata(&p).unwrap().uid();
        let _ = std::fs::remove_file(&p);
        uid == 0
    })
}

struct Fx {
    home: PathBuf,
    yomi_home: PathBuf,
    tmp_root: PathBuf,
    cache_home: PathBuf,
    proc_root: PathBuf,
}

impl Fx {
    fn new(tag: &str) -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "p15-{tag}-{}-{}",
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
        };
        std::fs::create_dir_all(fx.home.join(".claude/projects")).unwrap();
        for d in [&fx.tmp_root, &fx.cache_home, &fx.proc_root, &fx.yomi_home] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::set_permissions(&fx.yomi_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        fx
    }

    /// A scratch tree at `<tmp_root>/<slug>/<uuid>/scratchpad/n.md`.
    fn tree(&self, slug: &str, uuid: &str, payload: &str) {
        let d = self.tmp_root.join(slug).join(uuid).join("scratchpad");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("n.md"), format!("{payload}\n")).unwrap();
    }

    fn store_root(&self) -> PathBuf {
        self.yomi_home.join("archive/_scratch")
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
    fn manifest_path(&self, key: &str) -> PathBuf {
        self.store_root().join(key).join("manifest.json")
    }
    fn manifest(&self, key: &str) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(self.manifest_path(key)).unwrap()).unwrap()
    }
    fn set_manifest_field(&self, key: &str, field: &str, value: &str) {
        let mut m = self.manifest(key);
        m[field] = serde_json::Value::String(value.to_string());
        std::fs::write(
            self.manifest_path(key),
            serde_json::to_string_pretty(&m).unwrap(),
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
        self.run(&["archive", "--all", "--include", "scratch"])
    }

    /// The stored payload of `<key>/scratchpad/n.md`, or `None`.
    fn payload(&self, key: &str) -> Option<String> {
        let o = self.run(&["read", "--scratch", key, "--file", "scratchpad/n.md"]);
        (o.code == 0).then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
    }

    fn age_trees(&self) {
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(200 * 86_400);
        for p in walk_files(&self.tmp_root) {
            let _ = filetime::set_file_mtime(&p, filetime::FileTime::from_system_time(when));
        }
    }

    fn gc_reasons(&self) -> Vec<String> {
        let o = self.run(&["gc", "--targets", "scratch", "--json"]);
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).expect("gc json");
        v["items"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|i| i["reason"].as_str().unwrap_or("").to_string())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn verify_scratch(&self) -> serde_json::Value {
        let o = self.run(&["verify", "--json"]);
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).expect("verify json");
        v["scratch"].clone()
    }
}

struct Out {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
}
impl Out {
    fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.stdout).ok()
    }
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

fn zst_count(root: &Path) -> usize {
    walk_files(root)
        .iter()
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("zst"))
        .count()
}

/// The two directory pairs that collide on `a---b`, in pure ASCII.
const COLLIDE: [(&str, &str, &str); 2] = [("a", "-b", "OWNER-A"), ("a-", "b", "OTHER-B")];
const COLLIDING_KEY: &str = "a---b";

fn colliding_fx(tag: &str) -> Fx {
    let fx = Fx::new(tag);
    for (slug, uuid, payload) in COLLIDE {
        fx.tree(slug, uuid, payload);
    }
    fx
}

// ---------------------------------------------------------------------------
// A. The collision itself.
// ---------------------------------------------------------------------------

/// The defect U6 exists for: two session directories that differ only in where
/// the boundary `-` sits produce one store key. Whoever arrives second must not
/// write through the first's archive.
#[test]
fn p15_ascii_colliding_trees_never_overwrite_each_other() {
    let fx = colliding_fx("collide");
    let first = fx.archive();
    assert_eq!(first.code, 0, "{}", first.summary());

    assert_eq!(
        fx.keys(),
        vec![COLLIDING_KEY.to_string()],
        "the two trees did not collide on one key; the fixture proves nothing"
    );
    let winner = fx.payload(COLLIDING_KEY).expect("no payload stored");
    assert!(
        winner == "OWNER-A" || winner == "OTHER-B",
        "unexpected payload: {winner}"
    );
    assert_eq!(
        zst_count(&fx.store_root()),
        1,
        "one key holds two trees' artifacts"
    );

    // Idempotent: re-running must not let the loser through on a later pass.
    for round in 0..3 {
        fx.archive();
        assert_eq!(
            fx.payload(COLLIDING_KEY).as_deref(),
            Some(winner.as_str()),
            "round {round}: the colliding tree overwrote the archived copy"
        );
    }
    // And the refusal is visible, not silent.
    assert!(
        fx.archive().stderr.contains("map to this store key"),
        "the refusal was not reported to the operator"
    );
}

/// The GC gate's half: it has the live tree, so it can tell the two apart and
/// must refuse to reclaim the one whose ledger belongs to the other.
#[test]
fn p15_the_gc_gate_refuses_the_colliding_tree() {
    let fx = colliding_fx("gc");
    fx.archive();
    fx.age_trees();

    let reasons = fx.gc_reasons();
    assert!(
        reasons.iter().any(|r| r == "StoreKeyCollision"),
        "the GC gate did not report a store key collision: {reasons:?}"
    );

    // Only the tree whose ledger belongs to the *other* one must be spared. The
    // owner's own archive genuinely covers its tree, so reclaiming that one is
    // correct — refusing both would punish the tree that did nothing wrong.
    let owner = fx.payload(COLLIDING_KEY).expect("nothing stored");
    let (loser_slug, loser_uuid) = if owner == "OWNER-A" {
        ("a-", "b")
    } else {
        ("a", "-b")
    };

    let out = fx.run(&["gc", "--targets", "scratch", "--commit"]);
    assert!([0, 2].contains(&out.code), "{}", out.summary());
    assert!(
        fx.tmp_root.join(loser_slug).join(loser_uuid).exists(),
        "the colliding tree was reclaimed on coverage computed from the other \
         tree's ledger — the shape of evidence that authorizes destroying live \
         data"
    );
}

/// `read --scratch <uuid>` must name the collision rather than serve the other
/// session's bytes under this one's name.
#[test]
fn p15_read_names_the_collision_instead_of_serving_the_wrong_tree() {
    let fx = colliding_fx("read");
    fx.archive();

    // The loser's uuid: its ledger records the winner's identity.
    let o = fx.run(&["read", "--scratch", "b", "--json"]);
    let j = o.json().expect("json");
    assert_eq!(
        j["error"],
        "StoreKeyCollision",
        "resolving the colliding session gave {} instead of naming the \
         collision: {}",
        j["error"],
        o.summary()
    );
    assert_ne!(o.code, 0, "{}", o.summary());
}

/// `verify` has no live tree — that half is the GC gate's. What it can assert
/// from the store alone is that a ledger's recorded identity produces the key it
/// sits under; a manifest failing that describes some other tree.
#[test]
fn p15_verify_refuses_a_ledger_whose_identity_does_not_produce_its_key() {
    let fx = Fx::new("verify");
    fx.tree("a", "-b", "P");
    fx.archive();
    assert!(
        fx.verify_scratch()["refused"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // 7a = "z": store_key("z","-b") is "z---b", not the key this sits under.
    fx.set_manifest_field(COLLIDING_KEY, "slug_hex", "7a");
    let s = fx.verify_scratch();
    let refused: Vec<String> = s["refused"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["issue"].as_str().unwrap().to_string())
        .collect();
    assert!(
        refused.contains(&"StoreKeyCollision".to_string()),
        "a ledger whose identity does not produce its own key was accepted: {s}"
    );
}

/// **An identity the reader cannot decode is not a licence to overwrite.**
///
/// `ScratchManifest::identity` folds an undecodable `slug_hex`/`uuid_hex` into
/// `None`, and `identity_verdict` reads `None` as `Proceed` — the same value it
/// gives a pre-U6 manifest that records nothing. But those are different facts:
/// one ledger makes no claim, the other makes a claim this run cannot read. A
/// corrupted or hand-edited byte therefore reopens exactly the overwrite U6
/// exists to prevent.
///
/// This is the principle already accepted twice in this series — an entry the
/// reader cannot parse is not a licence to destroy its artifact (U2 F3), and a
/// prior capture that cannot be salvaged is not a licence to delete its `.zst`.
#[test]
fn p15_an_undecodable_identity_does_not_authorize_an_overwrite() {
    let fx = colliding_fx("undecodable");
    fx.archive();
    let owner = fx.payload(COLLIDING_KEY).expect("nothing stored");

    // The owning tree goes away, so only the colliding one is enumerated and
    // cannot be corrected by the owner re-stamping its identity first.
    let (owner_slug, owner_uuid) = if owner == "OWNER-A" {
        ("a", "-b")
    } else {
        ("a-", "b")
    };
    std::fs::remove_dir_all(fx.tmp_root.join(owner_slug).join(owner_uuid)).unwrap();

    // Control: with the identity intact, the survivor is refused.
    fx.archive();
    assert_eq!(
        fx.payload(COLLIDING_KEY).as_deref(),
        Some(owner.as_str()),
        "control failed: the colliding tree overwrote even with a valid identity"
    );

    // Now make the recorded identity undecodable.
    fx.set_manifest_field(COLLIDING_KEY, "slug_hex", "zz");
    fx.archive();

    assert_eq!(
        fx.payload(COLLIDING_KEY).as_deref(),
        Some(owner.as_str()),
        "an undecodable `slug_hex` turned the collision check off and the other \
         tree overwrote the only archived copy. `identity()` cannot distinguish \
         'records nothing' from 'records something unreadable', and both become \
         Proceed."
    );
}

/// A manifest carrying only one of the two fields is a damaged record, not a
/// different session. It must not be read as a collision against a tree that is
/// in fact its owner.
#[test]
fn p15_a_half_recorded_identity_does_not_manufacture_a_collision() {
    let fx = Fx::new("half");
    fx.tree("a", "-b", "P");
    fx.archive();
    assert_eq!(fx.payload(COLLIDING_KEY).as_deref(), Some("P"));

    fx.set_manifest_field(COLLIDING_KEY, "uuid_hex", "");
    let out = fx.archive();
    assert!(
        !out.stderr.contains("map to this store key"),
        "a half-written identity was reported as a collision against the tree \
         that owns it: {}",
        out.summary()
    );
    assert_eq!(
        fx.payload(COLLIDING_KEY).as_deref(),
        Some("P"),
        "the owning tree lost access to its own store"
    );
}

/// Every shape of damaged identity must refuse, not just the one that was
/// reported. `Corrupt` is reached two structurally different ways — hex that
/// does not decode, and only one of the two halves present — and the second is
/// not a variant of the first.
#[test]
fn p15_every_corrupt_identity_shape_refuses_the_write() {
    let corruptions: [(&str, &str, &str); 5] = [
        ("non-hex slug", "slug_hex", "zz"),
        ("odd-length slug hex", "slug_hex", "abc"),
        ("non-hex uuid", "uuid_hex", "qq"),
        ("slug half missing", "slug_hex", ""),
        ("uuid half missing", "uuid_hex", ""),
    ];
    for (label, field, value) in corruptions {
        let fx = colliding_fx(&format!("corrupt-{}", field.len() + value.len()));
        fx.archive();
        let owner = fx.payload(COLLIDING_KEY).expect("nothing stored");
        let (owner_slug, owner_uuid) = if owner == "OWNER-A" {
            ("a", "-b")
        } else {
            ("a-", "b")
        };
        // Remove the owner so it cannot re-stamp the field before the other tree
        // is reached, which would mask a bypass.
        std::fs::remove_dir_all(fx.tmp_root.join(owner_slug).join(owner_uuid)).unwrap();

        let before = std::fs::read_to_string(fx.manifest_path(COLLIDING_KEY)).unwrap();
        fx.set_manifest_field(COLLIDING_KEY, field, value);
        let corrupted = std::fs::read_to_string(fx.manifest_path(COLLIDING_KEY)).unwrap();
        fx.archive();

        assert_eq!(
            fx.payload(COLLIDING_KEY).as_deref(),
            Some(owner.as_str()),
            "{label}: the surviving tree wrote through a ledger whose identity \
             cannot be read"
        );
        // The closure proof: a run that proceeded would have restamped this
        // field with its own identity, so the value still being the corrupt one
        // is evidence that nothing was written at all.
        assert_eq!(
            std::fs::read_to_string(fx.manifest_path(COLLIDING_KEY)).unwrap(),
            corrupted,
            "{label}: the ledger changed, so the run did not stop at the check"
        );
        assert_ne!(
            before, corrupted,
            "{label}: the fixture did not corrupt anything"
        );
    }
}

/// The two refusals name two different operator actions — rename one of two
/// directories, or repair a ledger — so they must not be reported under one
/// name. A collision reported as damage sends the operator to the wrong file.
#[test]
fn p15_collision_and_damage_are_reported_as_different_reasons() {
    // A genuine collision: both ledgers readable, one belongs to the other tree.
    let a = colliding_fx("reason-collision");
    a.archive();
    a.age_trees();
    let collision = a.gc_reasons();
    assert!(
        collision.iter().any(|r| r == "StoreKeyCollision"),
        "a genuine collision was not named as one: {collision:?}"
    );
    assert!(
        !collision.iter().any(|r| r == "UndecodableIdentity"),
        "a readable-but-foreign ledger was reported as damage: {collision:?}"
    );

    // Damage: the ledger cannot be read at all.
    let b = Fx::new("reason-damage");
    b.tree("a", "-b", "P");
    b.archive();
    b.set_manifest_field(COLLIDING_KEY, "slug_hex", "zz");
    b.age_trees();
    let damage = b.gc_reasons();
    assert!(
        damage.iter().any(|r| r == "UndecodableIdentity"),
        "an unreadable ledger was not named as damage: {damage:?}"
    );
    assert!(
        !damage.iter().any(|r| r == "StoreKeyCollision"),
        "damage was reported as a collision, sending the operator to rename a \
         directory when the fix is to repair a manifest: {damage:?}"
    );
}

/// `verify` names the third state rather than acting on it, and it is
/// `unverifiable` — the store is not proven broken, its ledger is unreadable.
#[test]
fn p15_verify_names_an_unreadable_identity_without_failing_the_run() {
    let fx = Fx::new("verify-damage");
    fx.tree("a", "-b", "P");
    fx.archive();
    fx.set_manifest_field(COLLIDING_KEY, "slug_hex", "zz");

    let s = fx.verify_scratch();
    let named: Vec<String> = ["violations", "unverifiable", "refused", "foreign_matter"]
        .iter()
        .flat_map(|c| {
            s[*c]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f["issue"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        named.contains(&"UndecodableIdentity".to_string()),
        "verify did not name the unreadable identity at all: {s}"
    );
    let unverifiable: Vec<String> = s["unverifiable"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["issue"].as_str().unwrap().to_string())
        .collect();
    assert!(
        unverifiable.contains(&"UndecodableIdentity".to_string()),
        "an unreadable identity was classed as something other than \
         unverifiable: {s}"
    );
}

/// **A damaged ledger is not a licence to serve another session's bytes.**
///
/// This test previously pinned the opposite as measured-but-not-judged: the
/// resolver treated `Corrupt` as pre-U6 ("the name is all there is") on the
/// ground that reading destroys nothing. Measuring the cost is what overturned
/// it — the failure here was never destruction, it was **answering the wrong
/// question**. One corrupted byte turned a correct refusal into exit 0 serving
/// the other session's archive under this session's name.
///
/// So the fourth layer now refuses like the other three, and the assertion is
/// inverted: same question, still refused, and refused *as damage* rather than
/// as a collision.
#[test]
fn p15_a_corrupt_ledger_is_refused_by_read_like_every_other_layer() {
    let fx = colliding_fx("read-corrupt");
    fx.archive();
    let owner = fx.payload(COLLIDING_KEY).expect("nothing stored");
    // The session whose uuid is *not* the one the ledger records.
    let other_uuid = if owner == "OWNER-A" { "b" } else { "-b" };

    // Intact ledger: the collision is named rather than answered.
    let intact = fx.run(&["read", "--scratch", other_uuid, "--json"]);
    assert_eq!(
        intact.json().map(|j| j["error"].clone()),
        Some(serde_json::json!("StoreKeyCollision")),
        "with an intact ledger the collision should be named: {}",
        intact.summary()
    );

    fx.set_manifest_field(COLLIDING_KEY, "slug_hex", "zz");
    let corrupt = fx.run(&["read", "--scratch", other_uuid, "--json"]);
    assert_eq!(
        corrupt.json().map(|j| j["error"].clone()),
        Some(serde_json::json!("UndecodableIdentity")),
        "a damaged ledger did not refuse the other session's question: {}",
        corrupt.summary()
    );
    assert_ne!(corrupt.code, 0, "{}", corrupt.summary());

    // And no bytes, by any route.
    let served = fx.run(&["read", "--scratch", other_uuid, "--file", "scratchpad/n.md"]);
    assert!(
        served.stdout.is_empty() && served.code != 0,
        "a damaged ledger still served bytes for a session it cannot vouch for: \
         {}",
        served.summary()
    );
}

/// The owner's *own* uuid gets the same refusal. A ledger that cannot say whose
/// store this is cannot say it is this session's either — answering one caller
/// and not the other would be guessing.
#[test]
fn p15_a_corrupt_ledger_refuses_even_its_own_session() {
    let fx = colliding_fx("read-corrupt-owner");
    fx.archive();
    let owner = fx.payload(COLLIDING_KEY).expect("nothing stored");
    let owner_uuid = if owner == "OWNER-A" { "-b" } else { "b" };

    assert_eq!(
        fx.run(&["read", "--scratch", owner_uuid, "--json"]).code,
        0,
        "the owner could not read its own store before the damage"
    );

    fx.set_manifest_field(COLLIDING_KEY, "slug_hex", "zz");
    let o = fx.run(&["read", "--scratch", owner_uuid, "--json"]);
    assert_eq!(
        o.json().map(|j| j["error"].clone()),
        Some(serde_json::json!("UndecodableIdentity")),
        "a damaged ledger answered for the session it happens to belong to, \
         which it has no way of knowing: {}",
        o.summary()
    );
}

/// All four layers, one fixture, one damaged ledger: archive refuses without
/// writing, the GC gate refuses with its own reason, `verify` names it, and the
/// resolver refuses. The point of the fix was that they agree.
#[test]
fn p15_all_four_layers_treat_a_damaged_identity_alike() {
    let fx = Fx::new("four-layers");
    fx.tree("a", "-b", "P");
    fx.archive();
    fx.set_manifest_field(COLLIDING_KEY, "slug_hex", "zz");
    let damaged = std::fs::read_to_string(fx.manifest_path(COLLIDING_KEY)).unwrap();

    // 1. archive — refuses, and the unchanged ledger proves it never wrote.
    let a = fx.archive();
    assert_eq!(
        std::fs::read_to_string(fx.manifest_path(COLLIDING_KEY)).unwrap(),
        damaged,
        "archive restamped a ledger it cannot read: {}",
        a.summary()
    );

    // 2. GC gate — its own reason, not the collision one.
    fx.age_trees();
    let reasons = fx.gc_reasons();
    assert!(
        reasons.iter().any(|r| r == "UndecodableIdentity"),
        "the gate did not refuse a damaged identity: {reasons:?}"
    );

    // 3. verify — names it, does not act on it.
    let named: Vec<String> = fx.verify_scratch()["unverifiable"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["issue"].as_str().unwrap().to_string())
        .collect();
    assert!(
        named.contains(&"UndecodableIdentity".to_string()),
        "verify did not name the damaged identity: {named:?}"
    );

    // 4. resolver — refuses, with the same vocabulary.
    let r = fx.run(&["read", "--scratch", "-b", "--json"]);
    assert_eq!(
        r.json().map(|j| j["error"].clone()),
        Some(serde_json::json!("UndecodableIdentity")),
        "the resolver is still out of step with the other three: {}",
        r.summary()
    );

    // And the tree survives all four.
    assert!(fx.tmp_root.join("a").join("-b").exists());
}

/// The two refusals must stay apart in the resolver too — they were already
/// checked at the gate. A collision reported as damage sends the operator to
/// repair a manifest that is fine; damage reported as a collision sends them to
/// rename a directory that is not the problem.
#[test]
fn p15_read_keeps_collision_and_damage_apart() {
    // Collision: ledger readable, naming the other session.
    let a = colliding_fx("read-reason-collision");
    a.archive();
    let owner = a.payload(COLLIDING_KEY).expect("nothing stored");
    let other = if owner == "OWNER-A" { "b" } else { "-b" };
    let collision = a.run(&["read", "--scratch", other, "--json"]);
    let cj = collision.json().expect("json");
    assert_eq!(cj["error"], "StoreKeyCollision", "{}", collision.summary());
    assert_ne!(
        cj["error"], "UndecodableIdentity",
        "a readable-but-foreign ledger was reported as damage"
    );

    // Damage: ledger illegible.
    let b = Fx::new("read-reason-damage");
    b.tree("a", "-b", "P");
    b.archive();
    b.set_manifest_field(COLLIDING_KEY, "slug_hex", "zz");
    let damage = b.run(&["read", "--scratch", "-b", "--json"]);
    let dj = damage.json().expect("json");
    assert_eq!(dj["error"], "UndecodableIdentity", "{}", damage.summary());
    assert_ne!(
        dj["error"], "StoreKeyCollision",
        "damage was reported as a collision, sending the operator to rename a \
         directory when the manifest is what needs repair"
    );
    // The two reasons must also say different things.
    assert_ne!(
        cj["reason"], dj["reason"],
        "the two refusals share one prose reason"
    );
}

/// An illegible key is only surfaced when **nothing else matched**
/// (`matched.is_empty()` guards the `illegible` branch), so a legible key that
/// answers to the same selector hides it. That turns the same downgrade the
/// resolver fix just closed, one step along: with both ledgers readable the
/// resolver refuses to guess between two stores; damage one byte and it picks
/// the survivor silently.
///
/// Narrow: it needs two stores answering one session uuid — the same uuid under
/// two project slugs — one of them in digest form, which needs both components
/// long. Reported for the shape rather than the likelihood; the fix is to
/// consult `illegible` whenever it is non-empty, not only when `matched` is.
#[test]
fn p15_an_illegible_key_is_not_hidden_by_a_legible_one() {
    let fx = Fx::new("illegible-hidden");
    let long = "s".repeat(200);
    let uuid = "u".repeat(58);
    // Two stores, one session uuid: a plain key and a digest key.
    fx.tree("shortslug", &uuid, "PLAIN-STORE");
    fx.tree(&long, &uuid, "DIGEST-STORE");
    fx.archive();

    let keys = fx.keys();
    assert_eq!(
        keys.len(),
        2,
        "fixture did not produce two stores: {keys:?}"
    );
    let digest = keys
        .iter()
        .find(|k| k.starts_with("_h256--"))
        .expect("no digest key")
        .clone();

    // Both legible: the resolver refuses to choose.
    let both = fx.run(&["read", "--scratch", &uuid, "--json"]);
    assert_eq!(
        both.json().map(|j| j["error"].clone()),
        Some(serde_json::json!("Ambiguous")),
        "fixture does not start ambiguous: {}",
        both.summary()
    );

    // One byte of damage to the digest ledger.
    fx.set_manifest_field(&digest, "uuid_hex", "zz");
    let after = fx.run(&["read", "--scratch", &uuid, "--json"]);
    assert_ne!(
        after.code,
        0,
        "damaging one of two stores that answer to this session turned a refusal \
         to guess into a silent answer from the survivor — the illegible key is \
         only reported when nothing else matched, so a legible key hides it. \
         Same downgrade the resolver fix closed, one layer along: {}",
        after.summary()
    );
}

/// The escape hatch, and the only one: a full store key asks about a directory
/// rather than a session, so it needs no agreement from the ledger. Without this
/// a damaged store would be unreachable by every route and unrepairable except
/// by hand.
#[test]
fn p15_the_full_key_escape_hatch_reaches_a_damaged_store() {
    let fx = Fx::new("escape");
    fx.tree("a", "-b", "P");
    fx.archive();
    fx.set_manifest_field(COLLIDING_KEY, "slug_hex", "zz");

    // By session: refused.
    assert_ne!(fx.run(&["read", "--scratch", "-b", "--json"]).code, 0);

    // By full key: reachable, so the operator can see what they must repair.
    let by_key = fx.run(&["read", "--scratch", COLLIDING_KEY, "--json"]);
    assert_eq!(
        by_key.code,
        0,
        "the full-key escape hatch does not reach a damaged store, leaving it \
         unreachable by every route: {}",
        by_key.summary()
    );
    let listing = by_key.json().expect("json");
    assert_eq!(
        listing["key"], COLLIDING_KEY,
        "the escape hatch returned some other store: {listing}"
    );
    assert_eq!(
        fx.payload(COLLIDING_KEY).as_deref(),
        Some("P"),
        "the escape hatch could not serve the store's own bytes"
    );

    // Repairing the manifest restores session addressing — the hatch is a way
    // back, not a permanent state.
    let ident = fx.manifest(COLLIDING_KEY);
    assert!(ident["slug_hex"].as_str().is_some());
    fx.set_manifest_field(COLLIDING_KEY, "slug_hex", "61"); // "a"
    assert_eq!(
        fx.run(&["read", "--scratch", "-b", "--json"]).code,
        0,
        "repairing the ledger did not restore addressing by session"
    );
}

// ---------------------------------------------------------------------------
// B. Key length and the three namespaces.
// ---------------------------------------------------------------------------

/// `KEY_MAX` is 200, but `NAME_MAX` is 255 — so a plain key of 201..255 bytes
/// **was** a legal directory name and pre-U6 stores at those names exist. Such a
/// key now takes the digest form, leaving the old store orphaned: its artifacts
/// are not read, not reconciled, and not reclaimed.
///
/// The doc reasons "a key that exceeded `NAME_MAX` never successfully created a
/// directory, so there is nothing to orphan", which holds above 255 and not in
/// the 201..255 band.
///
/// **Pins current behaviour.** 思兼 is ruling on this; if the ruling raises
/// `KEY_MAX` to 255, the expectation here changes.
#[test]
fn p15_a_long_plain_key_does_not_orphan_a_pre_u6_store() {
    let fx = Fx::new("keymax");
    // 150 + 2 + 58 = 210: over KEY_MAX, under NAME_MAX. Built from component
    // names only, so the fixture does not depend on the tmpdir's length.
    let slug = "s".repeat(150);
    let uuid = "u".repeat(58);
    let plain = format!("{slug}--{uuid}");
    assert!(
        plain.len() > 200 && plain.len() <= 255,
        "fixture is not in the 201..255 band: {}",
        plain.len()
    );
    fx.tree(&slug, &uuid, "LONGKEY");

    // A pre-U6 store that used the plain name successfully.
    let old = fx.store_root().join(&plain);
    std::fs::create_dir_all(&old).unwrap();
    std::fs::write(old.join("manifest.json"), br#"{"entries":[]}"#).unwrap();

    fx.archive();

    let keys = fx.keys();
    assert!(
        !keys.iter().any(|k| k.starts_with("_h256--")),
        "a plain key of {} bytes was moved to the digest form, orphaning the \
         pre-U6 store at its old name (keys now: {:?}). Those names were legal \
         — NAME_MAX is 255 — so such stores exist.",
        plain.len(),
        keys.iter().map(|k| k.len()).collect::<Vec<_>>()
    );
}

/// The three key namespaces must be mutually unimpersonable: a plain pair whose
/// concatenation would begin with either marker is pushed into the encoded
/// branch, so no plain key can look like an encoded one.
#[test]
fn p15_the_three_key_namespaces_cannot_impersonate_each_other() {
    let fx = Fx::new("namespaces");
    // A slug that would make the plain key start with each marker.
    fx.tree("_hex--x", "s1", "HEXLIKE");
    fx.tree("_h256--y", "s2", "DIGESTLIKE");
    fx.tree("plain", "s3", "PLAIN");
    fx.archive();

    let keys = fx.keys();
    assert_eq!(keys.len(), 3, "unexpected key set: {keys:?}");
    // The two marker-shaped plain pairs must have been encoded, so neither can
    // be mistaken for a genuine encoded key's payload.
    let encoded: Vec<&String> = keys.iter().filter(|k| k.starts_with("_hex--")).collect();
    assert_eq!(
        encoded.len(),
        2,
        "a plain pair beginning with a marker stayed in the plain namespace: \
         {keys:?}"
    );
    // Each remains individually retrievable — encoding must not merge them.
    let mut payloads: Vec<String> = keys.iter().filter_map(|k| fx.payload(k)).collect();
    payloads.sort();
    assert_eq!(
        payloads,
        vec![
            "DIGESTLIKE".to_string(),
            "HEXLIKE".to_string(),
            "PLAIN".to_string()
        ],
        "encoding merged two distinct trees: {keys:?}"
    );
}

// ---------------------------------------------------------------------------
// C. The resolver.
// ---------------------------------------------------------------------------

/// Resolving a session by uuid must open **only the chosen key's** manifest.
/// Proved without tracing: every other store's manifest is made unreadable, and
/// resolution must still succeed — a resolver that read them would fail.
///
/// Skipped under uid 0, which ignores the mode bits.
#[test]
fn p15_the_resolver_opens_only_the_chosen_manifest() {
    if is_root() {
        return;
    }
    let fx = Fx::new("resolver");
    for i in 1..=5 {
        fx.tree(&format!("slug{i}"), &format!("sess{i}"), &format!("p{i}"));
    }
    fx.archive();
    assert_eq!(fx.keys().len(), 5);

    for k in fx.keys() {
        if k != "slug3--sess3" {
            std::fs::set_permissions(fx.manifest_path(&k), std::fs::Permissions::from_mode(0o000))
                .unwrap();
        }
    }
    let o = fx.run(&["read", "--scratch", "sess3", "--json"]);
    for k in fx.keys() {
        let _ =
            std::fs::set_permissions(fx.manifest_path(&k), std::fs::Permissions::from_mode(0o600));
    }
    assert_eq!(
        o.code,
        0,
        "resolving one session failed while other stores' manifests were \
         unreadable, so the resolver opened more than the chosen one: {}",
        o.summary()
    );
}

/// The plain form's last residual: a session directory literally named
/// `bbbb--cccc` is suffix-indistinguishable from the key of slug `-a--bbbb` and
/// session `cccc`. The name test cannot separate them; the ledger must.
#[test]
fn p15_the_plain_suffix_residual_is_closed_by_the_ledger() {
    let fx = Fx::new("residual");
    fx.tree("-a--bbbb", "cccc", "FROM-SLUG-PAIR");
    fx.tree("zz", "bbbb--cccc", "FROM-LITERAL-NAME");
    fx.archive();

    // Both exist; asking for `cccc` must not hand back the other tree's bytes.
    let o = fx.run(&["read", "--scratch", "cccc", "--json"]);
    if o.code == 0 {
        let file = fx.run(&["read", "--scratch", "cccc", "--file", "scratchpad/n.md"]);
        assert_eq!(
            String::from_utf8_lossy(&file.stdout).trim(),
            "FROM-SLUG-PAIR",
            "resolving `cccc` served the tree literally named `bbbb--cccc`"
        );
    } else {
        // Refusing is also correct — the ledger disagreed and only an operator
        // can resolve an ambiguity. What is not correct is serving the wrong one.
        let j = o.json().expect("json");
        assert!(
            j["error"] == "Ambiguous" || j["error"] == "StoreKeyCollision",
            "unexpected refusal for an ambiguous selector: {}",
            o.summary()
        );
    }
}

/// A digest-form store whose manifest is gone cannot be resolved from a session
/// name — the key encodes nothing recoverable and the ledger is the only bridge.
/// Pinned as a known limit of the digest form.
///
/// **Fixture sized for `KEY_MAX = 255`.** It was 150/58 while `KEY_MAX` was 200,
/// which put it in the same 201..255 band as
/// `p15_a_long_plain_key_does_not_orphan_a_pre_u6_store` — the two then demanded
/// opposite forms of one pair and no `KEY_MAX` could satisfy both. The
/// arithmetic is asserted below so a future change to `KEY_MAX` fails here
/// loudly instead of silently re-pointing this test at the plain form.
///
/// Reaching the digest form needs **both** components long: each is a directory
/// name, so each is capped at `NAME_MAX` (a 300-byte slug cannot be `mkdir`ed at
/// all — measured), and only their sum can exceed the key bound.
#[test]
fn p15_a_digest_store_without_its_manifest_is_unreachable_by_uuid() {
    let fx = Fx::new("digest-lost");
    let slug = "s".repeat(200);
    let uuid = "u".repeat(58);
    // plain = 200 + 2 + 58 = 260 > 255, so the plain form is out; the hex form
    // doubles its input (6 + 400 + 2 + 116 = 524), so that is out too. Digest is
    // the only form left, and it is 71 bytes.
    assert!(
        slug.len() + 2 + uuid.len() > 255,
        "fixture no longer exceeds the plain bound"
    );
    assert!(
        6 + 2 * slug.len() + 2 + 2 * uuid.len() > 255,
        "fixture no longer exceeds the hex bound"
    );
    assert!(
        slug.len() <= 255 && uuid.len() <= 255,
        "fixture components exceed NAME_MAX and cannot be created"
    );
    fx.tree(&slug, &uuid, "DIGEST");
    fx.archive();
    let key = fx
        .keys()
        .into_iter()
        .find(|k| k.starts_with("_h256--"))
        .expect("no digest key produced");

    // Reachable by uuid while the ledger is there.
    assert_eq!(
        fx.run(&["read", "--scratch", &uuid, "--json"]).code,
        0,
        "a digest store was not resolvable by uuid even with its manifest"
    );

    std::fs::remove_file(fx.manifest_path(&key)).unwrap();
    let o = fx.run(&["read", "--scratch", &uuid, "--json"]);
    assert_ne!(
        o.code,
        0,
        "a digest store with no manifest resolved anyway: {}",
        o.summary()
    );
    // The full key still names its own directory.
    let by_key = fx.run(&["read", "--scratch", &key, "--json"]);
    assert_eq!(
        by_key.json().map(|j| j["error"].clone()),
        Some(serde_json::json!("NoManifest")),
        "naming the digest key directly gave an unexpected result: {}",
        by_key.summary()
    );
}

// ---------------------------------------------------------------------------
// D. Backward compatibility and self-promotion.
// ---------------------------------------------------------------------------

/// A pre-U6 manifest records neither field. It must parse, must not be refused,
/// must keep its store directory's name byte for byte, and must be stamped with
/// the real identity on the next write.
#[test]
fn p15_a_pre_u6_manifest_self_promotes_without_renaming_its_store() {
    let fx = Fx::new("pre-u6");
    fx.tree("-home-test", "sess1", "P");
    fx.archive();
    let key_before = fx.keys();
    assert_eq!(key_before, vec!["-home-test--sess1".to_string()]);

    // Strip the fields, as a manifest written before U6 would have them.
    let mut m = fx.manifest("-home-test--sess1");
    let obj = m.as_object_mut().unwrap();
    obj.remove("slug_hex");
    obj.remove("uuid_hex");
    std::fs::write(
        fx.manifest_path("-home-test--sess1"),
        serde_json::to_string_pretty(&m).unwrap(),
    )
    .unwrap();

    let out = fx.archive();
    assert_eq!(out.code, 0, "{}", out.summary());
    assert_eq!(
        fx.keys(),
        key_before,
        "a pre-U6 store was renamed; existing stores must keep their names"
    );
    assert_eq!(
        fx.payload("-home-test--sess1").as_deref(),
        Some("P"),
        "the pre-U6 store lost its payload"
    );
    let after = fx.manifest("-home-test--sess1");
    assert_eq!(
        after["slug_hex"].as_str(),
        Some("2d686f6d652d74657374"),
        "the identity was not stamped on the next write: {after}"
    );
    assert_eq!(after["uuid_hex"].as_str(), Some("7365737331"));
}

/// Non-UTF-8 slug and uuid must round-trip through the recorded identity, so the
/// check works for exactly the population `_hex--` exists for.
#[test]
fn p15_non_utf8_identity_round_trips() {
    let fx = Fx::new("nonutf8");
    let mut p = fx.tmp_root.clone().into_os_string().into_vec();
    p.extend_from_slice(b"/-proj-\xff/sess-\xfe/scratchpad");
    let d = PathBuf::from(OsString::from_vec(p));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("n.md"), b"NONUTF8\n").unwrap();

    fx.archive();
    let keys = fx.keys();
    assert_eq!(keys.len(), 1, "{keys:?}");
    assert!(
        keys[0].starts_with("_hex--"),
        "expected a hex key: {keys:?}"
    );

    let m = fx.manifest(&keys[0]);
    assert_eq!(
        m["slug_hex"].as_str(),
        Some("2d70726f6a2dff"),
        "the recorded slug identity is not the raw bytes: {m}"
    );
    assert_eq!(m["uuid_hex"].as_str(), Some("736573732dfe"));

    // Re-archiving must be a no-op, not a self-collision.
    let out = fx.archive();
    assert!(
        !out.stderr.contains("map to this store key"),
        "a non-UTF-8 tree collided with its own ledger: {}",
        out.summary()
    );
    assert_eq!(fx.keys(), keys);
}

/// A ledger outlives the tree it describes: tree A archives and stamps its
/// identity, GC reclaims A, and a colliding tree B appears later. B is refused
/// by the ledger of a tree that no longer exists.
///
/// Pinned as current behaviour — it is the safe side (B's data is never
/// overwritten), but an operator must intervene to clear it, and nothing in the
/// output says the blocking tree is gone.
#[test]
fn p15_a_ledger_outliving_its_tree_still_refuses_the_newcomer() {
    let fx = Fx::new("outlives");
    fx.tree("a", "-b", "OWNER-A");
    fx.archive();
    assert_eq!(fx.payload(COLLIDING_KEY).as_deref(), Some("OWNER-A"));

    // A's tree is gone; its ledger and archive remain.
    std::fs::remove_dir_all(fx.tmp_root.join("a")).unwrap();
    // B arrives.
    fx.tree("a-", "b", "NEWCOMER-B");
    let out = fx.archive();

    assert!(
        out.stderr.contains("map to this store key"),
        "the newcomer was not refused: {}",
        out.summary()
    );
    assert_eq!(
        fx.payload(COLLIDING_KEY).as_deref(),
        Some("OWNER-A"),
        "the newcomer overwrote the departed tree's archive"
    );
}
