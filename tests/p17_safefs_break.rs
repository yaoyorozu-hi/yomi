//! P17 break tests: adversarial assault on the final unit — fd descent for
//! store writes, and the `ensure_layout` window.
//!
//! The claim is that a symlink cannot redirect a store write, because nothing is
//! resolved by path: each component is opened from its parent's descriptor with
//! `O_NOFOLLOW`. So the attacks are — plant a link at every level and at the
//! artifact name itself, and force the **append** path, which is the one that was
//! actually leaking before this unit.
//!
//! Written to BREAK, not to confirm. Fixtures live under `CARGO_TARGET_TMPDIR`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_yomi");
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
            "p17-{tag}-{}-{}",
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
        for d in [
            &fx.cache_home,
            &fx.proc_root,
            &fx.yomi_home,
            &fx.decoy_dir(),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::set_permissions(&fx.yomi_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        fx
    }

    fn decoy_dir(&self) -> PathBuf {
        self.base.join("decoy")
    }

    fn transcript(&self) -> PathBuf {
        self.home
            .join(".claude/projects/-p")
            .join(format!("{SESSION}.jsonl"))
    }

    fn line(&self, n: u32, text: &str) -> String {
        serde_json::json!({
            "type": "user", "uuid": format!("u-{n}"), "parentUuid": null,
            "timestamp": "2026-07-12T10:00:00.000Z", "cwd": "/x",
            "gitBranch": "m", "version": "1", "sessionId": SESSION,
            "message": {"role": "user", "content": text}
        })
        .to_string()
            + "\n"
    }

    fn seed(&self) {
        std::fs::write(self.transcript(), self.line(1, "first message")).unwrap();
        std::fs::write(
            self.tmp_root.join("-p/s1/scratchpad/n.md"),
            b"scratch body\n",
        )
        .unwrap();
    }

    /// Append a line to the live transcript so the next run takes the
    /// incremental (append) path rather than a full re-capture.
    fn grow(&self, text: &str) {
        let mut s = std::fs::read_to_string(self.transcript()).unwrap();
        s.push_str(&self.line(2, text));
        std::fs::write(self.transcript(), s).unwrap();
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

    fn archive(&self) -> Out {
        self.run(&["archive", "--all", "--include", "transcript,scratch"])
    }

    fn artifact(&self) -> PathBuf {
        self.yomi_home
            .join("archive/-p")
            .join(SESSION)
            .join("transcript.jsonl.zst")
    }
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}
impl Out {
    fn summary(&self) -> String {
        format!(
            "exit={} stdout={:?} stderr={:?}",
            self.code,
            self.stdout.chars().take(120).collect::<String>(),
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

fn is_symlink(p: &Path) -> bool {
    std::fs::symlink_metadata(p)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

fn mode_of(p: &Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
}

// ---------------------------------------------------------------------------
// A. fd descent — every level, and the artifact name itself.
// ---------------------------------------------------------------------------

/// A symlink at any directory level inside the store must redirect nothing: the
/// descent opens each component from its parent's descriptor with `O_NOFOLLOW`,
/// so the link is never traversed and its target is never re-moded.
#[test]
fn p17_a_symlink_at_any_store_level_cannot_redirect_a_write() {
    let levels = [
        "archive/-p",
        "archive/-p/11111111-2222-3333-4444-555555555555",
        "archive/_scratch",
        "archive/_scratch/-p--s1",
        "archive/_scratch/-p--s1/scratchpad",
    ];
    for level in levels {
        let fx = Fx::new(&format!("lvl{}", level.len()));
        fx.seed();
        // Establish the layout once so the deeper levels are meaningful.
        assert_eq!(fx.archive().code, 0, "fixture must archive cleanly first");

        let decoy = fx.decoy_dir();
        std::fs::write(decoy.join("keep"), b"MUST-SURVIVE\n").unwrap();
        std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o755)).unwrap();
        let before_mode = mode_of(&decoy);
        let before_count = std::fs::read_dir(&decoy).unwrap().count();

        let target = fx.yomi_home.join(level);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        let _ = std::fs::remove_dir_all(&target);
        std::os::unix::fs::symlink(&decoy, &target).unwrap();

        // Give the run new work at every family so it must descend.
        fx.grow("more transcript");
        std::fs::write(
            fx.tmp_root.join("-p/s1/scratchpad/second.md"),
            b"second body\n",
        )
        .unwrap();
        let out = fx.archive();

        assert_eq!(
            std::fs::read_dir(&decoy).unwrap().count(),
            before_count,
            "level {level}: something was written through the link ({})",
            out.summary()
        );
        assert_eq!(
            mode_of(&decoy),
            before_mode,
            "level {level}: the link's target was re-moded"
        );
        assert!(
            is_symlink(&target),
            "level {level}: the link was replaced instead of refused"
        );
    }
}

/// The **append path** — the one that was actually leaking. `OpenOptions::append`
/// followed the link and wrote the frame into whatever it pointed at.
///
/// The decoy holds the genuine prior artifact, so the incremental decision really
/// does choose append rather than falling back to a full re-capture; otherwise
/// the attack never reaches the code under test.
#[test]
fn p17_the_append_path_refuses_a_symlinked_artifact() {
    let fx = Fx::new("append");
    fx.seed();
    assert_eq!(fx.archive().code, 0);

    let art = fx.artifact();
    let decoy = fx.decoy_dir().join("file");
    std::fs::copy(&art, &decoy).unwrap();
    let before = std::fs::read(&decoy).unwrap();
    let before_mode = mode_of(&decoy);

    std::fs::remove_file(&art).unwrap();
    std::os::unix::fs::symlink(&decoy, &art).unwrap();

    fx.grow("APPEND-PAYLOAD-2");
    let out = fx.archive();

    assert_eq!(
        std::fs::read(&decoy).unwrap(),
        before,
        "the append path wrote a frame through the symlink: {}",
        out.summary()
    );
    assert_eq!(
        mode_of(&decoy),
        before_mode,
        "the append path re-moded the link's target"
    );
    assert!(
        is_symlink(&art),
        "the link was replaced rather than refused: {}",
        out.summary()
    );
    assert!(
        out.stderr.contains("refusing to append"),
        "the refusal was not reported: {}",
        out.summary()
    );
}

/// The read side is still path-based, so a symlinked artifact whose target does
/// *not* look like the prior capture feeds foreign bytes into the append/full
/// decision. Measured: the decision falls to a full re-capture, which
/// `renameat`s a real artifact over the link — the link node is replaced, its
/// target untouched. Safe, and pinned so the reasoning is on record.
#[test]
fn p17_a_foreign_prefix_read_falls_back_to_a_safe_full_capture() {
    let fx = Fx::new("foreignread");
    fx.seed();
    assert_eq!(fx.archive().code, 0);

    let art = fx.artifact();
    let decoy = fx.decoy_dir().join("file");
    std::fs::write(&decoy, b"NOT-A-PRIOR-ARTIFACT\n").unwrap();
    let before = std::fs::read(&decoy).unwrap();
    std::fs::remove_file(&art).unwrap();
    std::os::unix::fs::symlink(&decoy, &art).unwrap();

    fx.grow("second message");
    let out = fx.archive();

    assert_eq!(
        std::fs::read(&decoy).unwrap(),
        before,
        "foreign bytes read through the link led to a write through it: {}",
        out.summary()
    );
    assert!(
        !is_symlink(&art),
        "expected the full-capture path to rename a real artifact over the link"
    );
    assert!(
        !std::fs::read(&art).unwrap().is_empty(),
        "no artifact was written at all: {}",
        out.summary()
    );
}

/// Temp names are **appended**, not substituted for the extension, so a staged
/// write can never collide with a differently-suffixed artifact the store
/// legitimately holds — and no temp may survive a completed run.
#[test]
fn p17_temp_names_neither_collide_nor_survive() {
    let fx = Fx::new("temps");
    fx.seed();
    assert_eq!(fx.archive().code, 0);
    fx.grow("second");
    assert_eq!(fx.archive().code, 0);

    let leftovers: Vec<PathBuf> = walk(&fx.yomi_home)
        .into_iter()
        .filter(|p| p.to_string_lossy().contains(".tmp-"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temp files survived a completed run: {leftovers:?}"
    );
    // Every stored artifact still carries its own suffix.
    let zst: Vec<PathBuf> = walk(&fx.yomi_home.join("archive"))
        .into_iter()
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("zst"))
        .collect();
    assert!(!zst.is_empty(), "nothing was stored");
}

/// A run that refuses partway must leave no temp behind for the reconciler to
/// find — `Staged` discards on drop, including on an early return.
#[test]
fn p17_a_refused_run_leaves_no_temp_behind() {
    let fx = Fx::new("droptemp");
    fx.seed();
    assert_eq!(fx.archive().code, 0);

    // Force the append refusal, which returns early from inside the writer.
    let art = fx.artifact();
    let decoy = fx.decoy_dir().join("file");
    std::fs::copy(&art, &decoy).unwrap();
    std::fs::remove_file(&art).unwrap();
    std::os::unix::fs::symlink(&decoy, &art).unwrap();
    fx.grow("payload");
    let out = fx.archive();
    assert_ne!(
        out.code,
        0,
        "fixture did not reach a refusal: {}",
        out.summary()
    );

    let leftovers: Vec<PathBuf> = walk(&fx.yomi_home)
        .into_iter()
        .filter(|p| p.to_string_lossy().contains(".tmp-"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "a refused run left staged temps behind: {leftovers:?}"
    );
}

// ---------------------------------------------------------------------------
// B. `ensure_layout` — assertion and creation as one operation.
// ---------------------------------------------------------------------------

/// The three members below the root are created through the root's descriptor.
/// A symlink at any of them must refuse the run, stay a symlink, and leave its
/// target untouched — including its mode.
#[test]
fn p17_ensure_layout_members_refuse_a_symlink_without_remoding_it() {
    for member in ["archive", "quarantine", "state"] {
        let fx = Fx::new(&format!("layout{}", member.len()));
        fx.seed();
        let decoy = fx.decoy_dir();
        std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o755)).unwrap();
        let before_mode = mode_of(&decoy);
        std::os::unix::fs::symlink(&decoy, fx.yomi_home.join(member)).unwrap();

        let out = fx.archive();
        assert_eq!(
            out.code,
            3,
            "a symlinked `{member}` was not refused: {}",
            out.summary()
        );
        assert!(
            is_symlink(&fx.yomi_home.join(member)),
            "`{member}` link was replaced rather than refused"
        );
        assert_eq!(
            std::fs::read_dir(&decoy).unwrap().count(),
            0,
            "something was written through the `{member}` link"
        );
        assert_eq!(
            mode_of(&decoy),
            before_mode,
            "the `{member}` link's target was re-moded"
        );
    }
}

/// Modes are claimed through the descriptor the run just obtained, so a
/// pre-existing loose directory is tightened even when the process umask is
/// wide open — `mkdirat` masks its mode, and an existing directory keeps what it
/// had, so `fchmod` is what makes this true.
#[test]
fn p17_loose_members_are_tightened_under_a_wide_umask() {
    let fx = Fx::new("tighten");
    fx.seed();
    for m in ["archive", "quarantine", "state"] {
        let d = fx.yomi_home.join(m);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
    }

    let sh = format!(
        "umask 000; exec {} archive --all --include transcript,scratch --home {}",
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

    for m in ["archive", "quarantine", "state"] {
        assert_eq!(
            mode_of(&fx.yomi_home.join(m)),
            0o700,
            "`{m}` was not tightened from 777 under a wide umask"
        );
    }
    // And every file the run wrote is owner-only, mode claimed before the name
    // became reachable.
    let loose: Vec<String> = walk(&fx.yomi_home)
        .into_iter()
        .filter(|p| {
            std::fs::symlink_metadata(p)
                .map(|m| m.is_file() && (m.permissions().mode() & 0o077) != 0)
                .unwrap_or(false)
        })
        .map(|p| format!("{} = {:o}", p.display(), mode_of(&p)))
        .collect();
    assert!(loose.is_empty(), "files readable beyond owner: {loose:#?}");
}

fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

// ---------------------------------------------------------------------------
// C. The remaining path-based operations.
// ---------------------------------------------------------------------------

/// Reconciliation removes stale artifacts by path. `WalkDir` does not descend a
/// symlinked directory, so a link planted inside a store key must not let the
/// sweep delete outside the tree.
#[test]
fn p17_reconciliation_does_not_delete_through_a_symlinked_directory() {
    let fx = Fx::new("reconcile");
    fx.seed();
    assert_eq!(fx.archive().code, 0);

    let outside = fx.base.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("precious.md.zst"), b"MUST-SURVIVE\n").unwrap();

    let key_dir = fx.yomi_home.join("archive/_scratch/-p--s1");
    assert!(key_dir.is_dir(), "fixture produced no scratch store");
    std::os::unix::fs::symlink(&outside, key_dir.join("hop")).unwrap();

    // Deny everything so the reconciler sweeps the whole key.
    std::fs::write(fx.yomi_home.join("config.toml"), "[scratch]\nallow = []\n").unwrap();
    let out = fx.archive();

    assert!(
        outside.join("precious.md.zst").exists(),
        "reconciliation deleted through a symlinked directory inside a store \
         key: {}",
        out.summary()
    );
}

/// The store root is the one member still asserted by path — there is no
/// descriptor above `--home` to descend from. It must still refuse.
#[test]
fn p17_the_store_root_itself_is_still_refused_when_foreign() {
    let fx = Fx::new("root");
    fx.seed();
    let decoy = fx.decoy_dir();
    std::fs::remove_dir_all(&fx.yomi_home).unwrap();
    std::os::unix::fs::symlink(&decoy, &fx.yomi_home).unwrap();

    let out = fx.archive();
    assert_eq!(
        out.code,
        3,
        "a symlinked store root was not refused: {}",
        out.summary()
    );
    assert!(is_symlink(&fx.yomi_home), "the root link was replaced");
    assert_eq!(
        std::fs::read_dir(&decoy).unwrap().count(),
        0,
        "something was written through the root link"
    );
}
