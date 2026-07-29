//! P4 break tests, CLI level: drive the real `yomi` binary at the delete path
//! and the lock path after the rustix/std migration (#4, c1a8f73).
//!
//! Everything is fabricated in a tmpdir with an isolated HOME/YOMI_HOME; no real
//! Claude Code data is touched.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_yomi");

struct Fx {
    home: PathBuf,
    yomi_home: PathBuf,
    tmp_root: PathBuf,
    cache_home: PathBuf,
    proc_root: PathBuf,
    slug: String,
}

fn unique() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

impl Fx {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "yomi-p4g-{tag}-{}-{}",
            std::process::id(),
            unique()
        ));
        let home = base.join("home");
        let slug = "-home-test".to_string();
        std::fs::create_dir_all(home.join(".claude/projects").join(&slug)).unwrap();
        let fx = Fx {
            home,
            yomi_home: base.join("yomi"),
            tmp_root: base.join("tmp"),
            cache_home: base.join("cache"),
            proc_root: base.join("proc"),
            slug,
        };
        for d in [&fx.tmp_root, &fx.cache_home, &fx.proc_root] {
            std::fs::create_dir_all(d).unwrap();
        }
        let b = fx.proc_root.parent().unwrap();
        std::fs::create_dir_all(b.join("homes")).unwrap();
        std::fs::create_dir_all(b.join("tmpbase")).unwrap();
        fx
    }

    fn projects(&self) -> PathBuf {
        self.home.join(".claude/projects").join(&self.slug)
    }

    fn transcript(&self, uuid: &str) -> PathBuf {
        self.projects().join(format!("{uuid}.jsonl"))
    }

    fn write_transcript(&self, uuid: &str, texts: &[&str]) {
        let mut body = String::new();
        for t in texts {
            body.push_str(&user_line(uuid, t));
            body.push('\n');
        }
        std::fs::create_dir_all(self.projects()).unwrap();
        std::fs::write(self.transcript(uuid), body).unwrap();
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(BIN);
        c.args(args)
            .arg("--home")
            .arg(&self.yomi_home)
            .env("HOME", &self.home)
            .env("YOMI_TMP_ROOT", &self.tmp_root)
            .env("YOMI_CACHE_HOME", &self.cache_home)
            .env("YOMI_PROC_ROOT", &self.proc_root)
            // Cross-user discovery must never walk the real /home or /tmp.
            .env(
                "YOMI_HOME_BASE",
                self.proc_root.parent().unwrap().join("homes"),
            )
            .env(
                "YOMI_TMP_BASE",
                self.proc_root.parent().unwrap().join("tmpbase"),
            )
            .env_remove("YOMI_HOME")
            .env_remove("YOMI_CLAUDE_HOME");
        c
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        self.command(args).output().expect("run yomi")
    }

    fn gc_log(&self) -> Vec<serde_json::Value> {
        let Ok(text) = std::fs::read_to_string(self.yomi_home.join("gc.log")) else {
            return Vec::new();
        };
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn scratch_session(&self, uuid: &str) -> PathBuf {
        self.tmp_root.join(&self.slug).join(uuid)
    }
}

fn user_line(uuid: &str, text: &str) -> String {
    serde_json::json!({
        "type": "user",
        "uuid": format!("u-{}", unique()),
        "parentUuid": null,
        "timestamp": "2026-07-12T10:00:00.000Z",
        "cwd": "/home/test",
        "gitBranch": "main",
        "version": "2.1.207",
        "sessionId": uuid,
        "message": {"role": "user", "content": text}
    })
    .to_string()
}

fn code(out: &std::process::Output) -> i32 {
    out.status.code().unwrap()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn set_mtime_days(path: &Path, days: u64) {
    let when = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86_400);
    filetime::set_file_mtime(path, filetime::FileTime::from_system_time(when)).unwrap();
}

fn set_tree_mtime_days(root: &Path, days: u64) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    set_mtime_days(&p, days);
                }
            }
        }
    }
}

/// Whether this process runs as uid 0, read off a file it just created — a new
/// file takes its creator's effective uid. The chmod-based denial tests below
/// are meaningless as root, which ignores directory write bits.
///
/// The earlier form probed by creating `/.yomi-p4g-root-probe`; in a root CI
/// container that write actually succeeds, so the suite wrote into the
/// filesystem root to answer a question a local stat already answers.
fn is_root() -> bool {
    static ROOT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ROOT.get_or_init(|| {
        use std::os::unix::fs::MetadataExt;
        let probe = std::env::temp_dir().join(format!("yomi-p4g-uid-{}", std::process::id()));
        std::fs::write(&probe, b"").unwrap();
        let uid = std::fs::metadata(&probe).unwrap().uid();
        let _ = std::fs::remove_file(&probe);
        uid == 0
    })
}

/// Deletable count from a dry-run plan, so a fixture that produces no candidate
/// cannot make an escape test pass vacuously.
fn plan_deletable(fx: &Fx, target: &str) -> u64 {
    let out = fx.run(&["gc", "--targets", target, "--json"]);
    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("plan json");
    v["deletable"].as_u64().unwrap()
}

/// Every file and dir under `root`, with its mode.
fn walk_modes(root: &Path) -> Vec<(PathBuf, u32)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        if let Ok(md) = std::fs::symlink_metadata(&p) {
            out.push((p.clone(), md.permissions().mode() & 0o7777));
            if md.is_dir()
                && let Ok(rd) = std::fs::read_dir(&p)
            {
                for e in rd.flatten() {
                    stack.push(e.path());
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// A. An unlink failure aborts the ENTIRE commit run.
// ---------------------------------------------------------------------------

/// `safe_unlink` returns `Err` when `unlinkat` fails; `gc::commit` propagates it
/// with `?` and `cli::gc::run` propagates again, so ONE undeletable candidate
/// kills the whole pass: later candidates are never re-evaluated, never
/// unlinked, and never written to `gc.log`. A partial, silently-truncated audit
/// trail is exactly what the delete path must not produce.
#[test]
fn p4g_one_unlink_failure_aborts_the_whole_commit() {
    if is_root() {
        return;
    }
    let fx = Fx::new("abort");
    let uuids: Vec<String> = (0..4)
        .map(|i| format!("aaaaaaaa-bbbb-cccc-dddd-00000000000{i}"))
        .collect();
    for u in &uuids {
        fx.write_transcript(u, &["one", "two"]);
    }
    assert!(fx.run(&["archive", "--all"]).status.success());
    for u in &uuids {
        set_mtime_days(&fx.transcript(u), 200);
    }

    // Dry run must see all four as deletable.
    let plan = fx.run(&["gc", "--targets", "transcripts", "--json"]);
    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&plan.stdout).trim()).expect("plan json");
    assert_eq!(
        v["deletable"], 4,
        "fixture did not produce 4 candidates: {v}"
    );

    // Make every unlink fail with EACCES (parent dir r-x, no write).
    std::fs::set_permissions(fx.projects(), std::fs::Permissions::from_mode(0o555)).unwrap();
    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    std::fs::set_permissions(fx.projects(), std::fs::Permissions::from_mode(0o755)).unwrap();

    for u in &uuids {
        assert!(
            fx.transcript(u).exists(),
            "a source was deleted under EACCES"
        );
    }
    let log = fx.gc_log();
    assert_eq!(
        log.len(),
        4,
        "only {} of 4 candidates reached gc.log (exit {}, stderr {:?}); an unlink \
         failure aborted the run and the remaining candidates were silently \
         dropped from the audit trail",
        log.len(),
        code(&out),
        stderr(&out).trim()
    );
}

/// The same abort seen from the operator's side: the run reports a hard error
/// (exit 1) rather than the documented EXIT_PARTIAL(2) it uses for every other
/// "could not delete this one" outcome.
#[test]
fn p4g_unlink_failure_reports_partial_not_hard_error() {
    if is_root() {
        return;
    }
    let fx = Fx::new("exitcode");
    let u = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    fx.write_transcript(u, &["one"]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    set_mtime_days(&fx.transcript(u), 200);

    std::fs::set_permissions(fx.projects(), std::fs::Permissions::from_mode(0o555)).unwrap();
    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    std::fs::set_permissions(fx.projects(), std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(fx.transcript(u).exists());
    assert_eq!(
        code(&out),
        2,
        "expected EXIT_PARTIAL for an undeletable candidate, got {} (stderr {:?})",
        code(&out),
        stderr(&out).trim()
    );
}

// ---------------------------------------------------------------------------
// B. umask: the rustix Mode::RWXG|RWXO replacement for libc::umask(0o077).
// ---------------------------------------------------------------------------

/// Run every write command under a wide-open process umask. If the umask
/// tightening regressed, transcripts, secrets and the catalog land group- and
/// world-readable.
#[test]
fn p4g_wide_umask_never_leaks_group_or_world_bits() {
    let fx = Fx::new("umask");
    let u = "aaaaaaaa-bbbb-cccc-dddd-ffffffffffff";
    fx.write_transcript(u, &["hello", "world"]);

    // Drive the umask through a shell so each child really starts with 000.
    for sub in [
        "archive --all",
        "index",
        "gc --targets transcripts --commit",
        "gc --discover-all-users",
        "verify",
    ] {
        let sh = format!(
            "umask 000; exec {bin} {sub} --home {yh}",
            bin = shell_quote(BIN),
            yh = shell_quote(&fx.yomi_home.to_string_lossy())
        );
        let out = Command::new("/bin/sh")
            .arg("-c")
            .arg(&sh)
            .env("HOME", &fx.home)
            .env("YOMI_TMP_ROOT", &fx.tmp_root)
            .env("YOMI_CACHE_HOME", &fx.cache_home)
            .env("YOMI_PROC_ROOT", &fx.proc_root)
            .env(
                "YOMI_HOME_BASE",
                fx.proc_root.parent().unwrap().join("homes"),
            )
            .env(
                "YOMI_TMP_BASE",
                fx.proc_root.parent().unwrap().join("tmpbase"),
            )
            .env_remove("YOMI_HOME")
            .env_remove("YOMI_CLAUDE_HOME")
            .output()
            .expect("run under umask 000");
        assert!(
            [0, 2].contains(&code(&out)),
            "`{sub}` under umask 000 failed hard: {:?}",
            stderr(&out)
        );
    }

    let loose: Vec<String> = walk_modes(&fx.yomi_home)
        .into_iter()
        .filter(|(_, m)| m & 0o077 != 0)
        .map(|(p, m)| format!("{} = {m:o}", p.display()))
        .collect();
    assert!(
        loose.is_empty(),
        "umask 0o077 did not hold under a 000 process umask; \
         group/world-accessible store entries: {loose:#?}"
    );
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

// ---------------------------------------------------------------------------
// C. The write lock under real concurrency and hostile lock paths.
// ---------------------------------------------------------------------------

/// Four `gc --commit` processes launched at once against one store. The
/// properties asserted here hold under EVERY interleaving, including full
/// serialization: nobody crashes, every source is reclaimed, and each is
/// reclaimed exactly once.
///
/// Mutual exclusion is asserted as "at most one process reported reclaiming
/// anything", not as "three of the four exited REFUSED". The latter is a
/// statement about the scheduler: nothing forbids the four from running strictly
/// back to back, each taking an uncontended lock, the first reclaiming all six
/// and the rest finding an empty plan and also exiting OK. That is correct
/// behaviour that the exit-code form would report as a lock failure. Counting
/// reported deletions says the same thing about the lock without depending on
/// overlap ever happening.
///
/// (Measured: even pinned to a single CPU, three of four did observe contention
/// in 6/6 trials here — the exit-code form was not seen to fail. It is dropped
/// as unsound in principle, not as an observed flake.)
#[test]
fn p4g_concurrent_commits_never_double_delete() {
    let fx = Fx::new("concurrent");
    let uuids: Vec<String> = (0..6)
        .map(|i| format!("cccccccc-bbbb-cccc-dddd-00000000000{i}"))
        .collect();
    for u in &uuids {
        fx.write_transcript(u, &["one"]);
    }
    assert!(fx.run(&["archive", "--all"]).status.success());
    for u in &uuids {
        set_mtime_days(&fx.transcript(u), 200);
    }

    let mut children: Vec<_> = (0..4)
        .map(|_| {
            fx.command(&["gc", "--targets", "transcripts", "--commit", "--json"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn gc")
        })
        .collect();
    let outs: Vec<_> = children
        .drain(..)
        .map(|c| c.wait_with_output().unwrap())
        .collect();

    let codes: Vec<i32> = outs.iter().map(code).collect();
    for (i, o) in outs.iter().enumerate() {
        assert!(
            [0, 2, 3].contains(&code(o)),
            "gc #{i} exited {} (not OK/PARTIAL/REFUSED): {:?}",
            code(o),
            stderr(o).trim()
        );
    }
    // Mutual exclusion, stated without reference to the scheduler: a process
    // that refused reports nothing; at most one may report reclaiming anything,
    // and between them they must account for all six exactly once.
    let reported: Vec<u64> = outs
        .iter()
        .map(|o| {
            serde_json::from_str::<serde_json::Value>(String::from_utf8_lossy(&o.stdout).trim())
                .ok()
                .and_then(|v| v["deleted"].as_u64())
                .unwrap_or(0)
        })
        .collect();
    assert!(
        reported.iter().filter(|n| **n > 0).count() <= 1,
        "more than one concurrent `gc --commit` reclaimed sources: {reported:?} \
         (exit codes {codes:?}) — the write lock did not serialize them"
    );
    assert_eq!(
        reported.iter().sum::<u64>(),
        6,
        "the four processes together reclaimed {:?}, expected 6 in total \
         (exit codes {codes:?})",
        reported
    );

    // Every source reclaimed, none left behind.
    for u in &uuids {
        assert!(
            !fx.transcript(u).exists(),
            "{u} survived four concurrent commits (exit codes {codes:?})"
        );
    }
    // And each reclaimed exactly once. A second process re-deleting a source
    // already gone — or double-counting one — shows up here as a 7th record.
    let deletes: Vec<String> = fx
        .gc_log()
        .iter()
        .filter(|l| l["action"] == "delete")
        .map(|l| l["source"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        deletes.len(),
        6,
        "expected exactly 6 delete records across all four processes, got {} \
         (exit codes {codes:?})",
        deletes.len()
    );
    let unique: std::collections::HashSet<&String> = deletes.iter().collect();
    assert_eq!(
        unique.len(),
        6,
        "a source was recorded as deleted more than once: {deletes:?}"
    );
}

/// `WriteLock::acquire` uses `File::create`, which follows symlinks and
/// truncates. A `.yomi.lock` symlinked at the catalog destroys the catalog on
/// the next write command — and the store then reports zero archives while the
/// archive files are still on disk. Pre-existing (fs2 did the same); #4 did not
/// change it.
#[test]
fn p4g_symlinked_lock_path_destroys_the_catalog() {
    let fx = Fx::new("locksym");
    let u = "dddddddd-bbbb-cccc-dddd-eeeeeeeeeeee";
    fx.write_transcript(u, &["one"]);
    assert!(fx.run(&["archive", "--all"]).status.success());

    let catalog = fx.yomi_home.join("state/catalog.db");
    let before = std::fs::metadata(&catalog).unwrap().len();
    assert!(before > 0);
    let rows_before = archive_rows(&catalog);
    assert!(rows_before > 0, "fixture archived nothing");

    let lock = fx.yomi_home.join(".yomi.lock");
    let _ = std::fs::remove_file(&lock);
    std::os::unix::fs::symlink(&catalog, &lock).unwrap();

    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    let rows_after = archive_rows(&catalog);
    assert_eq!(
        rows_after,
        rows_before,
        "the catalog lost {} of {rows_before} archive rows because .yomi.lock was a \
         symlink to it — File::create follows symlinks and applies O_TRUNC \
         (size {before} -> {}, gc exit {}, stderr {:?})",
        rows_before - rows_after,
        std::fs::metadata(&catalog).map(|m| m.len()).unwrap_or(0),
        code(&out),
        stderr(&out).trim()
    );
}

fn archive_rows(db: &Path) -> i64 {
    let conn =
        match rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        {
            Ok(c) => c,
            Err(_) => return 0,
        };
    conn.query_row("SELECT count(*) FROM artifacts", [], |r| r.get(0))
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// D. Symlink escape from the roots.
// ---------------------------------------------------------------------------

/// The project directory is swapped for a symlink at an out-of-roots tree that
/// happens to hold an identically named, identically contented file. Every gate
/// (blacklist, catalog, source sha, store re-verify, age) would pass on content,
/// so containment is the only thing standing between the GC and a file it has
/// no business touching.
#[test]
fn p4g_symlinked_project_dir_does_not_escape_roots() {
    let fx = Fx::new("escape");
    let u = "eeeeeeee-bbbb-cccc-dddd-eeeeeeeeeeee";
    fx.write_transcript(u, &["one", "two"]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    set_mtime_days(&fx.transcript(u), 200);

    // An out-of-roots twin with byte-identical content.
    let outside = fx.home.parent().unwrap().join("outside/projects");
    std::fs::create_dir_all(&outside).unwrap();
    let twin = outside.join(format!("{u}.jsonl"));
    std::fs::copy(fx.transcript(u), &twin).unwrap();
    set_mtime_days(&twin, 200);
    assert_eq!(
        plan_deletable(&fx, "transcripts"),
        1,
        "fixture is not deletable before the swap"
    );

    // Replace the real project dir with a symlink at the outside tree.
    std::fs::remove_dir_all(fx.projects()).unwrap();
    std::os::unix::fs::symlink(&outside, fx.projects()).unwrap();

    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    assert!(
        twin.exists(),
        "GC unlinked {} — a file outside every source root — through a symlinked \
         project directory (exit {}, stderr {:?})",
        twin.display(),
        code(&out),
        stderr(&out).trim()
    );
}

/// The same escape one level up: `.claude/projects` itself is a symlink, so the
/// candidate's parent-dir open in `safe_unlink` traverses it (O_NOFOLLOW guards
/// only the final component).
#[test]
fn p4g_symlinked_projects_root_does_not_escape_roots() {
    let fx = Fx::new("escape2");
    let u = "ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee";
    fx.write_transcript(u, &["one", "two"]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    set_mtime_days(&fx.transcript(u), 200);

    let outside = fx.home.parent().unwrap().join("outside2");
    std::fs::create_dir_all(outside.join(&fx.slug)).unwrap();
    let twin = outside.join(&fx.slug).join(format!("{u}.jsonl"));
    std::fs::copy(fx.transcript(u), &twin).unwrap();
    set_mtime_days(&twin, 200);
    assert_eq!(
        plan_deletable(&fx, "transcripts"),
        1,
        "fixture is not deletable before the swap"
    );

    let projects_root = fx.home.join(".claude/projects");
    std::fs::remove_dir_all(&projects_root).unwrap();
    std::os::unix::fs::symlink(&outside, &projects_root).unwrap();

    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    assert!(
        twin.exists(),
        "GC unlinked {} outside every source root through a symlinked \
         .claude/projects (exit {}, stderr {:?})",
        twin.display(),
        code(&out),
        stderr(&out).trim()
    );
}

/// A scratch session directory replaced by a symlink at an out-of-roots tree.
/// `remove_tree_guarded` ends in `std::fs::remove_dir_all`; it must not follow.
#[test]
fn p4g_scratch_root_symlink_does_not_delete_outside_tree() {
    let fx = Fx::new("scratchsym");
    let u = "11111111-2222-3333-4444-555555555555";
    let sess = fx.scratch_session(u);
    std::fs::create_dir_all(sess.join("scratchpad")).unwrap();
    std::fs::write(sess.join("scratchpad/notes.md"), b"work\n").unwrap();
    assert!(
        fx.run(&["archive", "--all", "--include", "scratch"])
            .status
            .success()
    );
    set_tree_mtime_days(&sess, 200);
    assert_eq!(
        plan_deletable(&fx, "scratch"),
        1,
        "fixture is not deletable"
    );

    // Swap the live tree for a symlink at an outside tree of the same shape.
    let outside = fx.home.parent().unwrap().join("outside-scratch");
    std::fs::create_dir_all(outside.join("scratchpad")).unwrap();
    std::fs::write(outside.join("scratchpad/notes.md"), b"work\n").unwrap();
    std::fs::remove_dir_all(&sess).unwrap();
    std::os::unix::fs::symlink(&outside, &sess).unwrap();
    set_tree_mtime_days(&outside, 200);

    let out = fx.run(&["gc", "--targets", "scratch", "--commit"]);
    assert!(
        outside.join("scratchpad/notes.md").exists(),
        "remove_dir_all followed a symlinked scratch root and deleted {} \
         (exit {}, stderr {:?})",
        outside.display(),
        code(&out),
        stderr(&out).trim()
    );
}

/// A directory symlink planted INSIDE an otherwise-deletable scratch tree.
/// Removing the tree must remove the link node, never walk into the target.
#[test]
fn p4g_scratch_inner_dir_symlink_is_not_followed() {
    let fx = Fx::new("scratchinner");
    let u = "22222222-2222-3333-4444-555555555555";
    let sess = fx.scratch_session(u);
    std::fs::create_dir_all(sess.join("scratchpad")).unwrap();
    std::fs::write(sess.join("scratchpad/notes.md"), b"work\n").unwrap();

    let outside = fx.home.parent().unwrap().join("precious");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("keepme"), b"do not delete\n").unwrap();

    assert!(
        fx.run(&["archive", "--all", "--include", "scratch"])
            .status
            .success()
    );
    std::os::unix::fs::symlink(&outside, sess.join("scratchpad/hop")).unwrap();
    set_tree_mtime_days(&sess, 200);
    assert_eq!(
        plan_deletable(&fx, "scratch"),
        1,
        "fixture is not deletable"
    );

    let out = fx.run(&["gc", "--targets", "scratch", "--commit"]);
    assert!(
        !sess.exists(),
        "the scratch tree itself was not reclaimed, so the symlink was never \
         exercised (exit {}, stderr {:?})",
        code(&out),
        stderr(&out).trim()
    );
    assert!(
        outside.join("keepme").exists(),
        "a directory symlink inside the scratch tree was followed and {} was \
         deleted (exit {}, stderr {:?})",
        outside.display(),
        code(&out),
        stderr(&out).trim()
    );
}

/// `verify_scratch_tree` keys the manifest by `to_string_lossy()`. Two distinct
/// non-UTF-8 filenames collapse to the same lossy key, so an UNARCHIVED file can
/// impersonate an archived sibling and let the whole tree be reclaimed. The tree
/// must not be deleted while it holds a file the archive does not cover.
#[test]
fn p4g_scratch_lossy_filename_collision_does_not_authorize_delete() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let fx = Fx::new("lossy");
    let u = "66666666-2222-3333-4444-555555555555";
    let pad = fx.scratch_session(u).join("scratchpad");
    std::fs::create_dir_all(&pad).unwrap();
    // Archived under one non-UTF-8 name.
    let archived = pad.join(OsStr::from_bytes(b"note-\xff.md"));
    std::fs::write(&archived, b"archived\n").unwrap();
    assert!(
        fx.run(&["archive", "--all", "--include", "scratch"])
            .status
            .success()
    );

    // A DIFFERENT non-UTF-8 name that lossy-decodes to the same string, holding
    // content that was never archived.
    let impostor = pad.join(OsStr::from_bytes(b"note-\xfe.md"));
    std::fs::write(&impostor, b"archived\n").unwrap();
    set_tree_mtime_days(&fx.scratch_session(u), 200);

    let out = fx.run(&["gc", "--targets", "scratch", "--commit"]);
    assert!(
        impostor.exists(),
        "an unarchived file was reclaimed because its filename lossy-decodes to \
         an archived sibling's name (exit {}, stderr {:?})",
        code(&out),
        stderr(&out).trim()
    );
}

/// The same collision with DIFFERENT content: gate (2) re-hashes live bytes, so
/// the impostor must fail the sha check and block the whole-tree delete.
#[test]
fn p4g_scratch_lossy_collision_with_distinct_content_is_caught() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let fx = Fx::new("lossy2");
    let u = "77777777-2222-3333-4444-555555555555";
    let pad = fx.scratch_session(u).join("scratchpad");
    std::fs::create_dir_all(&pad).unwrap();
    let archived = pad.join(OsStr::from_bytes(b"note-\xff.md"));
    std::fs::write(&archived, b"archived\n").unwrap();
    assert!(
        fx.run(&["archive", "--all", "--include", "scratch"])
            .status
            .success()
    );

    let impostor = pad.join(OsStr::from_bytes(b"note-\xfe.md"));
    std::fs::write(&impostor, b"SECRETS!\n").unwrap(); // same length, other bytes
    set_tree_mtime_days(&fx.scratch_session(u), 200);

    let out = fx.run(&["gc", "--targets", "scratch", "--commit"]);
    assert!(
        impostor.exists() && archived.exists(),
        "the tree was reclaimed although it held unarchived content under a \
         lossy-colliding name (exit {}, stderr {:?})",
        code(&out),
        stderr(&out).trim()
    );
}

/// Both colliding names present when the archive runs. Scratch identity is
/// byte-valued (`ScratchRel` in `src/scratch.rs`), so the two names key and
/// store separately: two `.zst`, two manifest entries, no overwrite. Coverage is
/// therefore real, and the reclaim that follows is a reclaim of archived data —
/// both payloads are still retrievable from the store afterwards, which is the
/// whole point of the name of this test.
///
/// Before that module owned the key, both names derived from the same `U+FFFD`
/// lossy string: one `.zst` silently overwrote the other while the manifest
/// still listed two entries, so recoverability was preserved only by the gate
/// refusing the tree forever. The invariant asserted here is unchanged — both
/// files stay recoverable — but it is now met by capturing both rather than by
/// never reclaiming.
#[test]
fn p4g_scratch_lossy_collision_at_archive_time_keeps_both_recoverable() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    /// Decompressed payload of every `.zst` under the scratch store.
    fn store_payloads(root: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(p) = stack.pop() {
            let Ok(md) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if md.is_dir() {
                for e in std::fs::read_dir(&p).unwrap().flatten() {
                    stack.push(e.path());
                }
            } else if p.extension().and_then(|e| e.to_str()) == Some("zst")
                && let Ok(raw) = std::fs::read(&p)
                && let Ok(d) = yomi::archive::compress::decompress_all(&raw)
            {
                out.push(String::from_utf8_lossy(&d).to_string());
            }
        }
        out.sort();
        out
    }

    let fx = Fx::new("lossy3");
    let u = "88888888-2222-3333-4444-555555555555";
    let pad = fx.scratch_session(u).join("scratchpad");
    std::fs::create_dir_all(&pad).unwrap();
    let a = pad.join(OsStr::from_bytes(b"note-\xff.md"));
    let b = pad.join(OsStr::from_bytes(b"note-\xfe.md"));
    std::fs::write(&a, b"AAAA-content\n").unwrap();
    std::fs::write(&b, b"BBBB-content\n").unwrap();

    assert!(
        fx.run(&["archive", "--all", "--include", "scratch"])
            .status
            .success()
    );
    set_tree_mtime_days(&fx.scratch_session(u), 200);

    let store_root = fx.yomi_home.join("archive/_scratch");
    let captured = store_payloads(&store_root);
    let has_both = |v: &[String]| {
        let j = v.join("\n");
        j.contains("AAAA-content") && j.contains("BBBB-content")
    };
    assert!(
        has_both(&captured),
        "one of two lossy-colliding payloads was dropped — their stored paths \
         still collapse to a single key. The store holds {captured:?}"
    );

    let out = fx.run(&["gc", "--targets", "scratch", "--commit"]);
    assert!(
        !fx.scratch_session(u).exists(),
        "the tree was not reclaimed although the archive covers both colliding \
         files (exit {}, stderr {:?})",
        code(&out),
        stderr(&out).trim()
    );
    let after = store_payloads(&store_root);
    assert!(
        has_both(&after),
        "the live tree was reclaimed but the store no longer holds both payloads \
         ({after:?}) — the reclaim destroyed data it claimed to have archived"
    );
}

// ---------------------------------------------------------------------------
// E. Post-delete integrity.
// ---------------------------------------------------------------------------

/// After a real delete the archive must still serve the data and the catalog
/// must still agree with what is on disk. A source gone from the fs but a store
/// that no longer verifies is unrecoverable data loss.
#[test]
fn p4g_after_delete_archive_and_catalog_stay_consistent() {
    let fx = Fx::new("integrity");
    let u = "33333333-2222-3333-4444-555555555555";
    fx.write_transcript(u, &["alpha", "beta"]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    assert!(fx.run(&["index"]).status.success());
    set_mtime_days(&fx.transcript(u), 200);

    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    assert_eq!(code(&out), 0, "commit not clean: {:?}", stderr(&out).trim());
    assert!(!fx.transcript(u).exists(), "source not deleted");

    let ver = fx.run(&["verify", "--json"]);
    assert_eq!(
        code(&ver),
        0,
        "verify failed after GC: {:?} {:?}",
        String::from_utf8_lossy(&ver.stdout),
        stderr(&ver).trim()
    );
    let read = fx.run(&["read", u]);
    assert_eq!(
        code(&read),
        0,
        "the archived session is unreadable after its source was deleted: {:?}",
        stderr(&read).trim()
    );
    assert!(
        String::from_utf8_lossy(&read.stdout).contains("alpha"),
        "archived content lost after delete"
    );
    let raw = fx.run(&["read", u, "--raw"]);
    assert_eq!(code(&raw), 0, "raw read broke: {:?}", stderr(&raw).trim());
    assert!(
        String::from_utf8_lossy(&raw.stdout).contains("beta"),
        "stored bytes are not recoverable after the source was deleted"
    );
    let status = fx.run(&["status", "--json"]);
    assert_eq!(code(&status), 0, "status broke after GC");
}

/// A source that vanishes between plan and unlink (the ordinary case: Claude
/// Code cleaned up its own file, or a second yomi won the race) must be a skip,
/// not a run-killing error.
#[test]
fn p4g_source_vanishing_before_commit_is_a_skip() {
    let fx = Fx::new("vanish");
    let a = "44444444-2222-3333-4444-555555555555";
    let b = "55555555-2222-3333-4444-555555555555";
    fx.write_transcript(a, &["alpha"]);
    fx.write_transcript(b, &["beta"]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    set_mtime_days(&fx.transcript(a), 200);
    set_mtime_days(&fx.transcript(b), 200);

    // `a` disappears before the run starts.
    std::fs::remove_file(fx.transcript(a)).unwrap();

    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    assert!(
        [0, 2].contains(&code(&out)),
        "a vanished source made the run fail hard (exit {}): {:?}",
        code(&out),
        stderr(&out).trim()
    );
    assert!(
        !fx.transcript(b).exists(),
        "the surviving candidate was not deleted"
    );
}
