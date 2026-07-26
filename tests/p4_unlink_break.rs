//! P4 break tests: adversarial assault on the physical delete primitive
//! (`gc::safety::safe_unlink`) and the single-writer lock (`lock::WriteLock`)
//! after the libc -> rustix / fs2 -> std migration (#4, c1a8f73).
//!
//! These are written to BREAK, not to confirm. Every fixture is fabricated in a
//! tmpdir; nothing touches real Claude Code data.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use yomi::gc::safety::safe_unlink;
use yomi::lock::WriteLock;

fn tmp(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("yomi-p4u-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn pin(path: &Path) -> (u64, u64) {
    let md = std::fs::metadata(path).unwrap();
    (md.dev(), md.ino())
}

fn lpin(path: &Path) -> (u64, u64) {
    let md = std::fs::symlink_metadata(path).unwrap();
    (md.dev(), md.ino())
}

fn is_root() -> bool {
    std::fs::metadata("/").map(|m| m.uid()).unwrap_or(1) == 0
        && std::fs::File::create("/.yomi-root-probe")
            .map(|_| {
                let _ = std::fs::remove_file("/.yomi-root-probe");
                true
            })
            .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// A. rustix statat (dev,ino) must agree with std::fs::metadata (dev,ino).
//    If rustix's statx->makedev encoding disagreed with glibc's stat encoding,
//    `safe_unlink` would silently refuse EVERY delete (fail-closed but broken).
//    Exercised behaviourally through the production path, across every
//    filesystem we can reach, so a differing dev encoding cannot hide.
// ---------------------------------------------------------------------------

#[test]
fn p4u_pin_encoding_agrees_across_filesystems() {
    let mut bases: Vec<PathBuf> = vec![tmp("fs-tmp")];
    // A second filesystem, if one is mounted, to exercise a distinct dev
    // major/minor pair through the rustix statx -> makedev path.
    for cand in ["/dev/shm", "."] {
        let p = Path::new(cand);
        if !p.is_dir() {
            continue;
        }
        let d = p.join(format!("yomi-p4u-fs-{}", std::process::id()));
        if std::fs::create_dir_all(&d).is_ok() {
            bases.push(d);
        }
    }

    let mut seen_devs = std::collections::HashSet::new();
    for base in &bases {
        let f = base.join("victim.bin");
        std::fs::write(&f, b"payload").unwrap();
        let p = pin(&f);
        seen_devs.insert(p.0);
        assert!(
            safe_unlink(&f, p).unwrap(),
            "safe_unlink refused a correctly-pinned file on {} \
             (dev={} ino={}): rustix statat dev/ino does not agree with \
             std::fs::metadata on this filesystem",
            base.display(),
            p.0,
            p.1
        );
        assert!(!f.exists(), "file survived a successful safe_unlink");
        let _ = std::fs::remove_dir_all(base);
    }
    assert!(!seen_devs.is_empty());
}

#[test]
fn p4u_pin_mismatch_by_one_refuses() {
    let base = tmp("pin-off");
    let f = base.join("a");
    std::fs::write(&f, b"x").unwrap();
    let (dev, ino) = pin(&f);

    assert!(
        !safe_unlink(&f, (dev, ino.wrapping_add(1))).unwrap(),
        "wrong inode was accepted"
    );
    assert!(
        !safe_unlink(&f, (dev.wrapping_add(1), ino)).unwrap(),
        "wrong device was accepted"
    );
    assert!(f.exists(), "file deleted despite a mismatched pin");
    assert!(safe_unlink(&f, (dev, ino)).unwrap());
}

// ---------------------------------------------------------------------------
// B. TOCTOU: swap the name to a different inode between gate and unlink.
// ---------------------------------------------------------------------------

#[test]
fn p4u_toctou_same_name_new_inode_is_refused() {
    let base = tmp("toctou-swap");
    let f = base.join("transcript.jsonl");
    std::fs::write(&f, b"original\n").unwrap();
    let stale = pin(&f);

    // Attacker replaces the entry with a *different* inode under the same name.
    std::fs::remove_file(&f).unwrap();
    std::fs::write(&f, b"attacker\n").unwrap();
    let fresh = pin(&f);
    assert_ne!(
        stale, fresh,
        "inode was reused; retry-resistant setup failed"
    );

    assert!(
        !safe_unlink(&f, stale).unwrap(),
        "same-name/new-inode swap was deleted — inode pin is not effective"
    );
    assert_eq!(std::fs::read(&f).unwrap(), b"attacker\n");
}

#[test]
fn p4u_symlink_planted_at_name_is_refused_nofollow() {
    let base = tmp("nofollow");
    let secret = base.join("secret");
    std::fs::write(&secret, b"credential\n").unwrap();
    let secret_pin = pin(&secret);

    let link = base.join("victim");
    std::os::unix::fs::symlink(&secret, &link).unwrap();

    // Pin is the TARGET's inode. With AT_SYMLINK_NOFOLLOW the statat sees the
    // symlink's own inode, so this must refuse. Without NOFOLLOW it would match
    // and unlink the link node.
    assert!(
        !safe_unlink(&link, secret_pin).unwrap(),
        "SYMLINK_NOFOLLOW is not effective: statat resolved through the symlink"
    );
    assert!(secret.exists(), "symlink target was destroyed");
    assert!(
        std::fs::symlink_metadata(&link).is_ok(),
        "symlink node was destroyed"
    );

    // Pinning the symlink's *own* inode does delete it, and only it.
    assert!(safe_unlink(&link, lpin(&link)).unwrap());
    assert!(std::fs::symlink_metadata(&link).is_err());
    assert!(
        secret.exists(),
        "unlinkat followed the symlink to its target"
    );
}

#[test]
fn p4u_symlinked_final_parent_component_is_refused() {
    let base = tmp("parent-link");
    let real = base.join("real");
    std::fs::create_dir_all(&real).unwrap();
    let victim = real.join("f");
    std::fs::write(&victim, b"v").unwrap();
    let p = pin(&victim);

    let linked_parent = base.join("aliased");
    std::os::unix::fs::symlink(&real, &linked_parent).unwrap();

    // parent() == ".../aliased", a symlink. O_DIRECTORY|O_NOFOLLOW must fail.
    assert!(
        !safe_unlink(&linked_parent.join("f"), p).unwrap(),
        "O_NOFOLLOW on the parent open is not effective"
    );
    assert!(victim.exists(), "file deleted through a symlinked parent");
}

/// Documents the residual: `O_NOFOLLOW` guards only the LAST component of the
/// parent path. An intermediate symlink is still traversed, so a swap of any
/// non-final component redirects the unlink. Containment therefore cannot rest
/// on `safe_unlink` alone — it rests on `gc::under_allowed`, which runs at plan
/// time only (see p4_toctou_break.rs).
#[test]
fn p4u_intermediate_symlink_component_is_traversed() {
    let base = tmp("mid-link");
    let outside = base.join("outside");
    std::fs::create_dir_all(outside.join("sub")).unwrap();
    let victim = outside.join("sub/f");
    std::fs::write(&victim, b"v").unwrap();
    let p = pin(&victim);

    let hop = base.join("hop");
    std::os::unix::fs::symlink(&outside, &hop).unwrap();

    // path = base/hop/sub/f ; parent = base/hop/sub (a real dir reached THROUGH
    // the symlink `hop`). O_NOFOLLOW does not apply to `hop`.
    let deleted = safe_unlink(&hop.join("sub/f"), p).unwrap();
    assert!(
        deleted,
        "expected intermediate-symlink traversal; if this now refuses, \
         safe_unlink hardened and this documentation test needs updating"
    );
    assert!(
        !victim.exists(),
        "inconsistent: reported deleted but target survives"
    );
}

// ---------------------------------------------------------------------------
// C. Wrong-kind targets. AtFlags::empty() on unlinkat must never remove a dir.
// ---------------------------------------------------------------------------

#[test]
fn p4u_directory_target_is_never_removed() {
    let base = tmp("dir-target");
    let d = base.join("a-dir");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("child"), b"c").unwrap();
    let p = pin(&d);

    // Inode matches (it is the dir), so the pin gate passes and unlinkat runs
    // with AtFlags::empty(). It must fail (EISDIR/EPERM), never rmdir.
    let r = safe_unlink(&d, p);
    match r {
        Ok(true) => {
            panic!("safe_unlink removed a DIRECTORY — AtFlags::empty() is not AT_REMOVEDIR?")
        }
        Ok(false) => panic!("unexpected: pin should have matched the directory"),
        Err(_) => {}
    }
    assert!(d.is_dir(), "directory disappeared");
    assert!(d.join("child").exists());
}

#[test]
fn p4u_fifo_and_empty_file_boundaries() {
    let base = tmp("kinds");
    let empty = base.join("empty");
    std::fs::write(&empty, b"").unwrap();
    assert_eq!(std::fs::metadata(&empty).unwrap().len(), 0);
    assert!(
        safe_unlink(&empty, pin(&empty)).unwrap(),
        "empty file refused"
    );
    assert!(!empty.exists());

    // Deep nesting: 40 levels.
    let mut deep = base.join("deep");
    for i in 0..40 {
        deep = deep.join(format!("l{i}"));
    }
    std::fs::create_dir_all(&deep).unwrap();
    let f = deep.join("leaf");
    std::fs::write(&f, b"z").unwrap();
    assert!(
        safe_unlink(&f, pin(&f)).unwrap(),
        "deeply nested file refused"
    );
    assert!(!f.exists());
}

#[test]
fn p4u_hardlink_alias_shares_the_pin() {
    let base = tmp("hardlink");
    let a = base.join("a");
    std::fs::write(&a, b"data").unwrap();
    let b = base.join("b");
    std::fs::hard_link(&a, &b).unwrap();
    assert_eq!(pin(&a), pin(&b));

    // The pin is (dev,ino), so ANY link to that inode satisfies it. Deleting
    // via `b` with a pin taken from `a` succeeds. Production always passes the
    // same path it pinned, so this is a documented granularity limit, not a
    // reachable escape.
    assert!(safe_unlink(&b, pin(&a)).unwrap());
    assert!(!b.exists());
    assert!(a.exists(), "sibling hardlink was destroyed");
    assert_eq!(std::fs::read(&a).unwrap(), b"data");
}

#[test]
fn p4u_many_hardlinks_only_named_link_goes() {
    let base = tmp("many-links");
    let a = base.join("orig");
    std::fs::write(&a, b"d").unwrap();
    let links: Vec<PathBuf> = (0..64).map(|i| base.join(format!("l{i}"))).collect();
    for l in &links {
        std::fs::hard_link(&a, l).unwrap();
    }
    assert_eq!(std::fs::metadata(&a).unwrap().nlink(), 65);
    assert!(safe_unlink(&links[0], pin(&a)).unwrap());
    assert_eq!(std::fs::metadata(&a).unwrap().nlink(), 64);
    for l in &links[1..] {
        assert!(l.exists());
    }
}

// ---------------------------------------------------------------------------
// D. Malformed / hostile paths. The old libc path built a CString and
//    propagated `Err` on an interior NUL; the rustix path must not panic.
// ---------------------------------------------------------------------------

#[test]
fn p4u_non_utf8_filename_roundtrips() {
    let base = tmp("nonutf8");
    // Invalid UTF-8 (lone continuation byte + a raw 0xff).
    let name = OsStr::from_bytes(b"bad-\xff\x80-name.jsonl");
    let f = base.join(name);
    std::fs::write(&f, b"x").unwrap();
    assert!(f.to_str().is_none(), "fixture is not actually non-UTF-8");

    assert!(
        safe_unlink(&f, pin(&f)).unwrap(),
        "non-UTF-8 filename was refused: rustix Arg conversion is lossy here"
    );
    assert!(std::fs::symlink_metadata(&f).is_err());
}

#[test]
fn p4u_interior_nul_in_filename_does_not_panic() {
    let base = tmp("nul");
    let f = base.join(OsStr::from_bytes(b"a\0b"));
    // Cannot exist on disk; only the error path matters.
    let r = safe_unlink(&f, (1, 1));
    assert!(
        matches!(r, Ok(false)) || r.is_err(),
        "interior NUL produced an unexpected success"
    );
}

#[test]
fn p4u_enametoolong_and_degenerate_paths_are_inert() {
    let base = tmp("degenerate");
    let long = base.join("n".repeat(4096));
    assert!(
        !safe_unlink(&long, (1, 1)).unwrap(),
        "ENAMETOOLONG deleted something"
    );

    for p in ["/", "", ".", "..", "/////"] {
        let r = safe_unlink(Path::new(p), (1, 1));
        assert!(
            matches!(r, Ok(false)) || r.is_err(),
            "degenerate path {p:?} produced Ok(true)"
        );
    }
    // Documented divergence from POSIX: `unlink("regular_file/")` is ENOTDIR at
    // the syscall level, but `Path::file_name()` strips the trailing slash, so
    // safe_unlink deletes the file. The inode pin still holds, so the correct
    // inode is removed — cosmetic, and identical to the pre-#4 libc path.
    let f = base.join("real");
    std::fs::write(&f, b"x").unwrap();
    let slashed = PathBuf::from(format!("{}/", f.display()));
    assert!(
        safe_unlink(&slashed, pin(&f)).unwrap(),
        "trailing-slash behaviour changed; re-check the POSIX divergence note"
    );
    assert!(!f.exists());
}

#[test]
fn p4u_symlink_loop_parent_is_refused() {
    let base = tmp("eloop");
    let a = base.join("la");
    let b = base.join("lb");
    std::os::unix::fs::symlink(&b, &a).unwrap();
    std::os::unix::fs::symlink(&a, &b).unwrap();
    assert!(
        !safe_unlink(&a.join("f"), (1, 1)).unwrap(),
        "ELOOP parent did not refuse"
    );
}

#[test]
fn p4u_vanished_parent_directory_is_refused() {
    let base = tmp("gone-parent");
    let d = base.join("d");
    std::fs::create_dir_all(&d).unwrap();
    let f = d.join("f");
    std::fs::write(&f, b"x").unwrap();
    let p = pin(&f);
    std::fs::remove_file(&f).unwrap();
    std::fs::remove_dir(&d).unwrap();
    assert!(
        !safe_unlink(&f, p).unwrap(),
        "vanished parent did not refuse"
    );
}

// ---------------------------------------------------------------------------
// E. Fault injection on the unlink itself.
// ---------------------------------------------------------------------------

#[test]
fn p4u_readonly_parent_surfaces_error_not_silent_false() {
    if is_root() {
        return; // root ignores directory write permission
    }
    let base = tmp("ro-parent");
    let d = base.join("locked");
    std::fs::create_dir_all(&d).unwrap();
    let f = d.join("f");
    std::fs::write(&f, b"x").unwrap();
    let p = pin(&f);
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o555)).unwrap();

    let r = safe_unlink(&f, p);
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(
        r.is_err(),
        "EACCES on unlinkat was swallowed as Ok({:?}) — a failed delete would be \
         reported as a completed one",
        r.ok()
    );
    assert!(f.exists(), "file was deleted from a read-only directory");
}

#[test]
fn p4u_unsearchable_parent_is_refused() {
    if is_root() {
        return;
    }
    let base = tmp("noexec-parent");
    let d = base.join("d");
    std::fs::create_dir_all(&d).unwrap();
    let f = d.join("f");
    std::fs::write(&f, b"x").unwrap();
    let p = pin(&f);
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o000)).unwrap();

    let r = safe_unlink(&f, p);
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        matches!(r, Ok(false)),
        "EACCES parent open did not refuse: {r:?}"
    );
    assert!(f.exists());
}

/// Race 8 threads onto one pinned inode. Exactly one may report a delete —
/// a second `Ok(true)` would mean `gc::commit` could double-count a reclaim.
fn race_round(base: &Path, round: usize) -> (usize, Vec<String>) {
    let f = base.join(format!("f{round}"));
    std::fs::write(&f, b"x").unwrap();
    let p = pin(&f);
    let mut handles = Vec::new();
    for _ in 0..8 {
        let f = f.clone();
        handles.push(std::thread::spawn(move || safe_unlink(&f, p)));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let successes = results.iter().filter(|r| matches!(r, Ok(true))).count();
    let errors = results
        .iter()
        .filter_map(|r| r.as_ref().err().map(|e| e.to_string()))
        .collect();
    assert!(!f.exists());
    (successes, errors)
}

#[test]
fn p4u_concurrent_racers_delete_exactly_once() {
    let base = tmp("race-once");
    for round in 0..64 {
        let (successes, errors) = race_round(&base, round);
        assert_eq!(
            successes, 1,
            "round {round}: {successes} racers each reported a successful delete of \
             the same inode (errors: {errors:?})"
        );
    }
}

/// A racer that loses the statat->unlinkat window gets `ENOENT` from `unlinkat`,
/// which `safe_unlink` turns into `Err`. `gc::commit` propagates that with `?`,
/// so one file vanishing mid-run (a concurrent Claude Code write, log rotation,
/// or a second yomi that slipped past the lock) ABORTS the whole GC pass and
/// leaves every later candidate unprocessed. A vanished entry is the delete
/// already having happened — it must be `Ok(false)`, not an error.
#[test]
fn p4u_concurrent_racer_enoent_must_refuse_not_error() {
    let base = tmp("race-enoent");
    let mut all = Vec::new();
    for round in 0..64 {
        let (_, errors) = race_round(&base, round);
        all.extend(errors);
    }
    assert!(
        all.is_empty(),
        "{} losing racers returned Err instead of Ok(false); gc::commit \
         propagates this and aborts the run. Samples: {:?}",
        all.len(),
        &all[..all.len().min(3)]
    );
}

// ---------------------------------------------------------------------------
// F. WriteLock (std::fs::File::try_lock after dropping fs2).
// ---------------------------------------------------------------------------

#[test]
fn p4l_second_holder_in_same_process_is_refused() {
    let base = tmp("lock-basic");
    let lp = base.join(".yomi.lock");
    let first = WriteLock::acquire(&lp).expect("first acquire");
    let second = WriteLock::acquire(&lp);
    assert!(
        second.is_err(),
        "try_lock granted a SECOND exclusive lock on the same path in one \
         process — mutual exclusion is fail-open"
    );
    let msg = match second {
        Ok(_) => unreachable!(),
        Err(e) => e.to_string(),
    };
    assert!(
        msg.contains("another yomi process"),
        "contention did not produce the contention message: {msg}"
    );
    drop(first);
    WriteLock::acquire(&lp).expect("lock not released on drop");
}

#[test]
fn p4l_threads_contend_correctly() {
    let base = tmp("lock-threads");
    let lp = base.join(".yomi.lock");
    let held = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let peak = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut hs = Vec::new();
    for _ in 0..16 {
        let lp = lp.clone();
        let held = held.clone();
        let peak = peak.clone();
        hs.push(std::thread::spawn(move || {
            for _ in 0..40 {
                if let Ok(l) = WriteLock::acquire(&lp) {
                    let n = held.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(n, Ordering::SeqCst);
                    std::thread::yield_now();
                    held.fetch_sub(1, Ordering::SeqCst);
                    drop(l);
                }
            }
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    assert_eq!(
        peak.load(Ordering::SeqCst),
        1,
        "two threads held the write lock simultaneously"
    );
}

/// `WriteLock::acquire` collapses every `try_lock` failure into "another yomi
/// process holds the write lock". An `open` failure is at least distinguishable
/// (different message + no lock granted); a genuine flock I/O error would be
/// misreported but still refuses, so the lock is fail-CLOSED.
#[test]
fn p4l_open_failure_refuses_and_is_distinguishable() {
    let base = tmp("lock-open-fail");
    let lp = base.join(".yomi.lock");
    std::fs::create_dir_all(&lp).unwrap(); // lock path is a directory
    let msg = match WriteLock::acquire(&lp) {
        Ok(_) => panic!("acquiring the write lock on a directory succeeded"),
        Err(e) => format!("{e:#}"),
    };
    assert!(msg.contains("open lock file"), "unexpected message: {msg}");
    assert!(
        !msg.contains("another yomi process"),
        "an open failure is reported as lock contention: {msg}"
    );
}

/// `File::create` on the lock path TRUNCATES and FOLLOWS symlinks. A `.yomi.lock`
/// symlinked at any other file destroys that file the moment any write command
/// runs. Pre-existing (fs2 did the same), unchanged by #4.
#[test]
fn p4l_lock_path_symlink_truncates_its_target() {
    let base = tmp("lock-symlink");
    let victim = base.join("catalog.db");
    std::fs::write(&victim, b"SQLite format 3\0IMPORTANT-DATA").unwrap();
    let lp = base.join(".yomi.lock");
    std::os::unix::fs::symlink(&victim, &lp).unwrap();

    let _l = WriteLock::acquire(&lp).expect("acquire through symlink");
    let after = std::fs::read(&victim).unwrap();
    assert!(
        !after.is_empty(),
        "WriteLock::acquire truncated {} to zero bytes via a symlinked lock path \
         (File::create follows symlinks and applies O_TRUNC)",
        victim.display()
    );
}

/// Classic flock weakness: the lock lives on the INODE, not the name. Unlink the
/// lock file and a second acquirer creates a fresh inode and succeeds — two
/// holders at once. Pre-existing (fs2 had the same shape), unchanged by #4.
#[test]
fn p4l_unlinked_lock_file_admits_a_second_holder() {
    let base = tmp("lock-unlink");
    let lp = base.join(".yomi.lock");
    let _first = WriteLock::acquire(&lp).expect("first acquire");
    std::fs::remove_file(&lp).unwrap();
    let second = WriteLock::acquire(&lp);
    assert!(
        second.is_err(),
        "after the lock file was unlinked a SECOND writer acquired the lock — \
         mutual exclusion is defeated by removing {}",
        lp.display()
    );
}
