use anyhow::{Context, Result, bail};
use std::fs::{File, OpenOptions, TryLockError};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Advisory single-writer lock held for the duration of a mutating command.
/// Released when dropped (process exit or scope end).
///
/// Two anchors are locked, not one: the lock file, and the store directory that
/// holds it. `flock` attaches to the inode, never to the name, so a lock held
/// only on `.yomi.lock` is defeated by removing that name — the next acquirer
/// creates a fresh inode, locks that, and runs alongside the first holder. The
/// directory outlives such a removal, so it carries the mutual exclusion; the
/// lock file remains the named, inspectable artifact and the first contention
/// check.
///
/// The directory anchor buys unlink resistance, **not** rename resistance:
/// `mv ~/.yomi ~/.yomi.bak && mkdir ~/.yomi` still admits a second holder, which
/// locks the new directory's inode while the first holder keeps writing through
/// the same name.
///
/// This is a robustness measure, not a security boundary. The lock is advisory —
/// a process that never calls `flock` is unaffected — and any principal that can
/// write inside the mode-700 store can corrupt `catalog.db` directly. What the
/// directory anchor actually prevents is accidents: a hand-removed lock file, a
/// stale-lock cleanup habit, an interrupted `rm -rf ~/.yomi/*`, a restore that
/// leaves the lock file out.
pub struct WriteLock {
    _file: File,
    _dir: File,
}

impl WriteLock {
    /// Acquire an exclusive advisory lock on `path`. Fails fast (does not
    /// block) if another yomi process holds it.
    pub fn acquire(path: &Path) -> Result<Self> {
        let file =
            open_lock_file(path).with_context(|| format!("open lock file {}", path.display()))?;
        let dir_path = store_dir_of(path);
        let dir = File::open(dir_path)
            .with_context(|| format!("open store directory {}", dir_path.display()))?;
        lock_exclusive(&file, Anchor::LockFile(path))?;
        lock_exclusive(&dir, Anchor::StoreDir(dir_path))?;
        Ok(WriteLock {
            _file: file,
            _dir: dir,
        })
    }
}

/// The directory holding the lock file. `parent()` yields `None` only for a root
/// path, but an empty `Some("")` for a single-component relative path — which is
/// what a store configured as `YOMI_HOME=` produces. Both mean "the working
/// directory", and `File::open("")` is `ENOENT`.
fn store_dir_of(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// Which of the two anchors a `flock` was attempted on. Contention on the
/// directory must not be reported against the lock file: in the case the
/// directory anchor exists for, that file has just been deleted, and naming it
/// sends the operator looking for something that is not there.
enum Anchor<'a> {
    LockFile(&'a Path),
    StoreDir(&'a Path),
}

/// Open (or create) the lock file without following a symlink and without
/// truncating. `File::create` did both, so a `.yomi.lock` symlinked at the
/// catalog wiped the catalog the next time any write command ran. The lock file
/// carries no content, so a symlink there is never legitimate state: the link
/// node itself is removed — never its target — and a real file takes its place.
fn open_lock_file(path: &Path) -> std::io::Result<File> {
    match open_nofollow(path, false) {
        Err(e) if e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) => {
            // Re-confirm it is still a symlink before unlinking, so the only
            // thing this can ever remove is a link node.
            if !std::fs::symlink_metadata(path)?.file_type().is_symlink() {
                return Err(e);
            }
            tracing::warn!(
                path = %path.display(),
                "lock path is a symlink; replacing the link with a regular lock file"
            );
            std::fs::remove_file(path)?;
            open_nofollow(path, true)
        }
        other => other,
    }
}

fn open_nofollow(path: &Path, exclusive: bool) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(!exclusive)
        .create_new(exclusive)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
}

/// `WouldBlock` is contention — another yomi is running. `Error` is the lock
/// itself failing, which on a mount without `flock` support (some NFS, FUSE and
/// older CIFS) is permanent: reporting it as contention sends the operator
/// hunting for a competing process that does not exist.
fn lock_exclusive(f: &File, anchor: Anchor<'_>) -> Result<()> {
    match (f.try_lock(), anchor) {
        (Ok(()), _) => Ok(()),
        (Err(TryLockError::WouldBlock), Anchor::LockFile(p)) => bail!(
            "refuse: another yomi process holds the write lock ({})",
            p.display()
        ),
        (Err(TryLockError::WouldBlock), Anchor::StoreDir(d)) => bail!(
            "refuse: another yomi process holds the write lock on the store ({})",
            d.display()
        ),
        (Err(TryLockError::Error(e)), Anchor::LockFile(p)) => bail!(
            "refuse: cannot take the write lock ({}): {e}; the store may sit on a \
             filesystem that does not support flock — move it with --home or YOMI_HOME",
            p.display()
        ),
        (Err(TryLockError::Error(e)), Anchor::StoreDir(d)) => bail!(
            "refuse: cannot lock the store directory ({}): {e}; this filesystem may \
             support flock on files but not on directories — move the store with \
             --home or YOMI_HOME",
            d.display()
        ),
    }
}
