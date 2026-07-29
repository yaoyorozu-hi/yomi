//! Writes that a symlink cannot redirect.
//!
//! Every path in this store is built by joining names yomi derives itself, and
//! for a long time that was treated as enough. It is not: `create_dir_all`,
//! `std::fs::write`, `std::fs::rename` and `set_permissions` all resolve the
//! whole path at each call and all follow symlinks, so anything planted at an
//! intermediate level redirects the write — and re-modes the link's target on the
//! way. The store's bytes are post-redaction, which lowers the stakes against
//! `quarantine/`; it does not change the shape of the defect, and two writers in
//! one codebase that answer the same attack differently is itself the problem.
//!
//! **The fix is not a check.** A `symlink_metadata` before the write leaves a
//! window between the check and the use, which is the residual every guard in
//! this design has had to state and accept. Descending from a directory *file
//! descriptor* has no window because there is nothing to check: each component is
//! opened from its parent's fd with `O_NOFOLLOW`, so the kernel resolves one name
//! at a time and never traverses a link. A path that is not what this run reached
//! is not a path this run can be made to write through.
//!
//! Ownership of a mode belongs to whoever creates the object: `mkdirat` and
//! `O_CREAT` both mask their mode with the umask, and an *existing* file keeps
//! the mode it already had, so every level and every file is `fchmod`-ed through
//! its own descriptor. `Archiver` is a library type a caller can use without
//! `ensure_layout` ever having tightened the umask.

use anyhow::{Context, Result, bail};
use rustix::fs::{AtFlags, Mode, OFlags};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

/// Directories yomi creates inside the store.
pub const DIR_MODE: u32 = 0o700;
/// Files yomi writes inside the store.
pub const FILE_MODE: u32 = 0o600;

/// A directory this run reached without ever traversing a symlink.
///
/// Holding one is the proof: it cannot be constructed except by opening a root
/// by path — which the caller vouches for — or by descending one `O_NOFOLLOW`
/// component from another `Dir`.
pub struct Dir {
    fd: File,
    at: PathBuf,
}

impl Dir {
    /// Open `root` **by path**, following whatever it is.
    ///
    /// The root is where the caller's vouching stops and this module's begins.
    /// `archive/` and `quarantine/` are documented parts of the layout an
    /// operator may legitimately relocate — a store on another volume is the
    /// obvious case — and `ensure_layout` asserts and creates them through the
    /// same path on every mutating run. Everything *below* a root is a namespace
    /// yomi derives from an artifact's own identity, which no operator has a
    /// reason to hand-place, so that is where following stops.
    pub fn open_root(root: &Path) -> Result<Self> {
        let flags = OFlags::DIRECTORY | OFlags::CLOEXEC;
        let fd = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags.bits() as i32)
            .open(root)
            .with_context(|| format!("open store dir {}", root.display()))?;
        Ok(Dir {
            fd,
            at: root.to_path_buf(),
        })
    }

    /// The path this directory was reached by, for messages only. Never used to
    /// re-open anything.
    pub fn path(&self) -> &Path {
        &self.at
    }

    /// Create if absent, then open and mode one component below this directory.
    pub fn child(&self, name: &OsStr, mode: u32) -> Result<Dir> {
        let at = self.at.join(name);
        if let Err(e) = rustix::fs::mkdirat(&self.fd, name, Mode::from_bits_truncate(mode))
            && e != rustix::io::Errno::EXIST
        {
            return Err(anyhow::Error::new(e))
                .with_context(|| format!("create store dir {}", at.display()));
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd: File = rustix::fs::openat(&self.fd, name, flags, Mode::empty())
            .map_err(|e| {
                anyhow::anyhow!(
                    "refusing to write through {}: {e} — that level could not be \
                     opened as a directory without following a link",
                    at.display()
                )
            })?
            .into();
        rustix::fs::fchmod(&fd, Mode::from_bits_truncate(mode))
            .with_context(|| format!("chmod {mode:o} {}", at.display()))?;
        Ok(Dir { fd, at })
    }

    /// Descend every component of `rel`, creating what is absent.
    ///
    /// Only ordinary components are accepted. A `..` or a root in a store path is
    /// a bug in the caller, not input to sanitize: dropping it would write
    /// somewhere other than where the caller asked, which is the failure this
    /// module exists to prevent.
    pub fn descend(self, rel: &Path, mode: u32) -> Result<Dir> {
        let mut dir = self;
        for comp in rel.components() {
            let Component::Normal(name) = comp else {
                bail!(
                    "refuse: {} is not a plain relative path inside the store",
                    rel.display()
                );
            };
            dir = dir.child(name, mode)?;
        }
        Ok(dir)
    }

    /// Replace `name` with `bytes`: written to a temp sibling, moded, then
    /// `renameat`-ed into place.
    ///
    /// Crash safety is unchanged from the path-based version it replaces — the
    /// rename is still same-directory and still atomic — and the mode is now
    /// established *before* the bytes are reachable under the final name rather
    /// than after, so there is no window in which the artifact exists at the
    /// umask's mode.
    pub fn write_atomic(&self, name: &OsStr, bytes: &[u8], mode: u32) -> Result<()> {
        self.stage(name, bytes, mode)?.commit()
    }

    /// Write `bytes` to a temp sibling of `name`, to be committed or discarded
    /// later. Used where a write must be ordered against something else — the
    /// rescan swap lands only after its catalog transaction commits.
    pub fn stage(&self, name: &OsStr, bytes: &[u8], mode: u32) -> Result<Staged> {
        let tmp = temp_name(name);
        let at = self.at.join(&tmp);
        // `O_EXCL`: a temp name is ours alone, so anything already there — a file
        // or a link — is refused rather than followed or truncated.
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut file: File =
            rustix::fs::openat(&self.fd, &tmp, flags, Mode::from_bits_truncate(mode))
                .map_err(|e| anyhow::anyhow!("refusing to write {}: {e}", at.display()))?
                .into();
        rustix::fs::fchmod(&file, Mode::from_bits_truncate(mode))
            .with_context(|| format!("chmod {mode:o} {}", at.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write {}", at.display()))?;
        Ok(Staged {
            // A `dup` of the pinned descriptor, so a staged write can outlive the
            // borrow of the `Dir` that made it — the rescan swap has to survive
            // its catalog transaction — while still renaming through the same
            // directory this run reached, never through a path.
            dir: self.fd.try_clone().context("duplicate store dir handle")?,
            at: self.at.clone(),
            tmp,
            name: name.to_os_string(),
        })
    }

    /// Append to an existing file. `O_NOFOLLOW` so a link swapped in for the
    /// artifact cannot capture the frame.
    ///
    /// The mode is re-asserted as the path-based version did: an artifact stored
    /// before this rule existed keeps whatever mode it was given, and an append
    /// is the run that can correct it.
    pub fn append(&self, name: &OsStr, bytes: &[u8], mode: u32) -> Result<()> {
        let at = self.at.join(name);
        let flags = OFlags::WRONLY | OFlags::APPEND | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut file: File = rustix::fs::openat(&self.fd, name, flags, Mode::empty())
            .map_err(|e| anyhow::anyhow!("refusing to append to {}: {e}", at.display()))?
            .into();
        rustix::fs::fchmod(&file, Mode::from_bits_truncate(mode))
            .with_context(|| format!("chmod {mode:o} {}", at.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("append to {}", at.display()))
    }
}

/// Bytes written under a temp name, not yet visible at their own.
pub struct Staged {
    dir: File,
    at: PathBuf,
    tmp: OsString,
    name: OsString,
}

impl Staged {
    /// Move the staged bytes into place. `renameat` from and to the same pinned
    /// descriptor, so neither name is re-resolved through a path.
    pub fn commit(self) -> Result<()> {
        let r = rustix::fs::renameat(&self.dir, &self.tmp, &self.dir, &self.name);
        let out =
            r.with_context(|| format!("rename {} into place", self.at.join(&self.name).display()));
        if out.is_err() {
            self.discard();
        } else {
            std::mem::forget(self);
        }
        out
    }

    /// Remove the staged bytes. Also runs on drop, so an early return cannot
    /// leave a temp file behind for the reconciler to find.
    pub fn discard(&self) {
        let _ = rustix::fs::unlinkat(&self.dir, &self.tmp, AtFlags::empty());
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        self.discard();
    }
}

/// Write `bytes` at `rel` under `root`, creating the directories on the way.
pub fn write_under(root: &Path, rel: &Path, bytes: &[u8]) -> Result<()> {
    let (dirs, name) = split(rel)?;
    Dir::open_root(root)?
        .descend(&dirs, DIR_MODE)?
        .write_atomic(&name, bytes, FILE_MODE)
}

/// Append `bytes` to the file at `rel` under `root`.
pub fn append_under(root: &Path, rel: &Path, bytes: &[u8]) -> Result<()> {
    let (dirs, name) = split(rel)?;
    Dir::open_root(root)?
        .descend(&dirs, DIR_MODE)?
        .append(&name, bytes, FILE_MODE)
}

/// Create (and mode) every directory of `rel` under `root`.
pub fn make_dirs(root: &Path, rel: &Path) -> Result<Dir> {
    Dir::open_root(root)?.descend(rel, DIR_MODE)
}

/// Split a store-relative path into the directories to descend and the final
/// name.
pub fn split(rel: &Path) -> Result<(PathBuf, OsString)> {
    let name = rel
        .file_name()
        .with_context(|| format!("{} has no final component", rel.display()))?
        .to_os_string();
    Ok((rel.parent().unwrap_or(Path::new("")).to_path_buf(), name))
}

/// A temp sibling of `name`, unique within this process and across processes.
///
/// **Appended, never substituted for an extension.** `with_extension` turns
/// `a.md.zst` into `a.md.tmp-…`, which is a name a differently-suffixed artifact
/// could legitimately hold; appending cannot collide with any name the store
/// derives. Built on raw bytes so a non-UTF-8 scratch name keeps its identity.
fn temp_name(name: &OsStr) -> OsString {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let mut v = name.as_bytes().to_vec();
    v.extend_from_slice(
        format!(
            ".tmp-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        )
        .as_bytes(),
    );
    OsString::from_vec(v)
}
