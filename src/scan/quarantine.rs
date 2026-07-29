//! Where an unredacted original lives, and the one derivation every writer uses.
//!
//! **Quarantine mirrors the archive**: `quarantine/<X>` holds the unredacted
//! original of `archive/<X>.zst`. The path is the artifact's archive-relative
//! stored path with the compression suffix removed, and nothing else.
//!
//! An original is named by the identity of the artifact it is the original *of*,
//! so it inherits the store's uniqueness and its losslessness instead of
//! restating them. Before this rule three call sites each built a path their own
//! way: a scratch original was keyed by the lossy display name (two non-UTF-8
//! names collided at `U+FFFD` and one original overwrote the other — in the one
//! place the lost object has no other copy), the scratch key appeared twice, and
//! archive and rescan disagreed about how much of the path the `<uuid>` level
//! had already consumed.

use anyhow::{Context, Result};
use rustix::fs::{Mode, OFlags};
use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

/// Every directory yomi creates under `quarantine/`, and every original in it.
const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

/// The quarantine-relative path of the artifact stored at `stored_rel`, which is
/// that artifact's path relative to `archive/`.
///
/// Injective by construction, which is the whole point. A *compressed*
/// artifact's store path is its logical path with exactly one `.zst` appended,
/// so removing that suffix is the inverse of the map that added it; the only
/// *uncompressed* artifacts are subagent metas, whose names end `.meta.json` and
/// are therefore disjoint from the stripped set. Two originals can no longer
/// land on one path.
pub fn quarantine_rel(stored_rel: &Path) -> PathBuf {
    sanitize_rel(&strip_zst(stored_rel))
}

/// Drop one trailing `.zst`, on the raw bytes of the final component so a
/// non-UTF-8 name survives intact.
fn strip_zst(path: &Path) -> PathBuf {
    let Some(name) = path.file_name() else {
        return path.to_path_buf();
    };
    match name.as_bytes().strip_suffix(b".zst") {
        Some(stem) => path.with_file_name(OsStr::from_bytes(stem)),
        None => path.to_path_buf(),
    }
}

/// Keep only ordinary components, so a path can never escape the quarantine
/// root. Takes a `Path`, not a `&str`: a scratch store path is derived from raw
/// `ScratchRel` bytes, and a `&str` here is exactly where those bytes were lost.
fn sanitize_rel(rel: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in rel.components() {
        if let Component::Normal(c) = comp {
            out.push(c);
        }
    }
    if out.as_os_str().is_empty() {
        out.push("original");
    }
    out
}

/// Write an unredacted secret-bearing original to its mirrored path under
/// `quarantine_root` (every directory 700, the file 600), index-excluded and
/// recoverable.
///
/// `stored_rel` is the artifact's archive-relative stored path.
///
/// **The hierarchy is descended fd by fd, never by path.** Each level is
/// `mkdirat`-ed, opened `O_DIRECTORY|O_NOFOLLOW` from its parent's fd, and
/// `fchmod`-ed through that fd; the original is opened `O_CREAT|O_NOFOLLOW` and
/// `fchmod`-ed the same way. `create_dir_all` and `set_permissions` both follow
/// symlinks, so building the tree by path let anything planted at a mirrored
/// level redirect **the raw secret itself** — and re-mode the link's target on
/// the way. The store has `classify_store_dir` for that class; quarantine had
/// nothing, and the object at stake here is the one copy of an unredacted
/// original. Descending from fds refuses instead, with no window between the
/// check and the use because there is no check: the kernel resolves one
/// component at a time and never traverses a link.
///
/// Any error means the original was **not** preserved. Every caller treats that
/// as a refusal to archive the artifact at all — see `Archiver::capture` and
/// `rescan::commit`.
pub fn quarantine_original(
    quarantine_root: &Path,
    stored_rel: &Path,
    original: &[u8],
) -> Result<PathBuf> {
    let rel = quarantine_rel(stored_rel);
    let dest = quarantine_root.join(&rel);

    // The root is created and opened **by path**, following whatever it is:
    // `quarantine/` is a documented part of the layout an operator may
    // legitimately relocate — an encrypted volume being the obvious case, since
    // decision #6 leaves at-rest encryption to P6 — and `ensure_layout` already
    // creates and chmods it through the same path. Everything below it is a
    // namespace yomi derives from the artifact's own identity, which no operator
    // has a reason to hand-place, so that is where following stops.
    std::fs::create_dir_all(quarantine_root)
        .with_context(|| format!("create quarantine dir {}", quarantine_root.display()))?;
    set_700(quarantine_root)?;
    let mut dir = open_root(quarantine_root)?;

    let mut walked = quarantine_root.to_path_buf();
    for comp in rel.parent().unwrap_or(Path::new("")).components() {
        walked.push(comp);
        dir = open_level(&dir, comp.as_os_str(), &walked)?;
    }

    let name = rel
        .file_name()
        .context("quarantine path has no final component")?;
    write_original(&dir, name, original, &dest)?;
    Ok(dest)
}

fn set_700(dir: &Path) -> Result<()> {
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(DIR_MODE))
        .with_context(|| format!("chmod {DIR_MODE:o} {}", dir.display()))
}

fn open_root(path: &Path) -> Result<File> {
    let flags = OFlags::DIRECTORY | OFlags::CLOEXEC;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits() as i32)
        .open(path)
        .with_context(|| format!("open quarantine dir {}", path.display()))
}

/// Create (if absent) and open one mirrored level under `parent`, refusing
/// anything that is not a real directory reached without traversing a link.
fn open_level(parent: &File, name: &OsStr, display: &Path) -> Result<File> {
    // `mkdirat`'s mode is masked by the umask, so the `fchmod` below is what
    // actually establishes 700 — `Archiver` is a library type a caller can use
    // without `ensure_layout` ever having tightened the umask, and inherited
    // modes are not something to rely on for a tree of raw secrets.
    if let Err(e) = rustix::fs::mkdirat(parent, name, Mode::from_bits_truncate(DIR_MODE))
        && e != rustix::io::Errno::EXIST
    {
        return Err(anyhow::Error::new(e))
            .with_context(|| format!("create quarantine dir {}", display.display()));
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let dir: File = rustix::fs::openat(parent, name, flags, Mode::empty())
        .map_err(|e| {
            anyhow::anyhow!(
                "refusing to write an unredacted original through {}: {e} — that level \
                 could not be opened as a directory without following a link",
                display.display()
            )
        })?
        .into();
    rustix::fs::fchmod(&dir, Mode::from_bits_truncate(DIR_MODE))
        .with_context(|| format!("chmod {DIR_MODE:o} {}", display.display()))?;
    Ok(dir)
}

fn write_original(dir: &File, name: &OsStr, original: &[u8], display: &Path) -> Result<()> {
    let flags =
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut file: File = rustix::fs::openat(dir, name, flags, Mode::from_bits_truncate(FILE_MODE))
        .map_err(|e| {
            anyhow::anyhow!(
                "refusing to write an unredacted original to {}: {e}",
                display.display()
            )
        })?
        .into();
    // Before the bytes, not after: `O_CREAT`'s mode is masked by the umask, and
    // an already-existing file keeps the mode it had, so a permissive one would
    // otherwise hold a raw secret for the length of the write.
    rustix::fs::fchmod(&file, Mode::from_bits_truncate(FILE_MODE))
        .with_context(|| format!("chmod {FILE_MODE:o} {}", display.display()))?;
    file.write_all(original)
        .with_context(|| format!("write quarantine file {}", display.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    fn q(stored: &[u8]) -> Vec<u8> {
        quarantine_rel(Path::new(&OsString::from_vec(stored.to_vec())))
            .into_os_string()
            .into_vec()
    }

    /// The mirror rule, for each artifact shape the store holds.
    #[test]
    fn quarantine_path_mirrors_the_store_path() {
        assert_eq!(
            q(b"-home-test/uuid-1/transcript.jsonl.zst"),
            b"-home-test/uuid-1/transcript.jsonl"
        );
        // Uncompressed: subagent metas keep their name verbatim.
        assert_eq!(
            q(b"-home-test/uuid-1/subagents/x.meta.json"),
            b"-home-test/uuid-1/subagents/x.meta.json"
        );
        assert_eq!(
            q(b"_scratch/-home-test--uuid-1/scratchpad/a.md.zst"),
            b"_scratch/-home-test--uuid-1/scratchpad/a.md"
        );
    }

    /// The defect this rule exists to end: two non-UTF-8 names that share a
    /// lossy form must not share a quarantine path. Their store paths differ, so
    /// their quarantine paths do — provided the bytes are carried as a path.
    #[test]
    fn lossy_colliding_names_keep_distinct_quarantine_paths() {
        let a = q(b"_scratch/K/scratchpad/note-\xff.md.zst");
        let b = q(b"_scratch/K/scratchpad/note-\xfe.md.zst");
        assert_eq!(a, b"_scratch/K/scratchpad/note-\xff.md");
        assert_ne!(a, b, "two originals landed on one quarantine path");
    }

    /// Stripping the suffix must not merge a compressed artifact onto an
    /// uncompressed one: only `.zst` is removed, and only once.
    #[test]
    fn only_one_zst_suffix_is_removed() {
        assert_eq!(q(b"a/b.zst.zst"), b"a/b.zst");
        assert_eq!(q(b"a/b.json"), b"a/b.json");
        assert_eq!(q(b"a/b.zstx"), b"a/b.zstx");
        assert_eq!(q(b"a/zst"), b"a/zst");
    }

    /// Nothing a manifest could carry may escape the root.
    #[test]
    fn traversal_components_are_dropped() {
        assert_eq!(q(b"../../etc/passwd"), b"etc/passwd");
        assert_eq!(q(b"/etc/passwd"), b"etc/passwd");
        assert_eq!(q(b"a/../../b.zst"), b"a/b");
        assert_eq!(q(b".."), b"original");
        assert_eq!(q(b""), b"original");
    }
}
