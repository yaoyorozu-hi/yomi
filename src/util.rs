use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Current UTC time as an ISO-8601 / RFC-3339 string.
pub fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Lowercase hex sha256 of a byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex(&h.finalize())
}

/// First 8 hex chars of sha256 — an audit tag for a secret, never the secret.
pub fn sha8(bytes: &[u8]) -> String {
    sha256_hex(bytes)[..8].to_string()
}

/// Stream a reader through sha256 without holding the whole content in memory,
/// so the GC live-source re-hash bounds its footprint regardless of file size.
pub fn sha256_stream<R: std::io::Read>(reader: &mut R) -> std::io::Result<String> {
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decoder companion to [`hex`], for the manifest's `path_hex` field. `None` on
/// an odd length or any non-hex digit — a malformed value must refuse, never
/// decode to something plausible.
pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    b.chunks_exact(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

/// True only if `root` exists and is owned by the effective uid. A genuinely
/// absent root is benign (nothing to enumerate → proceed); a root owned by
/// another uid is a cross-user hazard and must block whatever the caller was
/// about to do with what is under it (須佐P2). Any *other* stat failure
/// (EACCES/ELOOP/EIO — e.g. a poisoned `YOMI_TMP_ROOT` symlink into a foreign
/// uid's mode-700 tree) is treated as not-owned and blocks: a root we cannot
/// prove we own is never enumerated (fail-closed). Ownership is read through
/// `metadata` (following symlinks), so a root symlinked at a foreign-owned tree
/// is caught by the target's real owner.
///
/// Lives here rather than beside either caller because there is one such rule and
/// it has two enforcement points — gc's candidate generation and archive's
/// scratch enumeration. A second implementation of it is the drift the store's
/// re-derived session dir already cost this codebase once.
pub fn root_owned_by_euid(root: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let euid = rustix::process::geteuid().as_raw();
    match std::fs::metadata(root) {
        Ok(md) => md.uid() == euid,
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    }
}

/// Resolve the user's home directory from `$HOME`.
pub fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("$HOME is not set")
}

/// Expand a leading `~` against `$HOME`.
pub fn expand_tilde(path: &str) -> Result<PathBuf> {
    if let Some(rest) = path.strip_prefix("~/") {
        Ok(home_dir()?.join(rest))
    } else if path == "~" {
        home_dir()
    } else {
        Ok(PathBuf::from(path))
    }
}

/// Absolute, symlink-resolved form of `path`, for comparing one path against
/// another — blacklist globs against their subjects, catalog keys against each
/// other.
///
/// Fully canonicalized when the path exists. When it does not, the **longest
/// existing ancestor** is canonicalized and the missing tail appended lexically,
/// so a path under a symlinked ancestor lands in the same tree whether or not its
/// leaf is present. Resolving only the whole path or nothing was the asymmetry
/// that let a denylist glob stop matching: patterns are anchored through this same
/// function, and a pattern resolved to `/mnt/home/u/...` never meets a subject
/// left at `/home/u/...` because its leaf happened to be gone.
pub fn abs_normalize(path: &Path) -> PathBuf {
    if let Ok(c) = path.canonicalize() {
        return c;
    }
    let lexical = lexical_abs(path);
    let mut tail: Vec<&std::ffi::OsStr> = Vec::new();
    let mut cur: &Path = &lexical;
    while let (Some(parent), Some(name)) = (cur.parent(), cur.file_name()) {
        tail.push(name);
        if let Ok(mut resolved) = parent.canonicalize() {
            resolved.extend(tail.iter().rev().copied());
            return resolved;
        }
        cur = parent;
    }
    lexical
}

/// `path` made absolute against the cwd with `.` and `..` folded away, resolving
/// no symlinks.
fn lexical_abs(path: &Path) -> PathBuf {
    let mut out = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().unwrap_or_default()
    };
    for comp in path.components() {
        use std::path::Component;
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::RootDir => {
                out = PathBuf::from("/");
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property blacklist anchoring rests on: a symlinked ancestor is
    /// resolved even when the leaf below it does not exist, so the same subject
    /// normalizes into the target tree whether it is present or missing.
    #[test]
    fn normalizes_a_missing_leaf_through_a_symlinked_ancestor() {
        let base = std::env::temp_dir().join(format!("yomi-norm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("real/sub")).unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("link")).unwrap();
        let real = base.join("real").canonicalize().unwrap();

        // Present leaf: plain canonicalization.
        std::fs::write(base.join("real/sub/here"), b"x").unwrap();
        assert_eq!(
            abs_normalize(&base.join("link/sub/here")),
            real.join("sub/here")
        );
        // Missing leaf, and a missing directory above it: same tree.
        assert_eq!(
            abs_normalize(&base.join("link/sub/gone")),
            real.join("sub/gone")
        );
        assert_eq!(
            abs_normalize(&base.join("link/absent/deeper/gone")),
            real.join("absent/deeper/gone")
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
