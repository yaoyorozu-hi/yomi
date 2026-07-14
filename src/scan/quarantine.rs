use anyhow::{Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

/// Write an unredacted secret-bearing original into
/// `quarantine/<uuid>/<rel>` (mode 700 dir, 600 file), index-excluded and
/// recoverable. `rel` preserves the artifact's sub-path so two originals with
/// the same basename in different sources cannot clobber each other (R10).
pub fn quarantine_original(
    quarantine_root: &Path,
    session_uuid: &str,
    rel: &str,
    original: &[u8],
) -> Result<PathBuf> {
    let base = quarantine_root.join(session_uuid);
    let dest = base.join(sanitize_rel(rel));

    let parent = dest.parent().unwrap_or(&base);
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create quarantine dir {}", parent.display()))?;
    // Tighten the per-session root explicitly.
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))?;

    std::fs::write(&dest, original)
        .with_context(|| format!("write quarantine file {}", dest.display()))?;
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600))?;
    Ok(dest)
}

/// Strip absolute/`..` components so `rel` can never escape the quarantine
/// root, keeping normal segments to preserve uniqueness.
fn sanitize_rel(rel: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in Path::new(rel).components() {
        if let Component::Normal(c) = comp {
            out.push(c);
        }
    }
    if out.as_os_str().is_empty() {
        out.push("original");
    }
    out
}
