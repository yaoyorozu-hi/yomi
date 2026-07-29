use crate::model::Manifest;
use anyhow::{Context, Result};
use std::path::Path;

/// Write a session manifest, descending fd by fd from the archive root.
///
/// `rel` is the manifest's path relative to `archive_dir`. Taken apart rather
/// than as one absolute path because the descent needs the root it may follow
/// and the components it may not — the ledger is written into the same tree the
/// artifacts are, under the same guarantee.
pub fn write(archive_dir: &Path, rel: &Path, manifest: &Manifest) -> Result<()> {
    let json = serde_json::to_string_pretty(manifest).context("serialize manifest")? + "\n";
    crate::safefs::write_under(archive_dir, rel, json.as_bytes())
        .with_context(|| format!("write manifest {}", rel.display()))
}

pub fn read(path: &Path) -> Result<Manifest> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read manifest {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse manifest {}", path.display()))
}
