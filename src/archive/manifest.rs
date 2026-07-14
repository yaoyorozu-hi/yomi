use crate::model::Manifest;
use anyhow::{Context, Result};
use std::path::Path;

pub fn write(path: &Path, manifest: &Manifest) -> Result<()> {
    let json = serde_json::to_string_pretty(manifest).context("serialize manifest")? + "\n";
    std::fs::write(path, json).with_context(|| format!("write manifest {}", path.display()))?;
    Ok(())
}

pub fn read(path: &Path) -> Result<Manifest> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read manifest {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse manifest {}", path.display()))
}
