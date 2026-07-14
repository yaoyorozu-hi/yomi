use anyhow::{Context, Result, bail};
use fs2::FileExt;
use std::fs::File;
use std::path::Path;

/// Advisory single-writer lock held for the duration of a mutating command.
/// Released when dropped (process exit or scope end).
pub struct WriteLock {
    _file: File,
}

impl WriteLock {
    /// Acquire an exclusive advisory lock on `path`. Fails fast (does not
    /// block) if another yomi process holds it.
    pub fn acquire(path: &Path) -> Result<Self> {
        let file =
            File::create(path).with_context(|| format!("open lock file {}", path.display()))?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(WriteLock { _file: file }),
            Err(_) => bail!(
                "refuse: another yomi process holds the write lock ({})",
                path.display()
            ),
        }
    }
}
