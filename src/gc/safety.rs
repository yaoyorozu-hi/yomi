//! The delete decision. `evaluate_file` runs the 5 gates for a catalog-backed
//! source; scratch and empty-dir families have their own, narrower gates. No
//! deletion primitive here touches a path that hasn't just passed the blacklist.

use crate::archive::compress::decompress_all;
use crate::archive::{canonical_key, verify_stored};
use crate::blacklist::{Blacklist, GuardOutcome};
use crate::catalog::Catalog;
use crate::config::Env;
use crate::gc::live;
use crate::gc::{PassedChecks, ProtectReason, SkipReason, Verdict, policy};
use anyhow::Result;
use serde::Deserialize;
use std::collections::HashSet;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use walkdir::WalkDir;

/// Evaluate a catalog-backed source (transcript/mcp/paste/snapshot) through all
/// five gates. Returns `(verdict, live_bytes)`. Only every gate passing yields
/// `Delete`; any doubt yields `Unverified` or `Protected`.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_file(
    cat: &Catalog,
    bl: &Blacklist,
    archive_dir: &Path,
    source: &Path,
    session_uuid: Option<&str>,
    active: &HashSet<String>,
    min_age: Duration,
    retain: Duration,
    active_window: Duration,
    require_indexed: bool,
) -> Result<(Verdict, u64)> {
    // Gate 0: blacklist, pre-decision. Pins the opened inode.
    let (mut file, md) = match bl.open_guarded(source)? {
        GuardOutcome::Denied => {
            return Ok((
                Verdict::Unverified {
                    reason: SkipReason::Blacklisted,
                },
                0,
            ));
        }
        GuardOutcome::Unreadable => {
            return Ok((
                Verdict::Unverified {
                    reason: SkipReason::OpenFailed,
                },
                0,
            ));
        }
        GuardOutcome::Opened(f, md) => (f, md),
    };
    let bytes = md.len();

    // Gate 1: catalog lookup by canonical source path.
    let key = canonical_key(source);
    let row = match cat.gc_row_for_source(&key)? {
        Some(r) => r,
        None => {
            return Ok((
                Verdict::Unverified {
                    reason: SkipReason::NoCatalogRow,
                },
                bytes,
            ));
        }
    };

    // Gate 2: live source sha (hashed from the pinned fd) == stored source sha.
    let live_sha = crate::util::sha256_stream(&mut file)?;
    if live_sha != row.source_sha256 {
        return Ok((
            Verdict::Unverified {
                reason: SkipReason::ShaMismatch,
            },
            bytes,
        ));
    }

    // Gate 3: two-layer store re-verification (P1 `verify_stored`, unchanged).
    // `verify_stored` keeps a legacy fallback: an empty `content_sha256` degrades
    // gate 3 to a stored-bytes-only check, which passes a valid-zstd frame of the
    // *wrong* bytes (the D2 class). That fallback is safe for archive's other
    // callers but never for a delete gate — a catalog row with no content hash is
    // unverified, so refuse rather than delete (D2 twin, never delete on doubt).
    if row.content_sha256.is_empty() {
        return Ok((
            Verdict::Unverified {
                reason: SkipReason::EmptyContentSha,
            },
            bytes,
        ));
    }
    if !verify_stored(
        archive_dir,
        &row.stored_path,
        &row.stored_sha256,
        &row.content_sha256,
    )? {
        return Ok((
            Verdict::Unverified {
                reason: SkipReason::StoreReverifyFailed,
            },
            bytes,
        ));
    }

    // Gate 3b: index status. In P2 no index layer exists, so require_indexed is
    // unsatisfiable — skip with warning, never delete.
    if require_indexed {
        return Ok((
            Verdict::Unverified {
                reason: SkipReason::IndexUnsatisfiable,
            },
            bytes,
        ));
    }

    // Gate 4: age AND not-live.
    let age = policy::age_of(&md);
    if !policy::age_ok(age, min_age, retain) {
        let reason = if age < min_age {
            ProtectReason::TooYoung
        } else {
            ProtectReason::RetainWindow
        };
        return Ok((Verdict::Protected { reason }, bytes));
    }
    if live::is_protected(active, &md, session_uuid, active_window, min_age) {
        return Ok((
            Verdict::Protected {
                reason: ProtectReason::SessionLive,
            },
            bytes,
        ));
    }

    let checks = PassedChecks {
        source_sha256: live_sha,
        archive_id: row.id,
        stored_reverified: true,
        index_ok: true,
        age_secs: age.as_secs(),
        session_live: false,
    };
    Ok((
        Verdict::Delete {
            archive_id: Some(row.id),
            checks,
        },
        bytes,
    ))
}

/// A scratch working tree is a manifest-gated janitor, not a per-file catalog
/// candidate (scratch archives write a manifest, not catalog rows). Delete rule,
/// resolved on the delete-less side of every doubt: the manifest exists, and a
/// full walk of the live tree proves the archive still faithfully covers it (see
/// [`verify_scratch_tree`] for the four coverage checks). Only then, if the
/// session is non-live and the newest mtime clears both the floor and
/// `scratch_retain`, is the tree deletable. A manifest predating the per-entry
/// hash fields cannot be verified, so its tree is skipped (safe side).
#[allow(clippy::too_many_arguments)]
pub fn evaluate_scratch(
    env: &Env,
    key: &str,
    session_dir: &Path,
    session_uuid: Option<&str>,
    active: &HashSet<String>,
    min_age: Duration,
    retain: Duration,
    active_window: Duration,
) -> Result<(Verdict, u64)> {
    let (bytes, newest) = tree_size_and_newest(session_dir);

    let store_dir = env.archive_dir().join("_scratch").join(key);
    let manifest_path = store_dir.join("manifest.json");
    let mf = match read_scratch_manifest(&manifest_path) {
        Some(m) => m,
        None => {
            return Ok((
                Verdict::Unverified {
                    reason: SkipReason::NoCatalogRow,
                },
                bytes,
            ));
        }
    };
    if let Some(reason) = verify_scratch_tree(session_dir, &store_dir, &mf) {
        return Ok((Verdict::Unverified { reason }, bytes));
    }

    let age = newest
        .map(|t| SystemTime::now().duration_since(t).unwrap_or_default())
        .unwrap_or_default();
    if !policy::age_ok(age, min_age, retain) {
        let reason = if age < min_age {
            ProtectReason::TooYoung
        } else {
            ProtectReason::RetainWindow
        };
        return Ok((Verdict::Protected { reason }, bytes));
    }
    if let Some(u) = session_uuid
        && active.contains(u)
    {
        return Ok((
            Verdict::Protected {
                reason: ProtectReason::SessionLive,
            },
            bytes,
        ));
    }
    if let Some(t) = newest
        && SystemTime::now().duration_since(t).unwrap_or_default() < active_window
    {
        return Ok((
            Verdict::Protected {
                reason: ProtectReason::SessionLive,
            },
            bytes,
        ));
    }

    let checks = PassedChecks {
        source_sha256: String::new(),
        archive_id: 0,
        stored_reverified: true,
        index_ok: true,
        age_secs: age.as_secs(),
        session_live: false,
    };
    Ok((
        Verdict::Delete {
            archive_id: None,
            checks,
        },
        bytes,
    ))
}

/// An empty-dir shell carries zero data, so it bypasses the archive gates but
/// still honors non-live + the hard floor + a strict emptiness re-check.
pub fn evaluate_empty_dir(
    dir: &Path,
    active: &HashSet<String>,
    min_age: Duration,
    active_window: Duration,
) -> Result<(Verdict, u64)> {
    let md = match std::fs::metadata(dir) {
        Ok(m) => m,
        Err(_) => {
            return Ok((
                Verdict::Unverified {
                    reason: SkipReason::OpenFailed,
                },
                0,
            ));
        }
    };
    let empty = std::fs::read_dir(dir)
        .map(|mut it| it.next().is_none())
        .unwrap_or(false);
    if !empty {
        return Ok((
            Verdict::Protected {
                reason: ProtectReason::RetainWindow,
            },
            0,
        ));
    }
    let age = policy::age_of(&md);
    if age < min_age {
        return Ok((
            Verdict::Protected {
                reason: ProtectReason::TooYoung,
            },
            0,
        ));
    }
    if live::is_protected(active, &md, None, active_window, min_age) {
        return Ok((
            Verdict::Protected {
                reason: ProtectReason::SessionLive,
            },
            0,
        ));
    }
    let checks = PassedChecks {
        source_sha256: String::new(),
        archive_id: 0,
        stored_reverified: false,
        index_ok: true,
        age_secs: age.as_secs(),
        session_live: false,
    };
    Ok((
        Verdict::Delete {
            archive_id: None,
            checks,
        },
        0,
    ))
}

/// Unlink a single file safely: open its parent dir `O_DIRECTORY|O_NOFOLLOW`,
/// `fstatat` the entry to confirm it is still the exact `(dev,ino)` the gate
/// pinned, then `unlinkat`. This pins both the directory and the entry, closing
/// the symlinked-parent race a path-based `remove_file` leaves open. Returns
/// `Ok(false)` (without deleting) if the inode drifted since the gate.
pub fn safe_unlink(path: &Path, pinned: (u64, u64)) -> Result<bool> {
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    let name = match path.file_name() {
        Some(n) => n,
        None => return Ok(false),
    };
    let dir = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)
    {
        Ok(d) => d,
        Err(_) => return Ok(false),
    };
    let st = match rustix::fs::statat(&dir, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => st,
        Err(_) => return Ok(false),
    };
    if (st.st_dev, st.st_ino) != pinned {
        return Ok(false);
    }
    match rustix::fs::unlinkat(&dir, name, rustix::fs::AtFlags::empty()) {
        Ok(()) => Ok(true),
        Err(e) => Err(anyhow::anyhow!("unlinkat {} failed: {}", path.display(), e)),
    }
}

/// Outcome of guarding then removing a scratch tree.
pub enum TreeRemoval {
    Removed,
    /// A blacklisted inode was found inside — the tree is left untouched.
    Blacklisted,
    Failed,
}

/// Remove a scratch tree only after proving no blacklisted inode lives inside.
/// Pass 1 guards every regular file through the denylist (aborting the whole
/// removal on any hit); pass 2 removes the tree. The residual plant-after-scan
/// window is bounded by the held `WriteLock` + single-user ownership — the same
/// residual class the archive read path accepts.
pub fn remove_tree_guarded(bl: &Blacklist, root: &Path) -> Result<TreeRemoval> {
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        let ft = entry.file_type();
        if ft.is_symlink() {
            // Removing a symlink removes the link node, never its target — but a
            // hardlink to a credential is a real file; guard those below.
            continue;
        }
        if ft.is_file() {
            match bl.open_guarded(entry.path())? {
                GuardOutcome::Denied => return Ok(TreeRemoval::Blacklisted),
                GuardOutcome::Unreadable => {
                    if bl.is_blacklisted(entry.path()) {
                        return Ok(TreeRemoval::Blacklisted);
                    }
                }
                GuardOutcome::Opened(_, _) => {}
            }
        }
    }
    match std::fs::remove_dir_all(root) {
        Ok(()) => Ok(TreeRemoval::Removed),
        Err(_) => Ok(TreeRemoval::Failed),
    }
}

/// Total byte size and newest **file** mtime across a tree (age proxy for
/// scratch). Directory mtimes are ignored — they change on any child operation
/// and would perpetually reset the tree's apparent age.
fn tree_size_and_newest(root: &Path) -> (u64, Option<SystemTime>) {
    let mut total = 0u64;
    let mut newest: Option<SystemTime> = None;
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        if let Ok(md) = entry.metadata() {
            total += md.len();
            if let Ok(t) = md.modified() {
                newest = Some(match newest {
                    Some(cur) if cur >= t => cur,
                    _ => t,
                });
            }
        }
    }
    (total, newest)
}

#[derive(Deserialize)]
struct ScratchManifestEntry {
    path: String,
    bytes: u64,
    stored: bool,
    /// Absent in manifests written before D2/R1 shipped — a stored entry without
    /// these hashes is unverifiable, so the tree is skipped (safe side).
    #[serde(default)]
    source_sha256: Option<String>,
    #[serde(default)]
    content_sha256: Option<String>,
}

#[derive(Deserialize)]
struct ScratchManifestRead {
    entries: Vec<ScratchManifestEntry>,
}

fn read_scratch_manifest(path: &Path) -> Option<ScratchManifestRead> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Upper bound on a live scratch file re-read for hashing. Stored entries are
/// bounded by the archiver's `file_cap` (≤5MB default); a live file that has
/// since grown past this is treated as drifted → skip, never OOM.
const MAX_SCRATCH_REHASH_BYTES: u64 = 64 * 1024 * 1024;

/// Walk the live tree and prove the manifest still faithfully covers it. Returns
/// `Some(reason)` on the first failure (→ skip the tree, do not delete), `None`
/// when every live file is accounted for and every stored archive re-verifies.
fn verify_scratch_tree(
    session_dir: &Path,
    store_dir: &Path,
    mf: &ScratchManifestRead,
) -> Option<SkipReason> {
    let by_path: std::collections::HashMap<&str, &ScratchManifestEntry> =
        mf.entries.iter().map(|e| (e.path.as_str(), e)).collect();

    for entry in WalkDir::new(session_dir).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = match entry.path().strip_prefix(session_dir) {
            Ok(r) => r.to_string_lossy().replace('\\', "/"),
            Err(_) => return Some(SkipReason::NoCatalogRow),
        };
        // (1) A live file absent from the manifest is unarchived data (created
        // after the last archive) — refuse the whole-tree delete.
        let Some(e) = by_path.get(rel.as_str()) else {
            return Some(SkipReason::NoCatalogRow);
        };
        let Ok(md) = entry.metadata() else {
            return Some(SkipReason::OpenFailed);
        };
        if !e.stored {
            // (4) Deny-listed junk carries no archive; presence + size is the
            // most we can assert, and a size drift means the manifest is stale.
            if md.len() != e.bytes {
                return Some(SkipReason::ShaMismatch);
            }
            continue;
        }
        // A stored entry written before the hash fields existed is unverifiable.
        let (Some(src_sha), Some(content_sha)) = (&e.source_sha256, &e.content_sha256) else {
            return Some(SkipReason::StoreReverifyFailed);
        };
        // (2) Live bytes must still hash to what was captured. Size first, so a
        // drifted/huge file is rejected without an unbounded read.
        if md.len() != e.bytes || md.len() > MAX_SCRATCH_REHASH_BYTES {
            return Some(SkipReason::ShaMismatch);
        }
        match std::fs::read(entry.path()) {
            Ok(live) if &crate::util::sha256_hex(&live) == src_sha => {}
            Ok(_) => return Some(SkipReason::ShaMismatch),
            Err(_) => return Some(SkipReason::OpenFailed),
        }
        // (3) The stored archive must decompress to the captured content hash —
        // valid-zstd of the wrong bytes is not verification (D2).
        let zst = store_dir.join(format!("{}.zst", e.path));
        let intact = std::fs::read(&zst)
            .ok()
            .and_then(|b| decompress_all(&b).ok())
            .map(|d| &crate::util::sha256_hex(&d) == content_sha)
            .unwrap_or(false);
        if !intact {
            return Some(SkipReason::StoreReverifyFailed);
        }
    }
    None
}

/// Enumerate empty directories under `root`, deepest-first so nested empties are
/// reported before their parents.
pub fn empty_dirs_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in WalkDir::new(root)
        .contents_first(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.path() == root {
            continue;
        }
        if entry.file_type().is_dir()
            && std::fs::read_dir(entry.path())
                .map(|mut it| it.next().is_none())
                .unwrap_or(false)
        {
            out.push(entry.path().to_path_buf());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("yomi-rtg-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// A credential hardlinked into a scratch tree must abort the whole-tree
    /// removal (Gate 0 by inode), never be unlinked. Exercises the `Blacklisted`
    /// branch of `remove_tree_guarded` directly.
    #[test]
    fn remove_tree_guarded_aborts_on_credential_hardlink() {
        let base = tmp("cred");
        let fake_home = base.join("home");
        let claude = fake_home.join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        let cred = claude.join(".credentials.json");
        std::fs::write(&cred, b"{\"token\":\"x\"}").unwrap();

        let tree = base.join("scratch/sess");
        let inner = tree.join("scratchpad");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(inner.join("notes.md"), b"work\n").unwrap();
        let link = inner.join("evil.json");
        std::fs::hard_link(&cred, &link).unwrap();

        // Compile the denylist against the fake HOME (credential inode captured);
        // the check itself re-stats stored absolute paths, not HOME.
        let prev = std::env::var_os("HOME");
        // SAFETY: test-only; restored immediately after compile.
        unsafe { std::env::set_var("HOME", &fake_home) };
        let bl = crate::blacklist::Blacklist::compile(&[]).unwrap();
        // SAFETY: restore prior value.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }

        let outcome = remove_tree_guarded(&bl, &tree).unwrap();
        assert!(
            matches!(outcome, TreeRemoval::Blacklisted),
            "credential hardlink did not abort the tree removal"
        );
        assert!(
            tree.exists(),
            "tree was removed despite a blacklisted inode"
        );
        assert!(cred.exists(), "credential was destroyed via hardlink");
    }
}
