//! The delete decision. `evaluate_file` runs the 5 gates for a catalog-backed
//! source; scratch and empty-dir families have their own, narrower gates. No
//! deletion primitive here touches a path that hasn't just passed the blacklist.

use crate::archive::compress::decompress_all;
use crate::archive::{canonical_key, verify_stored};
use crate::blacklist::{Blacklist, GuardOutcome};
use crate::catalog::Catalog;
use crate::config::Env;
use crate::gc::live;
use crate::gc::{ByteSplit, PassedChecks, ProtectReason, ScratchMode, SkipReason, Verdict, policy};
use crate::scratch::{
    IdentityVerdict, ScratchEntry, ScratchManifest, ScratchRel, StoreDir, read_manifest,
};
use anyhow::Result;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use walkdir::WalkDir;

/// Evaluate a catalog-backed source (transcript/mcp/paste/snapshot) through all
/// five gates. Returns `(verdict, live_bytes, split)`. Only every gate passing
/// yields `Delete`; any doubt yields `Unverified` or `Protected`.
///
/// The split turns on gate 3 rather than on the candidate's kind. A file that
/// reaches the age gate has a store copy this run re-verified, so its bytes are
/// archived; a file refused at gates 1-3 has none — no row, a row for other bytes,
/// or a store copy that did not verify — and reporting those bytes as archived
/// would be the one claim a byte split exists to make honestly.
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
) -> Result<(Verdict, u64, ByteSplit)> {
    // Gate 0: blacklist, pre-decision. Pins the opened inode.
    let (mut file, md) = match bl.open_guarded(source)? {
        GuardOutcome::Denied => {
            return Ok((
                Verdict::Unverified {
                    reason: SkipReason::Blacklisted,
                },
                0,
                ByteSplit::default(),
            ));
        }
        GuardOutcome::Unreadable => {
            return Ok((
                Verdict::Unverified {
                    reason: SkipReason::OpenFailed,
                },
                0,
                ByteSplit::default(),
            ));
        }
        GuardOutcome::Opened(f, md) => (f, md),
    };
    let bytes = md.len();
    let unarchived = ByteSplit::all_unarchived(bytes);
    let archived = ByteSplit::all_archived(bytes);

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
                unarchived,
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
            unarchived,
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
            unarchived,
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
            unarchived,
        ));
    }

    // Gate 3b: index status (P3). When require_indexed is set, this source's
    // stored content must be indexed at exactly the version we are about to
    // delete — i.e. index_state.indexed_source_sha256 == row.source_sha256.
    // Anything else — never indexed, indexed at a stale sha, or (via `?`) an SQL
    // error — refuses the delete. Fail-closed: never delete on an unproven index.
    if require_indexed {
        match cat.index_status_for_source(&key)? {
            Some(st) if st.indexed_source_sha256 == row.source_sha256 => {}
            _ => {
                return Ok((
                    Verdict::Unverified {
                        reason: SkipReason::NotIndexed,
                    },
                    bytes,
                    archived,
                ));
            }
        }
    }

    // Gate 4: age AND not-live.
    let age = policy::age_of(&md);
    if !policy::age_ok(age, min_age, retain) {
        let reason = if age < min_age {
            ProtectReason::TooYoung
        } else {
            ProtectReason::RetainWindow
        };
        return Ok((Verdict::Protected { reason }, bytes, archived));
    }
    if live::is_protected(active, &md, session_uuid, active_window, min_age) {
        return Ok((
            Verdict::Protected {
                reason: ProtectReason::SessionLive,
            },
            bytes,
            archived,
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
        archived,
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
///
/// Under [`ScratchMode::Full`] the age half of that rule relaxes to the floor in
/// `min_age` (never zero — see [`policy::relaxed_min_age_floor`]) and one gate is
/// **added**: [`full_protection`]. Nothing is removed. Every coverage check still
/// runs, and a tree with no readable ledger is refused exactly as it is by default
/// — "the captured set is empty" and "nothing ever tried to capture this" are
/// different statements, and only the first one licenses a delete.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_scratch(
    env: &Env,
    bl: &Blacklist,
    key: &str,
    session_dir: &Path,
    session_uuid: Option<&str>,
    active: &HashSet<String>,
    min_age: Duration,
    retain: Duration,
    active_window: Duration,
    mode: ScratchMode,
) -> Result<(Verdict, u64, ByteSplit)> {
    let (bytes, newest) = tree_size_and_newest(session_dir);
    // Until a ledger has been read, nothing says any of these bytes are in the
    // store — which is exactly what `unarchived` claims, no more.
    let no_ledger = ByteSplit::all_unarchived(bytes);

    // Before anything is read through it. A store path that is not a real
    // directory may point anywhere, and every fact this gate would draw from it —
    // the manifest, the `.zst` — becomes foreign evidence authorizing the delete
    // of a live tree. The writer and the reconciler refuse the same path; the
    // gate's stake is the largest of the three, because its output is a deletion.
    //
    // Both levels, because a key resolved through a foreign root is foreign even
    // when the key directory itself classifies `Own`.
    let root = crate::scratch::store_root(&env.archive_dir());
    let store_dir = root.join(key);
    if crate::scratch::classify_store_dir(&root) == StoreDir::Foreign
        || crate::scratch::classify_store_dir(&store_dir) == StoreDir::Foreign
    {
        return Ok((
            Verdict::Unverified {
                reason: SkipReason::ForeignStoreDir,
            },
            bytes,
            no_ledger,
        ));
    }
    let manifest_path = store_dir.join("manifest.json");
    let mf = match read_manifest(&manifest_path) {
        Some(m) => m,
        None => {
            return Ok((
                Verdict::Unverified {
                    reason: SkipReason::NoCatalogRow,
                },
                bytes,
                no_ledger,
            ));
        }
    };
    let split = byte_split(&mf);
    // Immediately after the manifest is read and before any coverage judgment.
    // A store key is not injective, so this ledger may describe a *different*
    // session directory that happens to map to the same key — and coverage
    // computed from it would be coverage of another tree, which is the shape of
    // evidence that authorizes destroying this one.
    let identity = crate::scratch::identity_verdict(&mf, session_dir);
    if identity != IdentityVerdict::Proceed {
        // Two states, two operator actions: rename one of two colliding session
        // directories, or repair a ledger whose identity cannot be read. A false
        // reason is worse than a coarse one (D-S7), so they do not share a name.
        let reason = match identity {
            IdentityVerdict::Collision => SkipReason::StoreKeyCollision,
            _ => SkipReason::UndecodableIdentity,
        };
        return Ok((Verdict::Unverified { reason }, bytes, split));
    }
    if let Some(reason) = verify_scratch_tree(bl, session_dir, &store_dir, &mf) {
        return Ok((Verdict::Unverified { reason }, bytes, split));
    }

    // After every verification check and before the age gate. After, because
    // "verification precedes policy" is the order the default path already runs in
    // and a reason's precedence must not depend on the flag. Before the age gate,
    // because these two states are permanent conditions of the tree while
    // `TooYoung` is a transient one, and the permanent answer is the useful one.
    if mode == ScratchMode::Full
        && let Some(reason) = full_protection(&mf)
    {
        return Ok((Verdict::Protected { reason }, bytes, split));
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
        return Ok((Verdict::Protected { reason }, bytes, split));
    }
    if let Some(u) = session_uuid
        && active.contains(u)
    {
        return Ok((
            Verdict::Protected {
                reason: ProtectReason::SessionLive,
            },
            bytes,
            split,
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
            split,
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
        split,
    ))
}

/// Whether the store holds a copy of nothing still in the live tree — no entry is
/// both `stored` and `present`.
///
/// **`present` is a condition, not an oversight.** `prior_tail` retains an entry
/// whose live file is gone (`present: false`) and keeps its `.zst`, because that
/// artifact is the only remaining copy. Such an entry describes a file that has
/// **already left the tree**, so deleting the tree loses nothing it names. Letting
/// it veto would put a tree permanently beyond `--full`'s reach in exchange for
/// protecting nothing.
fn captured_set_empty(mf: &ScratchManifest) -> bool {
    mf.entries.iter().all(|e| !(e.present && e.stored))
}

/// The two states `--full` holds a tree in, or `None` when the verb claims it.
///
/// **`Captured` is tested first**, and the order carries a claim: when both hold —
/// a capped run that stored something — `Captured` is the fact that is established
/// and `NotFullyArchived` is not, and `NotFullyArchived` would send the operator to
/// `archive --all --full`, which cannot make a tree with captured content a `--full`
/// candidate. A remedy that does not work is worse than the coarser reason.
///
/// **`caps_lifted` rather than `!over_total_cap`.** The two look interchangeable —
/// a caps-lifted run cannot be over a cap it never applied — and are not. Requiring
/// `!over_total_cap` would have made the feature inert at birth: under the
/// whole-tree accounting in force when this shipped, the one tree on this host
/// `--full` exists for (raw 468MB, captured 0.00MB) was over the cap, so the
/// conjunct would have left zero candidates. Decision #9 has since moved the cap
/// onto admitted bytes, which retires that instance without retiring the
/// objection: a tree still goes over the cap on its admitted set, and gating on
/// `!over_total_cap` would withhold `--full` from exactly the trees whose captured
/// set a cap emptied. `caps_lifted` also says the thing that matters — this ledger
/// was written by a run that *had the chance* to store everything policy admits —
/// which is what makes `gc --full` the pair of `archive --full` by construction
/// rather than by coincidence. A manifest from before the field reads `false` and
/// is refused; one `archive --all --full` run repairs that.
fn full_protection(mf: &ScratchManifest) -> Option<ProtectReason> {
    if !captured_set_empty(mf) {
        return Some(ProtectReason::Captured);
    }
    if !mf.caps_lifted {
        return Some(ProtectReason::NotFullyArchived);
    }
    None
}

/// Split a tree's ledger into the live bytes that have a stored copy and the live
/// bytes that have none.
///
/// Stated over **present** entries for the same reason [`captured_set_empty`] tests
/// `present`: a retained entry's file is already gone from the tree, so its bytes
/// are neither reclaimed nor lost by the delete and belong on neither side. Its
/// `bytes` counted as `unarchived` would inflate the one figure an operator reads
/// as "this much exists nowhere else after the run".
fn byte_split(mf: &ScratchManifest) -> ByteSplit {
    let mut split = ByteSplit::default();
    for e in mf.entries.iter().filter(|e| e.present) {
        if e.stored {
            split.archived += e.bytes;
        } else {
            split.unarchived += e.bytes;
        }
    }
    split
}

/// An empty-dir shell carries zero data, so it bypasses the archive gates but
/// still honors non-live + the hard floor + a strict emptiness re-check.
pub fn evaluate_empty_dir(
    dir: &Path,
    active: &HashSet<String>,
    min_age: Duration,
    active_window: Duration,
) -> Result<(Verdict, u64, ByteSplit)> {
    let md = match std::fs::metadata(dir) {
        Ok(m) => m,
        Err(_) => {
            return Ok((
                Verdict::Unverified {
                    reason: SkipReason::OpenFailed,
                },
                0,
                ByteSplit::default(),
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
            ByteSplit::default(),
        ));
    }
    let age = policy::age_of(&md);
    if age < min_age {
        return Ok((
            Verdict::Protected {
                reason: ProtectReason::TooYoung,
            },
            0,
            ByteSplit::default(),
        ));
    }
    if live::is_protected(active, &md, None, active_window, min_age) {
        return Ok((
            Verdict::Protected {
                reason: ProtectReason::SessionLive,
            },
            0,
            ByteSplit::default(),
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
        ByteSplit::default(),
    ))
}

/// Unlink a single file safely: open its parent dir `O_DIRECTORY|O_NOFOLLOW`,
/// `fstatat` the entry to confirm it is still the exact `(dev,ino)` the gate
/// pinned, then `unlinkat`. This pins both the directory and the entry, closing
/// the symlinked-parent race a path-based `remove_file` leaves open. Returns
/// `Ok(false)` (without deleting) if the inode drifted since the gate, or if the
/// entry was already gone by the time `unlinkat` ran.
pub fn safe_unlink(path: &Path, pinned: (u64, u64)) -> Result<bool> {
    let Some((dir, name)) = pin_entry(path, pinned) else {
        return Ok(false);
    };
    remove_at(&dir, name, path, rustix::fs::AtFlags::empty())
}

/// Remove an empty directory under the same guarantees as [`safe_unlink`]:
/// parent fd pinned `O_DIRECTORY|O_NOFOLLOW`, entry re-`fstatat`ed against the
/// pinned `(dev,ino)`, then `unlinkat(AT_REMOVEDIR)`. A path-based `remove_dir`
/// left the swapped-parent window open that `safe_unlink` closes, so the commit
/// loop ran two delete primitives under two different threat models.
pub fn safe_rmdir(path: &Path, pinned: (u64, u64)) -> Result<bool> {
    let Some((dir, name)) = pin_entry(path, pinned) else {
        return Ok(false);
    };
    remove_at(&dir, name, path, rustix::fs::AtFlags::REMOVEDIR)
}

/// Open the entry's parent `O_DIRECTORY|O_NOFOLLOW` and prove `name` under it
/// still resolves to `pinned`. `None` means anything drifted — refuse, never
/// delete.
fn pin_entry(path: &Path, pinned: (u64, u64)) -> Option<(std::fs::File, &OsStr)> {
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    let name = path.file_name()?;
    let flags = rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW;
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits() as i32)
        .open(parent)
        .ok()?;
    let st = rustix::fs::statat(&dir, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW).ok()?;
    if (st.st_dev, st.st_ino) != pinned {
        return None;
    }
    Some((dir, name))
}

fn remove_at(
    dir: &std::fs::File,
    name: &OsStr,
    path: &Path,
    flags: rustix::fs::AtFlags,
) -> Result<bool> {
    use rustix::io::Errno;
    match rustix::fs::unlinkat(dir, name, flags) {
        Ok(()) => Ok(true),
        // The candidate is simply no longer deletable, which is not a failure:
        // ENOENT means a racer (or Claude Code itself) already removed the entry
        // between the statat and here — the delete happened, it just was not us —
        // and ENOTEMPTY means an empty-dir candidate refilled. Both are refusals.
        // Every other errno is a genuine failure and is surfaced to the caller,
        // which records it and moves to the next candidate.
        Err(e) if e == Errno::NOENT || e == Errno::NOTEMPTY => Ok(false),
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

/// Upper bound on a live scratch file re-read for hashing. Stored entries are
/// bounded by the archiver's `file_cap` (≤5MB default); a live file that has
/// since grown past this is treated as drifted → skip, never OOM.
const MAX_SCRATCH_REHASH_BYTES: u64 = 64 * 1024 * 1024;

/// Walk the live tree and prove the manifest still faithfully covers it. Returns
/// `Some(reason)` on the first failure (→ skip the tree, do not delete), `None`
/// when every live file is accounted for and every stored archive re-verifies.
fn verify_scratch_tree(
    bl: &Blacklist,
    session_dir: &Path,
    store_dir: &Path,
    mf: &ScratchManifest,
) -> Option<SkipReason> {
    // Keyed by `ScratchRel` — raw bytes, never a lossy string. An entry whose
    // recorded fields do not decode contributes no key, so it matches no live
    // file and the tree is refused (safe side).
    let by_rel: std::collections::HashMap<ScratchRel, &ScratchEntry> = mf
        .entries
        .iter()
        .filter_map(|e| e.rel().map(|r| (r, e)))
        .collect();

    for entry in WalkDir::new(session_dir).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let Some(rel) = ScratchRel::from_live(session_dir, entry.path()) else {
            return Some(SkipReason::NoCatalogRow);
        };
        // (1) A live file absent from the manifest is unarchived data (created
        // after the last archive) — refuse the whole-tree delete.
        let Some(e) = by_rel.get(&rel) else {
            return Some(SkipReason::NoCatalogRow);
        };
        // A denylisted inode occupies this name. Refusing the tree is correct —
        // `remove_tree_guarded` would abort on it anyway — but doing so with a
        // reason is the point: it used to be unmanifested, so the gate reported
        // only `NoCatalogRow` and a benign denylist hit produced a permanent,
        // unexplained refusal.
        if e.blacklisted {
            return Some(SkipReason::Blacklisted);
        }
        let Ok(md) = entry.metadata() else {
            return Some(SkipReason::OpenFailed);
        };
        // The archiver meant to store this file and could not read it, so no
        // byte of its content was ever captured. That is not the deliberate
        // non-storage a bare `stored: false` records, and presence + size
        // assures nothing about content nobody read — refuse the tree rather
        // than delete a file yomi intended to archive. Transient by
        // construction: the first archive that can read the file clears it.
        if e.capture_failed {
            return Some(SkipReason::OpenFailed);
        }
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
        // (2) Live bytes must still hash to what was captured — read through the
        // denylist, exactly as `evaluate_file`'s Gate 0 does. This was the one
        // read in yomi that opened a live file by name and slurped it with no
        // guard, so a credential hardlinked over an archived entry's path (with
        // its size matched) had its bytes pulled into this process. The check is
        // on the *opened fd's* inode, not the name, because the name is what the
        // attacker controls.
        //
        // U2 made the window permanent rather than racy: before it, a denylisted
        // path had no manifest entry to match — the writer skipped it — so the
        // lookup above refused first. Retention now keeps an entry alive for a
        // name whose inode has since been swapped.
        let (mut live, fd_md) = match bl.open_guarded(entry.path()) {
            Ok(GuardOutcome::Opened(f, md)) => (f, md),
            Ok(GuardOutcome::Denied) => return Some(SkipReason::Blacklisted),
            Ok(GuardOutcome::Unreadable) | Err(_) => return Some(SkipReason::OpenFailed),
        };
        // Sized from the pinned fd rather than the walked path, and before a
        // single byte is read, so a drifted or huge file costs nothing.
        if fd_md.len() != e.bytes || fd_md.len() > MAX_SCRATCH_REHASH_BYTES {
            return Some(SkipReason::ShaMismatch);
        }
        match crate::util::sha256_stream(&mut live) {
            Ok(sha) if &sha == src_sha => {}
            Ok(_) => return Some(SkipReason::ShaMismatch),
            Err(_) => return Some(SkipReason::OpenFailed),
        }
        // (3) The stored archive must decompress to the captured content hash —
        // valid-zstd of the wrong bytes is not verification (D2).
        let zst = store_dir.join(rel.store_rel());
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
        let bl = crate::blacklist::Blacklist::compile_with_roots(
            &fake_home,
            &fake_home.join(".yomi"),
            &[],
        )
        .unwrap();

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
