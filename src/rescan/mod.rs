//! Retroactive re-scan / re-redact of the existing store against the hardened
//! scanner. Reads stored artifacts (never live source — sources may be wiped),
//! re-redacts in place, purges + rebuilds the affected index rows, keeps the
//! catalog / stored / index triad consistent, and proves no raw secret remains in
//! either the stored copy or the index. Dry-run by default; `commit` mutates.
//!
//! Crash-safety rests on one ordering invariant, per artifact: the DB transaction
//! (index purge + reindex from the in-memory redacted bytes + catalog + findings)
//! commits BEFORE the on-disk stored file is atomically renamed. At every crash
//! point the index therefore never holds a raw secret — the worst case is a stored
//! copy briefly left as stale raw (owner-only, flagged by verify), which the next
//! run re-targets and converges. The reverse order (rename first) would let a
//! post-rename crash leave `stored == clean` so the artifact is no longer a target
//! while the index still carries the raw secret — a permanent leak.

use crate::archive::compress::{compress_frame, decompress_all};
use crate::archive::{artifact_scan, manifest, summarize_records, verify_stored};
use crate::catalog::{Catalog, IndexCandidate};
use crate::config::Env;
use crate::index::{self, IndexMode};
use crate::model::{FindingAction, Frame};
use crate::scan::quarantine::quarantine_original;
use crate::scan::{
    Allowlist, ContentScan, ScanOpts, scan_content_with, stored_is_whole_quarantine,
};
use crate::util::{now_iso, sha256_hex};
use anyhow::Result;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// The three shapes a hardened re-scan can take on an old browsable artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// Scannable, no HIGH finding: redact the new secret(s) in place, stored stays
    /// browsable, raw is not quarantined.
    InPlaceRedact,
    /// Scannable with a HIGH finding: redact in place (stored stays browsable) but
    /// move the raw original to quarantine.
    VisibleQuarantine,
    /// Not fully scannable (escape-hidden / malformed / non-utf8 / utf16): store an
    /// opaque marker, move the raw original to quarantine.
    WholeQuarantine,
}

impl Transition {
    pub fn as_str(self) -> &'static str {
        match self {
            Transition::InPlaceRedact => "in-place",
            Transition::VisibleQuarantine => "visible-quarantine",
            Transition::WholeQuarantine => "whole-quarantine",
        }
    }
}

/// Totals for one `rescan --commit` run. Carries no secret material.
#[derive(Debug, Default)]
pub struct RescanReport {
    pub scanned: u64,
    pub targeted: u64,
    pub reredacted: u64,
    pub secrets_removed: u64,
    pub index_rows_purged: u64,
    pub index_rows_rebuilt: u64,
    pub visible_quarantine_transitions: u64,
    pub whole_quarantine_transitions: u64,
    pub skipped_markers: u64,
    pub verify_failures: u64,
    pub failed: Vec<String>,
}

/// One dry-run preview row. Carries NO secret material — detector kind + count +
/// transition + affected index-row count only.
pub struct TargetPreview {
    pub session_uuid: String,
    pub source_path: String,
    pub role: String,
    pub transition: Transition,
    pub kind_counts: BTreeMap<String, u32>,
    pub index_rows_affected: u64,
}

/// A dry-run plan: what would change, holding no secret bytes.
pub struct RescanPlan {
    pub previews: Vec<TargetPreview>,
    pub scanned: u64,
}

/// The computed re-redaction for one target artifact. Held only in memory.
struct Reredaction {
    scan: ContentScan,
    new_content: Vec<u8>,
    new_content_sha: String,
    new_frame: Vec<u8>,
    new_stored_sha: String,
    transition: Transition,
}

/// Sweep candidates, select targets, build previews. No mutation, no raw secret
/// retained beyond the per-artifact scope.
pub fn plan(
    env: &Env,
    cat: &Catalog,
    allow: &Allowlist,
    session: Option<&str>,
) -> Result<RescanPlan> {
    let archive_dir = env.archive_dir();
    let cands = candidates(cat, session)?;
    let mut previews = Vec::new();
    let mut scanned = 0u64;
    for c in &cands {
        if matches!(index::index_mode_for_role(&c.role), IndexMode::Skip) {
            continue;
        }
        let Some(stored) = read_stored(&archive_dir, &c.stored_path) else {
            continue;
        };
        scanned += 1;
        if is_genuine_whole_quarantine(c, &stored) {
            continue;
        }
        // Dry-run only needs the transition and finding kinds; skip the compress +
        // stored-sha work that only the commit path consumes.
        let Some((scan, transition)) = evaluate_target(&c.role, &stored, allow) else {
            continue;
        };
        previews.push(TargetPreview {
            session_uuid: c.session_uuid.clone(),
            source_path: c.source_path.clone(),
            role: c.role.clone(),
            transition,
            kind_counts: kind_counts(&scan),
            index_rows_affected: cat.entries_count_for_artifact(c.artifact_id)?,
        });
    }
    Ok(RescanPlan { previews, scanned })
}

/// Execute re-redaction under the caller-held WriteLock. Per-artifact, crash-safe.
pub fn commit(
    env: &Env,
    cat: &Catalog,
    allow: &Allowlist,
    session: Option<&str>,
) -> Result<RescanReport> {
    let archive_dir = env.archive_dir();
    let quarantine_dir = env.quarantine_dir();
    let cands = candidates(cat, session)?;
    let mut report = RescanReport::default();
    let mut faulted_once = false;

    for c in &cands {
        if matches!(index::index_mode_for_role(&c.role), IndexMode::Skip) {
            continue;
        }
        let Some(stored) = read_stored(&archive_dir, &c.stored_path) else {
            report
                .failed
                .push(fail_label(c, "stored artifact missing or unreadable"));
            continue;
        };
        report.scanned += 1;
        if is_genuine_whole_quarantine(c, &stored) {
            report.skipped_markers += 1;
            continue;
        }
        let Some(rr) = evaluate(&c.role, &stored, allow)? else {
            continue;
        };
        report.targeted += 1;
        let is_jsonl = rescan_is_jsonl(&c.role);

        // Fail-closed gate: never write bytes that still hide a secret. A marker is
        // clean (its secret lives only in quarantine); otherwise the re-redaction
        // must be idempotent (no further redaction possible).
        if !is_reredaction_clean(&rr.new_content, is_jsonl, allow) {
            report.failed.push(fail_label(
                c,
                "re-redaction left a residual secret; skipped",
            ));
            continue;
        }

        // Build the clean index docs from the IN-MEMORY redacted bytes, so the DB
        // reindex never depends on the stored file already being swapped on disk.
        let (docs, _skipped) = index::docs_for_stored(&archive_dir, c, &rr.new_content);
        let doc_count = docs.len() as u64;
        let quarantined_new = rr.transition != Transition::InPlaceRedact || c.quarantined;

        // Quarantine the raw original FIRST (owner-only, mode 700, index-excluded),
        // before any store/index mutation. If it fails, nothing has changed yet and
        // the next run re-targets cleanly — preserving the recovery copy fail-closed.
        // (Deliberate ordering: the security invariant is DB-commit-before-rename,
        // which this respects; moving quarantine earlier only guards recoverability.)
        if rr.transition != Transition::InPlaceRedact {
            let qrel = c.stored_path.strip_suffix(".zst").unwrap_or(&c.stored_path);
            if let Err(e) = quarantine_original(&quarantine_dir, &c.session_uuid, qrel, &stored) {
                report.failed.push(fail_label(
                    c,
                    &format!("quarantine of raw original failed: {e}"),
                ));
                continue;
            }
        }

        // Write the new stored frame to a temp sibling (not yet renamed).
        let dest = archive_dir.join(&c.stored_path);
        let tmp = match write_temp(&dest, &rr.new_frame) {
            Ok(t) => t,
            Err(e) => {
                report
                    .failed
                    .push(fail_label(c, &format!("temp store write failed: {e}")));
                continue;
            }
        };

        // DB transaction: purge stale index rows, reindex from in-mem redacted
        // bytes, bump the watermark (indexed_source_sha256 = source_sha256, kept
        // constant so the require_indexed GC gate stays satisfied), update the
        // artifact row, replace findings — all atomically, BEFORE the stored rename.
        let findings = rr.scan.findings.clone();
        let txn = cat.transaction(|| {
            let purged = cat.delete_entries_for_artifact(c.artifact_id)?;
            for d in &docs {
                cat.insert_entry(d)?;
            }
            cat.upsert_index_state(
                &c.source_path,
                &c.session_uuid,
                c.artifact_id,
                &c.source_sha256,
                c.source_bytes,
                doc_count,
            )?;
            cat.rescan_update_artifact(
                c.artifact_id,
                &rr.new_stored_sha,
                rr.new_frame.len() as u64,
                &rr.new_content_sha,
                true,
                quarantined_new,
            )?;
            cat.replace_findings(c.artifact_id, &findings)?;
            Ok(purged as u64)
        });
        let purged = match txn {
            Ok(p) => p,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                report
                    .failed
                    .push(fail_label(c, &format!("catalog transaction failed: {e}")));
                continue;
            }
        };

        // Test-only fault seam: simulate a crash between the DB commit and the
        // stored rename. The index is already clean (committed from in-mem bytes);
        // the stored file stays raw. Proves index-no-leak at this exact crash point.
        if !faulted_once && fault_after_commit() {
            faulted_once = true;
            report.failed.push(fail_label(
                c,
                "fault-injection: stored rename skipped after DB commit",
            ));
            continue;
        }

        // Atomic stored swap — after the DB commit.
        if let Err(e) = std::fs::rename(&tmp, &dest) {
            let _ = std::fs::remove_file(&tmp);
            report
                .failed
                .push(fail_label(c, &format!("stored rename failed: {e}")));
            continue;
        }

        update_session_manifest(env, c, &rr, quarantined_new);

        // Post-write verification (belt-and-suspenders; the pre-write gate already
        // proved idempotence). Any residual is a bug and counts as a verify failure.
        if !post_verify(cat, &archive_dir, c, &rr, is_jsonl, allow)? {
            report.verify_failures += 1;
        }

        report.reredacted += 1;
        report.secrets_removed += actionable_count(&rr.scan);
        report.index_rows_purged += purged;
        report.index_rows_rebuilt += doc_count;
        match rr.transition {
            Transition::VisibleQuarantine => report.visible_quarantine_transitions += 1,
            Transition::WholeQuarantine => report.whole_quarantine_transitions += 1,
            Transition::InPlaceRedact => {}
        }
    }
    Ok(report)
}

/// Skip predicate: is this artifact a genuine, already-processed whole-quarantine
/// marker? Both a strict single-token stored shape AND catalog provenance
/// (`quarantined == 1`, set by yomi itself, unforgeable by a source) are required.
///
/// The two checks are independent defenses against a gap-era *forged* leading
/// marker followed by a real secret. Shape: the trailing secret breaks the
/// single-token match. Provenance: a gap-era forged marker was flag-only, so its
/// catalog row is `quarantined = 0`. A genuine marker satisfies both, so the
/// infinite-re-quarantine guard is preserved; a forged one satisfies neither and
/// is rescanned so its secret is removed.
fn is_genuine_whole_quarantine(c: &IndexCandidate, stored: &[u8]) -> bool {
    c.quarantined && stored_is_whole_quarantine(stored)
}

/// Target predicate + transition, without the compress/sha work. `None` when the
/// stored bytes would not change (already clean or already the desired redaction).
/// Whole-quarantine markers are filtered out by the caller.
fn evaluate_target(
    role: &str,
    stored: &[u8],
    allow: &Allowlist,
) -> Option<(ContentScan, Transition)> {
    let scan = scan_content_with(
        stored,
        rescan_is_jsonl(role),
        allow,
        ScanOpts {
            trust_existing_tags: true,
        },
    );
    if scan.redacted == stored {
        return None;
    }
    let transition = if !scan.scanned {
        Transition::WholeQuarantine
    } else if scan.needs_quarantine {
        Transition::VisibleQuarantine
    } else {
        Transition::InPlaceRedact
    };
    Some((scan, transition))
}

/// [`evaluate_target`] plus the committed re-redaction (redacted bytes, compressed
/// frame, hashes). Used only by the commit path, where those values are consumed.
fn evaluate(role: &str, stored: &[u8], allow: &Allowlist) -> Result<Option<Reredaction>> {
    let Some((scan, transition)) = evaluate_target(role, stored, allow) else {
        return Ok(None);
    };
    let new_content = scan.redacted.clone();
    let new_content_sha = sha256_hex(&new_content);
    let new_frame = compress_frame(&new_content)?;
    let new_stored_sha = sha256_hex(&new_frame);
    Ok(Some(Reredaction {
        scan,
        new_content,
        new_content_sha,
        new_frame,
        new_stored_sha,
        transition,
    }))
}

/// Whether `content` is free of any raw secret we could still remove: a
/// whole-quarantine marker (secret held only in quarantine) is clean, otherwise
/// re-redaction must be idempotent. This is the fail-closed gate.
fn is_reredaction_clean(content: &[u8], is_jsonl: bool, allow: &Allowlist) -> bool {
    if stored_is_whole_quarantine(content) {
        return true;
    }
    let v = scan_content_with(
        content,
        is_jsonl,
        allow,
        ScanOpts {
            trust_existing_tags: true,
        },
    );
    v.redacted == content
}

/// Prove no raw secret survived on either face: the stored copy re-verifies
/// against the catalog and is idempotent, and every indexed doc's text is clean.
fn post_verify(
    cat: &Catalog,
    archive_dir: &Path,
    c: &IndexCandidate,
    rr: &Reredaction,
    is_jsonl: bool,
    allow: &Allowlist,
) -> Result<bool> {
    if !verify_stored(
        archive_dir,
        &c.stored_path,
        &rr.new_stored_sha,
        &rr.new_content_sha,
    )? {
        return Ok(false);
    }
    if !is_reredaction_clean(&rr.new_content, is_jsonl, allow) {
        return Ok(false);
    }
    for t in cat.entries_text_for_artifact(c.artifact_id)? {
        if !is_reredaction_clean(t.as_bytes(), false, allow) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Update the session manifest for the roles that carry one (transcript /
/// subagent / tool-result). Best-effort: the catalog is authority for verify / GC
/// / index, so a manifest write failure never blocks remediation.
fn update_session_manifest(env: &Env, c: &IndexCandidate, rr: &Reredaction, quarantined: bool) {
    if !matches!(c.role.as_str(), "transcript" | "subagent" | "tool-result") {
        return;
    }
    let Some(slug) = c.project_slug.as_deref() else {
        return;
    };
    let path = env.session_dir(slug, &c.session_uuid).join("manifest.json");
    let Ok(mut m) = manifest::read(&path) else {
        return;
    };
    let Some(rec) = m.artifacts.iter_mut().find(|a| a.source == c.source_path) else {
        return;
    };
    rec.stored_sha256 = rr.new_stored_sha.clone();
    rec.stored_bytes = rr.new_frame.len() as u64;
    rec.content_sha256 = rr.new_content_sha.clone();
    rec.redacted = true;
    rec.quarantined = quarantined;
    rec.scan = artifact_scan(&rr.scan);
    // The collapsed single frame covers the captured source span [0,
    // last_src_offset), not the full current source size: for a partially-captured
    // appendable artifact `source_bytes` overstates what the stored bytes actually
    // derive from. The manifest is non-authoritative (the catalog drives verify /
    // GC / index) and the next archive run self-heals via its prefix check, but
    // recording the true span keeps it accurate.
    rec.frames = vec![Frame {
        src_offset: 0,
        src_len: c.last_src_offset,
        captured_at: now_iso(),
    }];
    m.secret_scan = summarize_records(&m.artifacts);
    let _ = manifest::write(&path, &m);
}

fn candidates(cat: &Catalog, session: Option<&str>) -> Result<Vec<IndexCandidate>> {
    match session {
        Some(s) => cat.index_candidates_for_session(s),
        None => cat.index_candidates(),
    }
}

fn read_stored(archive_dir: &Path, stored_path: &str) -> Option<Vec<u8>> {
    let raw = std::fs::read(archive_dir.join(stored_path)).ok()?;
    decompress_all(&raw).ok()
}

/// Mirrors `archive::role_is_jsonl`: only the conversation JSONL roles get the
/// strict structural gate. `mcp` is `.jsonl`-shaped but scanned as plain text.
fn rescan_is_jsonl(role: &str) -> bool {
    matches!(role, "transcript" | "subagent" | "history")
}

fn kind_counts(scan: &ContentScan) -> BTreeMap<String, u32> {
    let mut m = BTreeMap::new();
    for f in &scan.findings {
        if matches!(f.action, FindingAction::Redact | FindingAction::Quarantine) {
            *m.entry(f.kind.clone()).or_insert(0) += 1;
        }
    }
    m
}

fn actionable_count(scan: &ContentScan) -> u64 {
    scan.findings
        .iter()
        .filter(|f| matches!(f.action, FindingAction::Redact | FindingAction::Quarantine))
        .count() as u64
}

fn fail_label(c: &IndexCandidate, reason: &str) -> String {
    format!(
        "{} [{}] {} — {}",
        c.session_uuid, c.role, c.source_path, reason
    )
}

fn write_temp(dest: &Path, bytes: &[u8]) -> Result<PathBuf> {
    let tmp = dest.with_extension(format!(
        "rescan-tmp-{}-{}",
        std::process::id(),
        now_iso().replace([':', '.'], "")
    ));
    std::fs::write(&tmp, bytes)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    Ok(tmp)
}

/// Test-only fault seam (see the crash-safety note at module top). Compiled only
/// in debug builds — the e2e tests drive the debug binary and set
/// `YOMI_RESCAN_FAULT`, while a release binary can never inject the fault, so a
/// stray environment variable in production cannot strand an artifact as stale raw.
#[cfg(debug_assertions)]
fn fault_after_commit() -> bool {
    std::env::var_os("YOMI_RESCAN_FAULT").is_some()
}

#[cfg(not(debug_assertions))]
fn fault_after_commit() -> bool {
    false
}
