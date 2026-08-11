pub mod compress;
pub mod incremental;
pub mod manifest;

use crate::blacklist::{Blacklist, GuardOutcome};
use crate::catalog::{ArtifactUpsert, Catalog, SessionUpsert};
use crate::config::Env;
use crate::model::{ArtifactRecord, ArtifactRole, Finding, Frame, Manifest, SecretScanSummary};
use crate::scan::{Allowlist, ContentScan, scan_content};
use crate::scratch::{
    ManifestRead, NotStored, ScratchEntry, ScratchManifest, ScratchRel, StoreDir,
};
use crate::source::claude::DiscoveredSession;
use crate::source::single::{ScratchDir, SingleFile};
use crate::util::{now_iso, sha256_hex};
use anyhow::{Context, Result};
use compress::{compress_frame, decompress_all};
use incremental::{Plan, plan};
use std::path::{Path, PathBuf};

/// Running totals for one `yomi archive` invocation.
#[derive(Debug, Default)]
pub struct Report {
    pub sessions: u64,
    pub artifacts_written: u64,
    pub artifacts_skipped: u64,
    pub bytes_stored: u64,
    pub findings: u64,
    pub redacted: u64,
    pub quarantined: u64,
    pub flagged: u64,
    pub blacklisted_skipped: u64,
    pub oversize_skipped: u64,
    /// Artifacts left unarchived because their unredacted original could not be
    /// written to `quarantine/`. Counted, not merely logged: the artifact is
    /// silently absent from the store until the cause is fixed, and stderr is
    /// discarded under cron.
    pub quarantine_refused: u64,
    /// Stored scratch artifacts the new manifest no longer claims, removed to
    /// keep the store dir and the manifest one ledger. Counted (not performed)
    /// under `--dry-run`. Surfaced because a config change that discards stored
    /// bytes must be loud.
    pub scratch_orphans_removed: u64,
    /// The subset of `scratch_orphans_removed` the `[scratch]` caps account for:
    /// this run's `file_cap` declined the file, or its `total_cap` declined the
    /// whole tree.
    ///
    /// Loud counts a removal; this names the **rule** that caused it. Without it
    /// a `--full` run followed by a plain one reports "N artifacts removed" with
    /// no cause, indistinguishable from an operator having edited the globs —
    /// which is the sharpest data-loss path `--full` opens, since the narrower
    /// run is the one that deletes.
    pub scratch_orphans_cap_declined: u64,
    /// Store keys where the removal above happened *and* the prior ledger
    /// recorded `caps_lifted` — a `--full` run stored those bytes and this run,
    /// with the caps in force, dropped them. The other half of the cause: the
    /// rule, and the run whose output it acted on.
    pub scratch_keys_caps_reimposed: u64,
}

pub struct Archiver<'a> {
    pub env: &'a Env,
    pub blacklist: &'a Blacklist,
    pub allow: &'a Allowlist,
    pub catalog: &'a Catalog,
    pub scan_enabled: bool,
    /// Force quarantine of the original for MED findings too, not just HIGH.
    pub quarantine_all: bool,
    /// `--full`: the `[scratch]` caps decline nothing this run — neither
    /// `file_cap` per file nor `total_cap` per tree.
    ///
    /// **Exactly the caps.** The allow/deny globs still decide what is stored, so
    /// `NotStored::{NotAllowed, Denied}` are unaffected and a `.git` tree is no
    /// more archivable under `--full` than without it; only `NotStored::FileCap`
    /// and `over_total_cap` become unreachable. The sizes are still measured and
    /// both tree totals — `total_bytes` and `admitted_bytes` — are still recorded:
    /// lifting a cap is not a reason to stop knowing what it would have declined.
    pub caps_lifted: bool,
    pub dry_run: bool,
}

/// Outcome of capturing one artifact.
struct CaptureOut {
    record: ArtifactRecord,
    /// Stored path relative to the archive root (catalog key for verify).
    stored_archive_rel: String,
    findings: Vec<Finding>,
}

impl<'a> Archiver<'a> {
    /// Archive one session: transcript, subagents, subagent metas, tool-results,
    /// per the requested `includes`. Writes/updates `manifest.json` + catalog.
    pub fn archive_session(
        &self,
        session: &DiscoveredSession,
        includes: &[crate::source::Include],
        report: &mut Report,
    ) -> Result<()> {
        use crate::source::Include::*;

        let session_dir = self
            .env
            .session_dir(&session.project_slug, &session.session_uuid);
        if !self.dry_run {
            self.store_dirs(&session_dir)?;
        }

        let mut outs: Vec<CaptureOut> = Vec::new();
        let mut meta = TranscriptMeta::default();

        // Load prior manifest so incremental frame ledgers and untouched
        // artifact records survive across runs.
        let manifest_path = session_dir.join("manifest.json");
        let prior_manifest = manifest_path
            .exists()
            .then(|| manifest::read(&manifest_path).ok())
            .flatten();

        // Transcript (always, unless explicitly excluded).
        if includes.contains(&Transcript)
            && let Some(bytes) = self.read_source(&session.transcript, report)?
        {
            meta = TranscriptMeta::parse(&bytes);
            if let Some(out) = self.capture(
                &session.transcript,
                ArtifactRole::Transcript,
                &bytes,
                &session_dir,
                "transcript.jsonl.zst",
                prior_frames(&prior_manifest, &session.transcript),
                report,
            )? {
                outs.push(out);
            }
        }

        if includes.contains(&Subagents) {
            for sub in &session.subagent_transcripts {
                let Some(bytes) = self.read_source(sub, report)? else {
                    continue;
                };
                let rel = format!("subagents/{}.jsonl.zst", file_stem(sub));
                if let Some(out) = self.capture(
                    sub,
                    ArtifactRole::Subagent,
                    &bytes,
                    &session_dir,
                    &rel,
                    prior_frames(&prior_manifest, sub),
                    report,
                )? {
                    outs.push(out);
                }
            }
            for m in &session.subagent_metas {
                let Some(bytes) = self.read_source(m, report)? else {
                    continue;
                };
                let rel = format!("subagents/{}", file_name(m));
                if let Some(out) = self.capture_meta(
                    m,
                    ArtifactRole::SubagentMeta,
                    &bytes,
                    &session_dir,
                    &rel,
                    report,
                )? {
                    outs.push(out);
                }
            }
        }

        if includes.contains(&ToolResults) {
            for tr in &session.tool_results {
                let Some(bytes) = self.read_source(tr, report)? else {
                    continue;
                };
                let rel = format!("tool-results/{}.zst", file_name(tr));
                if let Some(out) = self.capture(
                    tr,
                    ArtifactRole::ToolResult,
                    &bytes,
                    &session_dir,
                    &rel,
                    Vec::new(),
                    report,
                )? {
                    outs.push(out);
                }
            }
        }

        // Nothing captured this run: leave any prior manifest and catalog
        // untouched, and don't count the session as archived.
        if outs.is_empty() {
            return Ok(());
        }
        report.sessions += 1;
        if self.dry_run {
            return Ok(());
        }

        // Commit all catalog mutations for this session atomically (B3a).
        self.catalog.transaction(|| {
            for out in &outs {
                let id = self.upsert(&session.session_uuid, out)?;
                self.catalog.replace_findings(id, &out.findings)?;
            }
            self.catalog.upsert_session(&SessionUpsert {
                uuid: &session.session_uuid,
                project_slug: &session.project_slug,
                cwd: meta.cwd.as_deref(),
                git_branch: meta.git_branch.as_deref(),
                cc_version: meta.cc_version.as_deref(),
            })
        })?;

        // Rebuild the manifest by merging this run's records over the prior
        // manifest's, so untouched artifacts (and their scan provenance) are
        // preserved rather than truncated (倶生B1).
        let mut by_source: std::collections::BTreeMap<String, ArtifactRecord> = prior_manifest
            .as_ref()
            .map(|m| {
                m.artifacts
                    .iter()
                    .cloned()
                    .map(|a| (a.source.clone(), a))
                    .collect()
            })
            .unwrap_or_default();
        for out in &outs {
            by_source.insert(out.record.source.clone(), out.record.clone());
        }
        let artifacts: Vec<ArtifactRecord> = by_source.into_values().collect();

        let mut manifest =
            Manifest::new(session.session_uuid.clone(), session.project_slug.clone());
        manifest.cwd = meta.cwd.clone();
        manifest.git_branch = meta.git_branch.clone();
        manifest.cc_version = meta.cc_version.clone();
        manifest.session_start = meta.session_start.clone();
        manifest.session_end = meta.session_end.clone();
        manifest.entry_count = meta.entry_count;
        manifest.includes = includes.iter().map(|i| format!("{i:?}")).collect();
        manifest.secret_scan = summarize_records(&artifacts);
        if let Some(t) = artifacts
            .iter()
            .find(|r| r.role == ArtifactRole::Transcript)
        {
            manifest.incremental.last_src_offset = t.source_bytes;
            manifest.incremental.prior_capture = prior_manifest.map(|m| m.captured_at);
        }
        manifest.artifacts = artifacts;
        manifest::write(
            &self.env.archive_dir(),
            self.store_rel(&manifest_path)?,
            &manifest,
        )?;
        Ok(())
    }

    /// Archive a single-file source (history/mcp/snapshot/paste) into its
    /// category store. History is appendable; the rest are whole-file.
    pub fn archive_single(&self, sf: &SingleFile, report: &mut Report) -> Result<()> {
        let Some(bytes) = self.read_source(&sf.source, report)? else {
            return Ok(());
        };
        let appendable = sf.category == "_history";
        let category_dir = match &sf.subgroup {
            Some(g) => self.env.archive_dir().join(sf.category).join(g),
            None => self.env.archive_dir().join(sf.category),
        };
        if !self.dry_run {
            self.store_dirs(&category_dir)?;
        }
        let stem = if appendable {
            "history.jsonl.zst".to_string()
        } else {
            format!("{}.zst", file_name(&sf.source))
        };
        let rel = category_dir
            .strip_prefix(self.env.archive_dir())
            .unwrap_or(&category_dir)
            .join(&stem)
            .to_string_lossy()
            .to_string();

        let uuid = sf.category.to_string();
        let prior_frames = self.prior_single_frames(&rel);
        let out = self.capture(
            &sf.source,
            role_for_category(sf.category),
            &bytes,
            &self.env.archive_dir(),
            &rel,
            prior_frames,
            report,
        )?;
        if let Some(out) = out
            && !self.dry_run
        {
            self.catalog.transaction(|| {
                let id = self.upsert(&uuid, &out)?;
                self.catalog.replace_findings(id, &out.findings)
            })?;
        }
        Ok(())
    }

    /// Reconstruct the frame ledger for an appendable single-file store from
    /// the catalog's committed offset (there is no per-category manifest).
    fn prior_single_frames(&self, archive_rel: &str) -> Vec<Frame> {
        // Single-file stores use whole-file semantics except `_history`, whose
        // frames are rebuilt from the stored file on append; an empty ledger is
        // acceptable because `capture` re-derives from the store's decoded prefix.
        let _ = archive_rel;
        Vec::new()
    }

    /// Archive one scratch dir: manifest **every** file in the session tree
    /// (name, size, and — for stored files only — hashes); store only the files
    /// the `[scratch]` allow/deny globs admit under the size caps. Globs match the
    /// session-relative path with nested (`**/`) semantics, so a cloned repo's
    /// `.git`/`node_modules` are excluded wherever they sit (W2). A tree whose
    /// **admitted** bytes exceed `total_cap` is manifest-only: nothing is stored,
    /// and every live entry is recorded `stored: false`.
    ///
    /// Two ledger duties beyond writing the manifest:
    ///
    /// * an entry whose live file has **vanished** keeps its record and its
    ///   `.zst` verbatim, marked `present: false` — that artifact is the last
    ///   copy and no cap decision authorizes destroying it;
    /// * every other `*.zst` the new manifest does not claim is **removed**, so
    ///   the store dir and the manifest stay one ledger (store law S, §3).
    pub fn archive_scratch(&self, sc: &ScratchDir, report: &mut Report) -> Result<()> {
        let cfg = &self.env.config.scratch;
        let allow = build_globs_nested(&cfg.allow)?;
        let deny = build_globs_nested(&cfg.deny)?;

        // The root gets the same classification a key does. Every path below it
        // is resolved *through* it, so a foreign root makes every key foreign
        // while each one still classifies `Own` on its own — the guard has to sit
        // at both levels or it sits at neither.
        let root = crate::scratch::store_root(&self.env.archive_dir());
        if crate::scratch::classify_store_dir(&root) == StoreDir::Foreign {
            tracing::warn!(
                store_root = %root.display(),
                "scratch store root is not a directory this run owns; archiving no \
                 scratch until it is a real directory again."
            );
            return Ok(());
        }
        let store_dir = root.join(&sc.key);

        // The writes below descend fd by fd and would refuse this on their own;
        // the classification is here for the *other* half — checked before the
        // manifest is read, so a foreign ledger never informs a decision. It also
        // makes the refusal a named per-key skip rather than an I/O error out of
        // the descent, which is what keeps one bad key from ending the run.
        //
        // Refused, not repaired — unlike the lock file, whose symlink is
        // self-healed. That file holds nothing, so removing a link node there
        // destroys nothing; a store directory holds archived data, and a symlink
        // on it may well be an operator who deliberately put the store on
        // another volume. Replacing it would orphan that store and silently
        // begin an empty one. Refusing is reversible by hand; replacing is not.
        if crate::scratch::classify_store_dir(&store_dir) == StoreDir::Foreign {
            tracing::warn!(
                key = %sc.key,
                store = %store_dir.display(),
                "scratch store path is not a directory this run owns; leaving this \
                 key untouched. Nothing is archived or removed for it until the path \
                 is a real directory again."
            );
            return Ok(());
        }

        let prior = match crate::scratch::read_manifest_at(&store_dir.join("manifest.json")) {
            ManifestRead::Ok(mf) => Some(mf),
            // No ledger at all: nothing to carry, and nothing to contradict.
            ManifestRead::Missing => None,
            // A ledger that exists but cannot be read says nothing about the
            // artifacts beside it — including that they are unclaimed. This key
            // is left exactly as found: nothing stored, nothing deleted, and
            // above all the unreadable manifest is **not overwritten**. Replacing
            // it with a ledger describing only the live tree would manufacture
            // the confidence that lets the *next* run delete every archive-only
            // copy it failed to mention, turning a refusal into a one-run
            // reprieve.
            ManifestRead::Unreadable => {
                tracing::warn!(
                    key = %sc.key,
                    store = %store_dir.display(),
                    "scratch ledger exists but cannot be read; leaving this store \
                     untouched. Nothing is archived or removed for this key until \
                     the manifest is repaired or removed."
                );
                return Ok(());
            }
        };

        // Immediately after the manifest is read and before any write, any
        // reconciliation and any coverage judgment. A store key is not injective
        // — `store_key("a", "-b") == store_key("a-", "b")` — so two session
        // directories can map to one store, and the second to arrive would
        // otherwise claim the first's identity and overwrite its only archived
        // copy. Refusing here is what makes the key injective *in effect*, at no
        // migration cost: the ledger records the identity, and whoever does not
        // match it stops.
        if let Some(mf) = &prior {
            match crate::scratch::identity_verdict(mf, &sc.session_dir) {
                crate::scratch::IdentityVerdict::Proceed => {}
                // What stops is *this* tree, not both. The one the ledger names
                // goes on being archived and reclaimed — deliberately: a
                // symmetric rule would let anyone able to `mkdir` under
                // `/tmp/claude-<uid>/` freeze an existing tree's archive by
                // choosing a colliding name, where refusing pair-wise lets an
                // actor at that uid refuse only itself.
                crate::scratch::IdentityVerdict::Collision => {
                    tracing::warn!(
                        key = %sc.key,
                        store = %store_dir.display(),
                        session = %sc.session_dir.display(),
                        "two session directories map to this store key, and its \
                         ledger belongs to the other one; leaving this tree \
                         unarchived. Nothing is archived or removed for it until \
                         one of the two is renamed."
                    );
                    return Ok(());
                }
                // An identity this run cannot read is not a licence to write
                // through it. Proceeding would restamp the field with *this*
                // tree's identity and claim a store that may well be another
                // tree's — the overwrite the recorded identity exists to stop,
                // reopened by a single corrupted byte.
                crate::scratch::IdentityVerdict::Refuse => {
                    tracing::warn!(
                        key = %sc.key,
                        store = %store_dir.display(),
                        "this store's recorded tree identity cannot be read; \
                         leaving this key untouched. Nothing is archived or \
                         removed for it until the manifest is repaired or \
                         removed — an identity nobody can read is not evidence \
                         that this tree owns this store."
                    );
                    return Ok(());
                }
            }
        }

        // Whether the bytes this run may be about to reconcile away were stored by
        // a run that had the caps lifted. Read before the walk, because the
        // manifest is about to be replaced by this run's.
        let prior_caps_lifted = prior.as_ref().is_some_and(|mf| mf.caps_lifted);

        // The whole session tree, not `scratchpad/` + `tasks/*.output`: the
        // deleter removes `<slug>/<uuid>/` entire, so a live file the writer
        // never manifests is one the GC gate cannot account for, and the tree is
        // refused forever. Sorted because `WalkDir` yields in filesystem order.
        let mut candidates: Vec<PathBuf> = walkdir::WalkDir::new(&sc.session_dir)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().to_path_buf())
            .collect();
        candidates.sort();

        let mut entries: Vec<ScratchEntry> = Vec::new();
        let mut kept: Vec<(PathBuf, ScratchRel)> = Vec::new();
        let mut denied: Vec<ScratchRel> = Vec::new();
        // Identities a `[scratch]` cap declined this run, collected as the
        // decisions are taken rather than reconstructed at reconcile time: after
        // the tree cap flips `stored`, an entry it declined is indistinguishable
        // from one the globs never admitted, and the two send an operator to
        // different edits. Empty under `--full`, where no cap declines anything.
        let mut cap_declined: std::collections::HashSet<ScratchRel> =
            std::collections::HashSet::new();
        // Two tree totals, because two different questions are asked of them.
        // `total` is every live candidate's bytes — the tree's footprint, which is
        // what `total_bytes` records and what a reclaim will actually remove.
        // `admitted` is the subset policy would store, and it is the one
        // `total_cap` is compared against (decision #9).
        let mut total: u64 = 0;
        let mut admitted: u64 = 0;
        for path in &candidates {
            if self.blacklist.is_blacklisted(path) {
                report.blacklisted_skipped += 1;
                // Collected, not manifested here. Two facts are in play and they
                // are orthogonal: this identity may hold a prior run's archived
                // copy (keep it — that `.zst` is the last copy), and its name is
                // now occupied by a denylisted inode (refuse the tree, and say
                // why). They were coupled only by the accident that manifesting
                // an entry put it in the live set, which cost the first fact.
                // Staying out of the live set leaves retention untouched; the
                // flag is stamped after the tail is assembled.
                if let Some(rel) = ScratchRel::from_live(&sc.session_dir, path) {
                    denied.push(rel);
                }
                continue;
            }
            // Identity first: a candidate with no session-relative identity has
            // no manifest key and no store path, so it cannot be archived. Every
            // candidate comes from a walk of `session_dir`, so this is
            // unreachable; leaving it unmanifested refuses the tree, which is the
            // safe side of an impossible case.
            let Some(rel) = ScratchRel::from_live(&sc.session_dir, path) else {
                tracing::warn!(path = %path.display(), "scratch candidate escapes its session dir; skipped");
                continue;
            };
            let Ok(md) = std::fs::metadata(path) else {
                continue;
            };
            let size = md.len();
            let glob_key = rel.glob_subpath();
            let subpath: &str = &glob_key;
            // Record *which* rule declined, in the order `store = allow && !deny
            // && size <= file_cap` evaluates them. A reader that reconstructs the
            // cause from the config in force later gets it wrong the moment the
            // config moves, and a retained entry carries its decision across
            // several config generations.
            let not_stored = if !allow.is_match(subpath) {
                Some(NotStored::NotAllowed)
            } else if deny.is_match(subpath) {
                Some(NotStored::Denied)
            } else if !self.caps_lifted && size > cfg.file_cap.0 {
                Some(NotStored::FileCap)
            } else {
                None
            };
            if not_stored == Some(NotStored::FileCap) {
                cap_declined.insert(rel.clone());
            }
            total += size;
            if not_stored.is_none() {
                admitted += size;
            }
            entries.push(ScratchEntry::new(&rel, size, not_stored));
            kept.push((path.clone(), rel));
        }

        // The cap is a property of the whole tree, so it can only be applied once
        // every candidate has been sized — hence a second pass rather than a term
        // in `store` above. An over-cap tree stores nothing, and no entry may
        // claim otherwise: `stored: true` with no `.zst` and no hashes reads to
        // the GC gate as a corrupt archive, which refuses the tree forever (the
        // 134M clone the cap exists for was never reclaimable). `over_total_cap`
        // already records why nothing was stored — design §3, decision #4.
        //
        // **`admitted`, not `total`** (decision #9). Comparing the whole tree let
        // the bytes the globs had already refused decide the fate of the bytes
        // they admitted: one `target/` or `.git` beside a few MB of notes carried
        // the tree over the cap, after which nothing was stored — and it bought
        // nothing, because reclaimability does not depend on the cap. A
        // `stored: false` entry takes the gate's presence+size path whether it was
        // never admitted or declined here.
        //
        // Both totals are accumulated either way: `--full` lifts the cap, not the
        // measurement, and a later reader needs the footprint *and* the quantity
        // the cap is a verdict on.
        let over_total = !self.caps_lifted && admitted > cfg.total_cap.0;
        if over_total {
            for (entry, (_, rel)) in entries.iter_mut().zip(kept.iter()) {
                if entry.stored {
                    cap_declined.insert(rel.clone());
                }
                entry.stored = false;
            }
        }

        // What an earlier run captured for each identity. A capture that fails
        // this run must not discard it: those bytes are the last copy.
        let prior_by_rel: std::collections::HashMap<ScratchRel, &ScratchEntry> = prior
            .as_ref()
            .map(|mf| {
                mf.entries
                    .iter()
                    .filter_map(|e| e.rel().map(|r| (r, e)))
                    .collect()
            })
            .unwrap_or_default();

        if !self.dry_run {
            // Every level, including `archive/_scratch/` itself: the descent
            // modes each directory it opens, and the creator is what asserts the
            // mode. `ensure_layout` does not cover `_scratch` (it is one artifact
            // family's root, not the store's), and `Archiver` is a library type a
            // caller can use without ever having tightened the umask.
            self.store_dirs(&store_dir)?;
            for (entry, (path, rel)) in entries.iter_mut().zip(kept.iter()) {
                if !entry.stored {
                    continue;
                }
                // Policy said to store this file and the read then refused it:
                // a blacklisted inode swapped in after the walk, an I/O or
                // permission error, or a file that outgrew the read bound
                // between stat and read.
                let Some(bytes) = self.read_source(path, report)? else {
                    let salvaged = salvage(entry, rel, &prior_by_rel, &store_dir);
                    tracing::warn!(
                        path = %path.display(),
                        kept_earlier_capture = salvaged,
                        "scratch source could not be captured; this tree will not be \
                         reclaimed until it can be read"
                    );
                    continue;
                };
                let dest = store_dir.join(rel.store_rel());
                let scan = self.scan_bytes(&bytes, false);
                self.tally(report, &scan);
                if scan.needs_quarantine {
                    // Nothing of this file may enter the store while its
                    // unredacted original is unpreserved — the store copy is
                    // redacted or an opaque marker, so writing it and losing the
                    // original leaves the secret-bearing bytes only in the live
                    // file, which the gate would then let GC reclaim. The fourth
                    // path to `capture_failed`, and it records the same single
                    // ledger fact as the three source-read refusals: not one byte
                    // of this file's content was captured.
                    if let Err(e) = self.quarantine(&dest, &bytes, report) {
                        report.quarantine_refused += 1;
                        let salvaged = salvage(entry, rel, &prior_by_rel, &store_dir);
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            kept_earlier_capture = salvaged,
                            "the unredacted original could not be quarantined; this file \
                             is left unarchived and its tree will not be reclaimed"
                        );
                        continue;
                    }
                    entry.quarantined = true;
                }
                self.store_write(&dest, &compress_frame(&scan.redacted)?)?;
                report.bytes_stored += std::fs::metadata(&dest)?.len();
                entry.source_sha256 = Some(sha256_hex(&bytes));
                entry.content_sha256 = Some(sha256_hex(&scan.redacted));
            }
        }

        // Appended after the store pass and after the cap, so what the prior
        // ledger carries over can be neither re-policied nor counted against the
        // live tree.
        let (tail, ledger_complete) = match &prior {
            Some(mf) => prior_tail(mf, &kept),
            // A store dir with no ledger holds no archive-only copy this run
            // could be destroying.
            None => (Vec::new(), true),
        };
        entries.extend(tail);

        // After the tail, so a retained entry carrying this identity is already
        // present to receive the flag. Stamping rather than appending is what
        // keeps this from manufacturing the duplicate identity §5 reports, and
        // doing it here rather than in the candidate loop is what keeps
        // `entries` and `kept` — parallel vectors the store pass zips by index —
        // in correspondence: an entry with no live file to read would break it.
        //
        // `present` is untouched. A file that became denylisted this run is
        // treated as gone and its archive retained; `present: false` is that
        // conservative reading and deliberately not a claim about whether the
        // *name* is occupied. `blacklisted: true` is what answers that.
        for rel in &denied {
            match entries.iter_mut().find(|e| e.rel().as_ref() == Some(rel)) {
                Some(e) => e.blacklisted = true,
                None => entries.push(ScratchEntry::blacklisted(rel)),
            }
        }

        if !ledger_complete {
            tracing::warn!(
                key = %sc.key,
                "prior scratch ledger holds an entry whose identity does not \
                 decode; store dir left untouched. Its artifact cannot even be \
                 named, so stale artifacts remain until the manifest is repaired — \
                 an unreadable record is a reason to refuse, not a licence to \
                 delete what it describes."
            );
        }

        if !self.dry_run {
            // Stamped on every write, so a store written before these fields
            // gains its identity the first time a knowing writer touches it —
            // and the collision refusal above starts holding for it from then on.
            let (slug_hex, uuid_hex) = crate::scratch::identity_hex(&sc.session_dir);
            let mf = ScratchManifest {
                key: sc.key.clone(),
                slug_hex,
                uuid_hex,
                captured_at: now_iso(),
                total_bytes: total,
                admitted_bytes: Some(admitted),
                over_total_cap: over_total,
                caps_lifted: self.caps_lifted,
                entries,
            };
            let mfp = store_dir.join("manifest.json");
            self.store_write(&mfp, (serde_json::to_string_pretty(&mf)? + "\n").as_bytes())?;
            // Manifest first, then reconcile: a crash between them leaves a store
            // holding *more* than the ledger claims, which the GC gate ignores and
            // the next run cleans up. The reverse order would leave a ledger
            // claiming a `.zst` that is gone, which refuses the tree until someone
            // re-archives.
            if ledger_complete {
                let rec = reconcile_scratch_store(&store_dir, &mf.entries, &cap_declined, false)?;
                rec.tally(report, prior_caps_lifted);
            }
        } else if ledger_complete {
            let rec = reconcile_scratch_store(&store_dir, &entries, &cap_declined, true)?;
            rec.tally(report, prior_caps_lifted);
        }
        Ok(())
    }

    /// Open and read a source under the hard blacklist gate. The file is opened
    /// **once** and the denylist inode check runs against the opened fd's own
    /// metadata (fstat), so a path swapped to a credential hardlink between check
    /// and open cannot slip through (S3). Returns None if denied or oversized.
    fn read_source(&self, path: &Path, report: &mut Report) -> Result<Option<Vec<u8>>> {
        use std::io::Read;

        match self.blacklist.open_guarded(path)? {
            GuardOutcome::Denied => {
                report.blacklisted_skipped += 1;
                tracing::warn!(path = %path.display(), "blacklisted source refused");
                Ok(None)
            }
            GuardOutcome::Unreadable => {
                tracing::warn!(path = %path.display(), "skip unreadable source");
                Ok(None)
            }
            GuardOutcome::Opened(mut file, md) => {
                if md.len() > MAX_SOURCE_BYTES {
                    report.oversize_skipped += 1;
                    tracing::warn!(
                        path = %path.display(),
                        bytes = md.len(),
                        "source exceeds size cap; skipped (flagged)"
                    );
                    return Ok(None);
                }
                let mut bytes = Vec::with_capacity(md.len() as usize);
                file.read_to_end(&mut bytes)
                    .with_context(|| format!("read source {}", path.display()))?;
                Ok(Some(bytes))
            }
        }
    }

    /// Scan artifact content decode-first, honoring `--no-scan` and
    /// `--quarantine-on-secret`.
    fn scan_bytes(&self, content: &[u8], is_jsonl: bool) -> ContentScan {
        if !self.scan_enabled {
            return ContentScan {
                scanned: true,
                redacted: content.to_vec(),
                was_redacted: false,
                needs_quarantine: false,
                findings: Vec::new(),
                flagged: 0,
                redacted_count: 0,
            };
        }
        let mut out = scan_content(content, is_jsonl, self.allow);
        if self.quarantine_all
            && !out.needs_quarantine
            && out
                .findings
                .iter()
                .any(|f| f.action == crate::model::FindingAction::Redact)
        {
            out.needs_quarantine = true;
        }
        out
    }

    /// Capture an appendable or whole-file artifact. Scanning always runs over
    /// the full logical content `[0..end]` (decode-then-scan) so `\u`-escaped
    /// and multi-line secrets can't hide (B1/B2/R5); the store is written
    /// incrementally only when appending the new tail reproduces the full
    /// redacted content — otherwise the whole artifact is rewritten, which also
    /// self-heals a crash-interrupted prior append (B3a).
    #[allow(clippy::too_many_arguments)]
    fn capture(
        &self,
        source: &Path,
        role: ArtifactRole,
        source_bytes: &[u8],
        base_dir: &Path,
        rel: &str,
        prior_frames_vec: Vec<Frame>,
        report: &mut Report,
    ) -> Result<Option<CaptureOut>> {
        let source_path = canonical_key(source);
        let appendable = role.is_appendable();
        let is_jsonl = role_is_jsonl(role);
        let prior = self.catalog.prior_for_source(&source_path)?;
        let dest = base_dir.join(rel);
        let stored_archive_rel = archive_rel(self.env, &dest);

        let capture_plan = if appendable {
            plan(prior.as_ref(), source_bytes)
        } else {
            let full_sha = sha256_hex(source_bytes);
            match &prior {
                Some(p) if p.source_sha256 == full_sha => Plan::Skip,
                _ => Plan::Full {
                    end: source_bytes.len() as u64,
                },
            }
        };
        let (from, end) = match capture_plan {
            Plan::Skip => {
                report.artifacts_skipped += 1;
                return Ok(None);
            }
            Plan::Full { end } => (0u64, end),
            Plan::Tail { from, end } => (from, end),
        };

        let full = &source_bytes[..end as usize];
        let scan = self.scan_bytes(full, is_jsonl);
        let content_sha = sha256_hex(&scan.redacted);
        let needs_q = scan.needs_quarantine;

        // Choose append vs full rewrite. Append only if the current store
        // decodes to an exact prefix of the intended full redacted content.
        let mut append_from: Option<usize> = None;
        if from > 0
            && !self.dry_run
            && let Ok(raw) = std::fs::read(&dest)
            && let Ok(prior_dec) = decompress_all(&raw)
            && scan.redacted.starts_with(&prior_dec)
        {
            append_from = Some(prior_dec.len());
        }

        let frames = match append_from {
            Some(_) => {
                let mut f = prior_frames_vec;
                f.push(Frame {
                    src_offset: from,
                    src_len: end - from,
                    captured_at: now_iso(),
                });
                f
            }
            None => vec![Frame {
                src_offset: 0,
                src_len: end,
                captured_at: now_iso(),
            }],
        };

        // The original goes to quarantine **before** the store is touched, and a
        // failure there abandons the artifact rather than storing it anyway.
        // Storing the redacted copy while the raw original is lost is the one
        // ordering that destroys data: nothing downstream re-checks that the
        // original exists, so the catalog row would let GC delete the source and
        // the unredacted bytes would then exist nowhere. Skipping instead leaves
        // the source untouched and the next run re-captures it — the same
        // fail-closed shape `rescan::commit` already uses at its own quarantine
        // step, and the same asymmetry §3 rests on: refusing wrongly is repaired
        // by a later run, deleting wrongly is not.
        if needs_q {
            if self.dry_run {
                report.quarantined += 1;
            } else if let Err(e) = self.quarantine(&dest, full, report) {
                report.quarantine_refused += 1;
                tracing::warn!(
                    source = %source.display(),
                    error = %e,
                    "the unredacted original could not be quarantined; this artifact \
                     is left unarchived so the source stays the only copy of it"
                );
                return Ok(None);
            }
        }

        let (stored_sha, stored_bytes) = if self.dry_run {
            let frame = compress_frame(&scan.redacted)?;
            (sha256_hex(&frame), frame.len() as u64)
        } else {
            match append_from {
                Some(prior_len) => {
                    let remainder = &scan.redacted[prior_len..];
                    if !remainder.is_empty() {
                        self.store_append(&dest, &compress_frame(remainder)?)?;
                    }
                }
                None => self.store_write(&dest, &compress_frame(&scan.redacted)?)?,
            }
            let stored = std::fs::read(&dest)?;
            report.bytes_stored += stored.len() as u64;
            (sha256_hex(&stored), stored.len() as u64)
        };

        self.tally(report, &scan);

        let redacted_any = scan.was_redacted || self.catalog.artifact_redacted(&source_path)?;
        report.artifacts_written += 1;
        let record = ArtifactRecord {
            role,
            path: rel.to_string(),
            source: source_path,
            source_sha256: sha256_hex(full),
            source_bytes: end,
            stored_sha256: stored_sha,
            stored_bytes,
            content_sha256: content_sha,
            redacted: redacted_any,
            quarantined: needs_q,
            scan: artifact_scan(&scan),
            frames,
            parsed_meta: None,
        };
        Ok(Some(CaptureOut {
            record,
            stored_archive_rel,
            findings: scan.findings,
        }))
    }

    /// Capture a small JSON sidecar (subagent meta): decode-then-scanned and
    /// redacted-if-needed, stored uncompressed with a parsed convenience copy.
    #[allow(clippy::too_many_arguments)]
    fn capture_meta(
        &self,
        source: &Path,
        role: ArtifactRole,
        source_bytes: &[u8],
        base_dir: &Path,
        rel: &str,
        report: &mut Report,
    ) -> Result<Option<CaptureOut>> {
        let source_path = canonical_key(source);
        let full_sha = sha256_hex(source_bytes);
        if let Some(p) = self.catalog.prior_for_source(&source_path)?
            && p.source_sha256 == full_sha
        {
            report.artifacts_skipped += 1;
            return Ok(None);
        }
        let scan = self.scan_bytes(source_bytes, true);
        let needs_q = scan.needs_quarantine;
        let dest = base_dir.join(rel);
        let stored_archive_rel = archive_rel(self.env, &dest);
        let parsed_meta = serde_json::from_slice::<serde_json::Value>(&scan.redacted).ok();
        let content_sha = sha256_hex(&scan.redacted);

        // Before the store write, and abandoning the artifact on failure — see
        // the same step in `capture`.
        if needs_q {
            if self.dry_run {
                report.quarantined += 1;
            } else if let Err(e) = self.quarantine(&dest, source_bytes, report) {
                report.quarantine_refused += 1;
                tracing::warn!(
                    source = %source.display(),
                    error = %e,
                    "the unredacted original could not be quarantined; this artifact \
                     is left unarchived so the source stays the only copy of it"
                );
                return Ok(None);
            }
        }

        let (stored_sha, stored_bytes) = if self.dry_run {
            (sha256_hex(&scan.redacted), scan.redacted.len() as u64)
        } else {
            self.store_write(&dest, &scan.redacted)?;
            report.bytes_stored += scan.redacted.len() as u64;
            (sha256_hex(&scan.redacted), scan.redacted.len() as u64)
        };

        self.tally(report, &scan);

        report.artifacts_written += 1;
        let record = ArtifactRecord {
            role,
            path: rel.to_string(),
            source: source_path,
            source_sha256: full_sha,
            source_bytes: source_bytes.len() as u64,
            stored_sha256: stored_sha,
            stored_bytes,
            content_sha256: content_sha,
            redacted: scan.was_redacted,
            quarantined: needs_q,
            scan: artifact_scan(&scan),
            frames: vec![Frame {
                src_offset: 0,
                src_len: source_bytes.len() as u64,
                captured_at: now_iso(),
            }],
            parsed_meta,
        };
        Ok(Some(CaptureOut {
            record,
            stored_archive_rel,
            findings: scan.findings,
        }))
    }

    /// Where `dest` sits relative to `archive/`.
    ///
    /// A hard error rather than a fallback: every store path is built by joining
    /// onto the archive root, so one that is not under it is a bug — and writing
    /// it anyway is the thing this module is trying to stop.
    fn store_rel<'p>(&self, dest: &'p Path) -> Result<&'p Path> {
        dest.strip_prefix(self.env.archive_dir())
            .with_context(|| format!("{} is not inside the archive root", dest.display()))
    }

    /// Create every directory of `dir` under `archive/`, descending fd by fd.
    fn store_dirs(&self, dir: &Path) -> Result<()> {
        crate::safefs::make_dirs(&self.env.archive_dir(), self.store_rel(dir)?)?;
        Ok(())
    }

    /// Replace the artifact at `dest`, descending fd by fd from `archive/`.
    ///
    /// Every level is opened `O_NOFOLLOW` from its parent's descriptor and the
    /// file is created the same way, so nothing planted at an intermediate level
    /// can redirect the write or collect a `chmod` — the property the quarantine
    /// writer has had since the mirror rule landed, and which the store lacked.
    fn store_write(&self, dest: &Path, bytes: &[u8]) -> Result<()> {
        crate::safefs::write_under(&self.env.archive_dir(), self.store_rel(dest)?, bytes)
    }

    /// Append a frame to the artifact at `dest`, under the same guarantee.
    fn store_append(&self, dest: &Path, bytes: &[u8]) -> Result<()> {
        crate::safefs::append_under(&self.env.archive_dir(), self.store_rel(dest)?, bytes)
    }

    /// Add a scan's actionable tallies to the run report (Allowed excluded, N5).
    fn tally(&self, report: &mut Report, scan: &ContentScan) {
        report.findings += scan
            .findings
            .iter()
            .filter(|f| f.action != crate::model::FindingAction::Allowed)
            .count() as u64;
        report.redacted += scan.redacted_count as u64;
        report.flagged += scan.flagged as u64;
    }

    /// Quarantine the raw original of the artifact stored at `dest`.
    ///
    /// Takes the **store path** rather than a hand-built rel, so the mirror rule
    /// — `quarantine/<X>` holds the original of `archive/<X>.zst` — is derived
    /// from the artifact's own identity at every call site instead of being
    /// restated three ways.
    fn quarantine(&self, dest: &Path, original: &[u8], report: &mut Report) -> Result<()> {
        let stored_rel = dest.strip_prefix(self.env.archive_dir()).unwrap_or(dest);
        crate::scan::quarantine::quarantine_original(
            &self.env.quarantine_dir(),
            stored_rel,
            original,
        )?;
        report.quarantined += 1;
        Ok(())
    }

    fn upsert(&self, session_uuid: &str, out: &CaptureOut) -> Result<i64> {
        let r = &out.record;
        self.catalog.upsert_artifact(&ArtifactUpsert {
            session_uuid,
            role: r.role,
            source_path: &r.source,
            source_sha256: &r.source_sha256,
            source_bytes: r.source_bytes,
            last_src_offset: r.source_bytes,
            stored_path: &out.stored_archive_rel,
            stored_sha256: &r.stored_sha256,
            stored_bytes: r.stored_bytes,
            content_sha256: &r.content_sha256,
            redacted: r.redacted,
            quarantined: r.quarantined,
        })
    }
}

#[derive(Default)]
struct TranscriptMeta {
    cwd: Option<String>,
    git_branch: Option<String>,
    cc_version: Option<String>,
    entry_count: u64,
    session_start: Option<String>,
    session_end: Option<String>,
}

impl TranscriptMeta {
    fn parse(bytes: &[u8]) -> Self {
        let mut m = TranscriptMeta::default();
        let text = String::from_utf8_lossy(bytes);
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            m.entry_count += 1;
            if m.cwd.is_none() {
                m.cwd = v.get("cwd").and_then(|x| x.as_str()).map(String::from);
            }
            if m.git_branch.is_none() {
                m.git_branch = v
                    .get("gitBranch")
                    .and_then(|x| x.as_str())
                    .map(String::from);
            }
            if m.cc_version.is_none() {
                m.cc_version = v.get("version").and_then(|x| x.as_str()).map(String::from);
            }
            if let Some(ts) = v.get("timestamp").and_then(|x| x.as_str()) {
                if m.session_start.is_none() {
                    m.session_start = Some(ts.to_string());
                }
                m.session_end = Some(ts.to_string());
            }
        }
        m
    }
}

/// Upper bound on a single source read into memory (R11). Larger sources are
/// skipped and flagged rather than risking OOM; nothing yomi archives in P1
/// legitimately approaches this (transcripts are MBs; the runtime is blacklisted).
const MAX_SOURCE_BYTES: u64 = 256 * 1024 * 1024;

/// The conversation JSONL sources are held to the strict structural gate (every
/// line must parse). MCP debug logs, though `.jsonl`-shaped, are LOW-MED and may
/// carry non-JSON lines, so they are scanned as plain text (still escape-checked)
/// rather than risking a whole-file quarantine on a stray line.
fn role_is_jsonl(role: ArtifactRole) -> bool {
    matches!(
        role,
        ArtifactRole::Transcript | ArtifactRole::Subagent | ArtifactRole::History
    )
}

/// Canonical catalog key for a source path, so symlink/`..`/relative forms all
/// map to one row (R6). Falls back to a lexical normalization if the path is
/// gone by the time we key it.
pub fn canonical_key(source: &Path) -> String {
    source
        .canonicalize()
        .unwrap_or_else(|_| crate::util::abs_normalize(source))
        .to_string_lossy()
        .to_string()
}

/// Per-artifact scan tally for the manifest, so a merged summary folds cleanly.
pub fn artifact_scan(scan: &crate::scan::ContentScan) -> crate::model::ArtifactScan {
    crate::model::ArtifactScan {
        findings: scan
            .findings
            .iter()
            .filter(|f| f.action != crate::model::FindingAction::Allowed)
            .count() as u32,
        redacted: scan.redacted_count,
        flagged: scan.flagged,
        quarantined: scan.needs_quarantine,
    }
}

/// Fold every artifact's retained scan tally into the manifest summary, so an
/// incremental run reflects the whole session, not just what it touched.
pub fn summarize_records(records: &[ArtifactRecord]) -> SecretScanSummary {
    let mut s = SecretScanSummary {
        scanned: true,
        ..Default::default()
    };
    for r in records {
        s.findings += r.scan.findings;
        s.redacted += r.scan.redacted;
        s.flagged += r.scan.flagged;
        s.quarantined |= r.scan.quarantined || r.quarantined;
    }
    s
}

fn prior_frames(prior: &Option<Manifest>, source: &Path) -> Vec<Frame> {
    let key = canonical_key(source);
    prior
        .as_ref()
        .and_then(|m| m.artifacts.iter().find(|a| a.source == key))
        .map(|a| a.frames.clone())
        .unwrap_or_default()
}

fn role_for_category(cat: &str) -> ArtifactRole {
    match cat {
        "_history" => ArtifactRole::History,
        "_mcp" => ArtifactRole::Mcp,
        "_snapshots" => ArtifactRole::Snapshot,
        "_paste" => ArtifactRole::Paste,
        _ => ArtifactRole::ToolResult,
    }
}

/// The tail a prior manifest contributes to the new one, and whether that prior
/// ledger was decodable in full.
///
/// Two kinds of entry are carried across:
///
/// * **vanished** — identity decodes, but this run's walk did not see the file.
///   Retained verbatim and marked `present: false`; its `.zst` is the last copy.
///   "Vanished" is decided by identity, not by a filesystem probe: the walk that
///   produced `live` is the same walk the GC gate performs, so the two layers
///   agree on what "still here" means, and a file that merely became unreadable
///   or blacklisted this run is treated as gone — retaining its archive, the
///   direction that cannot lose data. A file that has come *back* is not
///   retained: the live pass already produced a fresh entry for it under current
///   policy, and two entries with one identity would be a self-contradicting
///   ledger.
/// * **undecodable** — identity does not decode at all (a corrupt or hand-edited
///   `path_hex`). Carried byte-for-byte with `present` untouched, because we
///   cannot tell whether its file is live and marking it either way would assert
///   more than the record supports.
///
/// An undecodable entry also makes the ledger incomplete, which the returned
/// flag reports. Its `store_rel` is *unknowable* — `rel()` is precisely what
/// would yield it — so its artifact cannot be named, and therefore cannot be
/// kept out of an orphan set by name. The only sound response is to stop
/// deleting for this key: a ledger the reader cannot parse is a reason to
/// refuse, not a licence to destroy what it describes.
fn prior_tail(
    prior: &ScratchManifest,
    live: &[(PathBuf, ScratchRel)],
) -> (Vec<ScratchEntry>, bool) {
    let live: std::collections::HashSet<&ScratchRel> = live.iter().map(|(_, r)| r).collect();
    let mut vanished: Vec<(ScratchRel, ScratchEntry)> = Vec::new();
    let mut undecodable: Vec<ScratchEntry> = Vec::new();
    // Retained entries are collapsed by identity. Archive cannot *create* a
    // duplicate — the live pass yields one entry per walked path and this tail
    // skips identities already live — and it must not be able to *propagate* one
    // either: two prior rows sharing an identity would otherwise be carried
    // forward together on every subsequent run, so a defect that arrived by
    // hand-editing or corruption would become permanent. The first row wins;
    // `verify` reports the duplicate on the manifest that still holds it, and
    // repairing one already on disk stays a manual act.
    let mut retained: std::collections::HashSet<ScratchRel> = std::collections::HashSet::new();
    for e in &prior.entries {
        match e.rel() {
            Some(rel) if live.contains(&rel) => {}
            Some(rel) => {
                if !retained.insert(rel.clone()) {
                    continue;
                }
                let mut e = e.clone();
                e.present = false;
                vanished.push((rel, e));
            }
            None => undecodable.push(e.clone()),
        }
    }
    let complete = undecodable.is_empty();
    vanished.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out: Vec<ScratchEntry> = vanished.into_iter().map(|(_, e)| e).collect();
    out.extend(undecodable);
    (out, complete)
}

/// Record that nothing of this file's content reached the store this run, and
/// carry an earlier run's capture forward if one is still on disk. Returns
/// whether it was.
///
/// Nothing was captured, so the entry must not go on claiming otherwise —
/// `stored: true` with no hashes is a manifest that lies, and the gate reads it
/// as a corrupt archive (the #9 failure mode, reached through another door).
///
/// `capture_failed` keeps this apart from the bare `stored: false` that policy
/// writes. That one means "we declined to hoard these bytes", and presence +
/// size is then the intended assurance; this one means nothing of the content
/// was captured, so presence + size assures nothing and the gate refuses the
/// tree rather than delete a file yomi meant to archive and could not.
///
/// An earlier run's capture is carried forward verbatim. The live bytes are
/// uncapturable *now*; that `.zst` is the last copy of them, and dropping the
/// claim would make reconciliation treat it as unclaimed and delete it — losing
/// a good archive over a permission bit. Same law as a vanished file: never
/// destroy what was already taken.
///
/// The claim is grounded in the artifact actually being on disk, not in the
/// prior ledger's word for it. Hashes are deliberately *not* required: a
/// manifest written before D2/R1 carries none, and refusing to salvage those
/// forfeited a real, valid archive — an entry that cannot be salvaged is no more
/// a licence to destroy its artifact than one that cannot be parsed. Their
/// absence is carried across too, so the gate keeps treating the artifact as
/// unverifiable rather than gaining a claim it cannot check.
fn salvage(
    entry: &mut ScratchEntry,
    rel: &ScratchRel,
    prior_by_rel: &std::collections::HashMap<ScratchRel, &ScratchEntry>,
    store_dir: &Path,
) -> bool {
    entry.capture_failed = true;
    let prior = prior_by_rel.get(rel).filter(|p| {
        p.stored
            && std::fs::symlink_metadata(store_dir.join(rel.store_rel()))
                .is_ok_and(|md| md.is_file())
    });
    match prior {
        Some(p) => {
            entry.stored = true;
            entry.source_sha256.clone_from(&p.source_sha256);
            entry.content_sha256.clone_from(&p.content_sha256);
            // The carried claim is about that same `.zst`, and so is its
            // original: the file under `quarantine/` is the unredacted source of
            // the capture being salvaged, at the mirror of the store path this
            // entry keeps. Drop the flag and the ledger denies an original that
            // is still there — which law Q reads as a stray.
            entry.quarantined = p.quarantined;
            true
        }
        None => {
            entry.stored = false;
            false
        }
    }
}

/// What one key's reconciliation did, and how much of it has a nameable cause.
#[derive(Default)]
struct Reconciled {
    /// Stale artifacts removed, or — under `dry_run` — that would be.
    removed: u64,
    /// The subset a `[scratch]` cap declined this run. Split out because a count
    /// alone cannot be acted on: the remedy for a cap is `--full` or a wider cap,
    /// and the remedy for a glob is an edit to `allow`/`deny`.
    by_cap: u64,
}

impl Reconciled {
    /// Fold into the run report, recording the prior ledger's `caps_lifted` only
    /// where a cap actually took something away. Ungated it would report a key
    /// that lost nothing, which is a claim about a loss that did not happen.
    fn tally(&self, report: &mut Report, prior_caps_lifted: bool) {
        report.scratch_orphans_removed += self.removed;
        report.scratch_orphans_cap_declined += self.by_cap;
        if self.by_cap > 0 && prior_caps_lifted {
            report.scratch_keys_caps_reimposed += 1;
        }
    }
}

/// Establish store law S for one scratch key: the `*.zst` under
/// `archive/_scratch/<K>/` are exactly the `store_rel()` of the manifest's
/// `stored: true` entries. Returns how many stale artifacts were removed — or,
/// under `dry_run`, how many would be — and how many of those a cap explains.
///
/// The delete authority is deliberately enumerable and cannot grow: **regular
/// files only**, **`.zst` extension only**, **under this one key's store dir
/// only**. `manifest.json` has the wrong extension, `quarantine/` and every
/// other key are outside the walked root, and `WalkDir` does not follow
/// symlinks, so the walk cannot leave the store dir. A store dir that is itself
/// a symlink is refused outright rather than walked through.
///
/// It also refuses whenever any entry's identity fails to decode. Such an entry
/// names an artifact whose path cannot be computed — `rel()` is what would
/// compute it — so it cannot be kept out of the orphan set, and every unnamed
/// artifact would be deleted as unclaimed. The caller already declines to call
/// in that case; the check lives here too because this is the function that
/// deletes, and a delete primitive must not depend on its caller's discipline.
fn reconcile_scratch_store(
    store_dir: &Path,
    entries: &[ScratchEntry],
    cap_declined: &std::collections::HashSet<ScratchRel>,
    dry_run: bool,
) -> Result<Reconciled> {
    if entries.iter().any(|e| e.rel().is_none()) {
        tracing::warn!(
            store = %store_dir.display(),
            "refusing to reconcile a store whose ledger holds an entry with an \
             undecodable identity"
        );
        return Ok(Reconciled::default());
    }
    if crate::scratch::classify_store_dir(store_dir) != StoreDir::Own {
        return Ok(Reconciled::default());
    }
    let expected: std::collections::HashSet<PathBuf> = entries
        .iter()
        .filter(|e| e.stored)
        .filter_map(|e| e.rel())
        .map(|rel| store_dir.join(rel.store_rel()))
        .collect();
    let capped: std::collections::HashSet<PathBuf> = cap_declined
        .iter()
        .map(|rel| store_dir.join(rel.store_rel()))
        .collect();

    let mut out = Reconciled::default();
    for entry in walkdir::WalkDir::new(store_dir)
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("zst") {
            continue;
        }
        if !entry.file_type().is_file() {
            // A symlink or device named `*.zst` is not something `archive` wrote.
            // Acting on it would widen the authority past "remove the artifacts
            // we stored", so it is reported and left alone.
            tracing::warn!(
                path = %path.display(),
                "non-regular *.zst in a scratch store dir; left in place"
            );
            continue;
        }
        if expected.contains(path) {
            continue;
        }
        if dry_run {
            out.removed += 1;
            out.by_cap += u64::from(capped.contains(path));
            continue;
        }
        match std::fs::remove_file(path) {
            Ok(()) => {
                tracing::info!(path = %path.display(), "removed stale scratch artifact");
                out.removed += 1;
                out.by_cap += u64::from(capped.contains(path));
            }
            Err(e) => tracing::warn!(
                path = %path.display(), error = %e,
                "could not remove stale scratch artifact"
            ),
        }
    }
    Ok(out)
}

/// Build a globset where each pattern also matches nested occurrences, so
/// `.git/**` excludes a `.git` at any depth, not only at the tree root (W2).
fn build_globs_nested(pats: &[String]) -> Result<globset::GlobSet> {
    let mut b = globset::GlobSetBuilder::new();
    for p in pats {
        b.add(globset::Glob::new(p)?);
        if !p.starts_with("**/") {
            b.add(globset::Glob::new(&format!("**/{p}"))?);
        }
    }
    Ok(b.build()?)
}

/// Path of `dest` relative to the archive root, for use as a catalog key.
fn archive_rel(env: &Env, dest: &Path) -> String {
    dest.strip_prefix(env.archive_dir())
        .unwrap_or(dest)
        .to_string_lossy()
        .to_string()
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unnamed")
        .to_string()
}

fn file_stem(p: &Path) -> String {
    p.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unnamed")
        .to_string()
}

/// Verify a stored artifact against the catalog: the compressed bytes must hash
/// to `expected_stored_sha`, and — critically — the *decompressed* content must
/// hash to `expected_content_sha`. The content check catches frame-duplication
/// corruption (e.g. a crash-replayed append) that a compressed-bytes check alone
/// would pass, since P2's wipe gate trusts a verified archive (B3b).
pub fn verify_stored(
    archive_dir: &Path,
    stored_rel: &str,
    expected_stored_sha: &str,
    expected_content_sha: &str,
) -> Result<bool> {
    let path = archive_dir.join(stored_rel);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => return Ok(false),
    };
    if sha256_hex(&bytes) != expected_stored_sha {
        return Ok(false);
    }
    let content = if stored_rel.ends_with(".zst") {
        match decompress_all(&bytes) {
            Ok(c) => c,
            Err(_) => return Ok(false),
        }
    } else {
        bytes
    };
    // Legacy rows without a content hash fall back to the stored-bytes check.
    if expected_content_sha.is_empty() {
        return Ok(true);
    }
    Ok(sha256_hex(&content) == expected_content_sha)
}

#[cfg(test)]
mod glob_depth {
    use super::build_globs_nested;
    use crate::config::ScratchConfig;

    fn set(pat: &str) -> globset::GlobSet {
        build_globs_nested(&[pat.to_string()]).unwrap()
    }

    /// Every path shape a scratch tree can present, at every depth that matters.
    const SUBJECTS: &[&str] = &[
        "a.md",
        "scratchpad/a.md",
        "scratchpad/sub/a.md",
        "scratchpad/sub/deeper/a.md",
        "a/b/c/d/e/f/g/deep.md",
        ".hidden.md",
        "scratchpad/.hidden.md",
        "repo/a.md",
        "scratchpad/repo/a.md",
        "tasks/run.output",
        ".git/config",
        "scratchpad/.git/config",
        "scratchpad/repo/.git/objects/ab/cd",
        "node_modules/x.js",
        "scratchpad/node_modules/x.js",
        "scratchpad/repo/node_modules/pkg/index.js",
        "clip.mp4",
        "scratchpad/clip.mp4",
        "scratchpad/sub/clip.mp4",
    ];

    /// The load-bearing fact, measured rather than assumed: in `globset`, a
    /// leading `**/` matches **zero** components as well as many. Every pattern
    /// `build_globs_nested` registers as `**/<p>` therefore also matches `<p>` at
    /// the tree root. If this ever changed, prefixing a subject with a directory
    /// component would start flipping verdicts.
    #[test]
    fn doubleglob_prefix_matches_at_depth_zero() {
        for (pat, subject) in [
            ("**/*.md", "a.md"),
            ("**/*.md", "scratchpad/a.md"),
            ("**/*.md", "a/b/c/d/e/f/g/deep.md"),
            ("**/.git/**", ".git/config"),
            ("**/node_modules/**", "node_modules/x.js"),
            ("**/*.{mp4,zip}", "clip.mp4"),
        ] {
            assert!(
                globset::Glob::new(pat)
                    .unwrap()
                    .compile_matcher()
                    .is_match(subject),
                "`{pat}` no longer matches `{subject}`: a leading `**/` stopped \
                 matching zero components, so build_globs_nested is no longer \
                 depth-insensitive"
            );
        }
    }

    /// The property U2 rests on: matching a *session-relative* path
    /// (`scratchpad/a.md`) instead of a prefix-stripped one (`a.md`) changes no
    /// verdict, for any pattern in the shipped allow/deny sets, at any depth.
    /// True because `build_globs_nested` always registers a `**/`-prefixed
    /// variant and that variant matches at depth zero.
    #[test]
    fn a_leading_directory_component_never_flips_a_verdict() {
        let cfg = ScratchConfig::default();
        for pat in cfg.allow.iter().chain(cfg.deny.iter()) {
            let gs = set(pat);
            for s in SUBJECTS {
                for prefix in ["scratchpad/", "tasks/", "scratchpad/nested/"] {
                    let prefixed = format!("{prefix}{s}");
                    assert_eq!(
                        gs.is_match(s),
                        gs.is_match(&prefixed),
                        "`{pat}`: `{s}` -> {} but `{prefixed}` -> {}; moving the \
                         glob input to session-relative paths would change this \
                         file's storage decision",
                        gs.is_match(s),
                        gs.is_match(&prefixed)
                    );
                }
            }
        }
    }

    /// The full matrix for the pattern *shapes* the config admits, pinned so a
    /// globset upgrade cannot silently redefine what gets stored.
    #[test]
    fn depth_matrix_is_pinned() {
        // (pattern, subject, expected)
        let cases: &[(&str, &str, bool)] = &[
            // Bare extension globs: nested registration makes them match at
            // every depth, and `*` alone never crosses a `/`.
            ("*.md", "a.md", true),
            ("*.md", "scratchpad/a.md", true),
            ("*.md", "scratchpad/sub/a.md", true),
            ("*.md", "a/b/c/d/e/f/g/deep.md", true),
            ("*.md", "clip.mp4", false),
            // Dotfiles are ordinary names to globset — no shell-style dot rule.
            ("*.md", ".hidden.md", true),
            ("*.md", "scratchpad/.hidden.md", true),
            // An explicitly nested pattern behaves identically to the bare one.
            ("**/*.md", "a.md", true),
            ("**/*.md", "scratchpad/sub/deeper/a.md", true),
            // A literal name matches that name at any depth, nothing else.
            ("a.md", "a.md", true),
            ("a.md", "scratchpad/sub/a.md", true),
            ("a.md", ".hidden.md", false),
            ("a.md", "a/b/c/d/e/f/g/deep.md", false),
            // A multi-component pattern is depth-insensitive in the same way.
            ("repo/a.md", "repo/a.md", true),
            ("repo/a.md", "scratchpad/repo/a.md", true),
            ("repo/a.md", "a.md", false),
            ("repo/a.md", "scratchpad/a.md", false),
            // Directory-anchored deny patterns match the directory wherever it
            // sits, including at the tree root (W2).
            (".git/**", ".git/config", true),
            (".git/**", "scratchpad/.git/config", true),
            (".git/**", "scratchpad/repo/.git/objects/ab/cd", true),
            (".git/**", "scratchpad/a.md", false),
            ("node_modules/**", "node_modules/x.js", true),
            (
                "node_modules/**",
                "scratchpad/repo/node_modules/pkg/index.js",
                true,
            ),
            ("node_modules/**", "scratchpad/a.md", false),
            // Brace alternation is unaffected by nesting.
            ("**/*.{mp4,zip}", "clip.mp4", true),
            ("**/*.{mp4,zip}", "scratchpad/sub/clip.mp4", true),
            ("**/*.{mp4,zip}", "scratchpad/a.md", false),
            ("*.output", "tasks/run.output", true),
            ("*.output", "scratchpad/a.md", false),
        ];
        for (pat, subject, expected) in cases {
            assert_eq!(
                set(pat).is_match(subject),
                *expected,
                "build_globs_nested({pat:?}) vs {subject:?}: expected {expected}"
            );
        }
    }
}
