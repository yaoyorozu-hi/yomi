pub mod compress;
pub mod incremental;
pub mod manifest;

use crate::blacklist::{Blacklist, GuardOutcome};
use crate::catalog::{ArtifactUpsert, Catalog, SessionUpsert};
use crate::config::Env;
use crate::model::{ArtifactRecord, ArtifactRole, Finding, Frame, Manifest, SecretScanSummary};
use crate::scan::{Allowlist, ContentScan, scan_content};
use crate::scratch::{ManifestRead, ScratchEntry, ScratchManifest, ScratchRel, StoreDir};
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
    /// Stored scratch artifacts the new manifest no longer claims, removed to
    /// keep the store dir and the manifest one ledger. Counted (not performed)
    /// under `--dry-run`. Surfaced because a config change that discards stored
    /// bytes must be loud.
    pub scratch_orphans_removed: u64,
}

pub struct Archiver<'a> {
    pub env: &'a Env,
    pub blacklist: &'a Blacklist,
    pub allow: &'a Allowlist,
    pub catalog: &'a Catalog,
    pub scan_enabled: bool,
    /// Force quarantine of the original for MED findings too, not just HIGH.
    pub quarantine_all: bool,
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
            std::fs::create_dir_all(&session_dir)?;
            set_700(&session_dir)?;
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
                &session.session_uuid,
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
                    &session.session_uuid,
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
                    &session.session_uuid,
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
                    &session.session_uuid,
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
        manifest::write(&manifest_path, &manifest)?;
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
            std::fs::create_dir_all(&category_dir)?;
            set_700(&category_dir)?;
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
            &uuid,
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
    /// `.git`/`node_modules` are excluded wherever they sit (W2). A tree over
    /// `total_cap` is manifest-only: nothing is stored, and every live entry is
    /// recorded `stored: false`.
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

        // `create_dir_all`, `set_700` and `atomic_write` all follow a symlink, so
        // a store dir that is not a real directory would take this key's manifest
        // and artifacts outside the archive tree and rewrite an unrelated
        // directory's mode to 700. Checked before the manifest is read, so a
        // foreign ledger never informs a decision either.
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
        let mut total: u64 = 0;
        for path in &candidates {
            if self.blacklist.is_blacklisted(path) {
                report.blacklisted_skipped += 1;
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
            total += size;
            let glob_key = rel.glob_subpath();
            let subpath: &str = &glob_key;
            let store =
                allow.is_match(subpath) && !deny.is_match(subpath) && size <= cfg.file_cap.0;
            entries.push(ScratchEntry::new(&rel, size, store));
            kept.push((path.clone(), rel));
        }

        // The cap is a property of the whole tree, so it can only be applied once
        // every candidate has been sized — hence a second pass rather than a term
        // in `store` above. An over-cap tree stores nothing, and no entry may
        // claim otherwise: `stored: true` with no `.zst` and no hashes reads to
        // the GC gate as a corrupt archive, which refuses the tree forever (the
        // 134M clone the cap exists for was never reclaimable). `over_total_cap`
        // already records why nothing was stored — design §3, decision #4.
        let over_total = total > cfg.total_cap.0;
        if over_total {
            for entry in &mut entries {
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
            std::fs::create_dir_all(&store_dir)?;
            set_700(&store_dir)?;
            for (entry, (path, rel)) in entries.iter_mut().zip(kept.iter()) {
                if !entry.stored {
                    continue;
                }
                // Policy said to store this file and the read then refused it:
                // a blacklisted inode swapped in after the walk, an I/O or
                // permission error, or a file that outgrew the read bound
                // between stat and read. Nothing was captured, so the entry must
                // not go on claiming otherwise — `stored: true` with no hashes
                // is a manifest that lies, and the gate reads it as a corrupt
                // archive (the #9 failure mode, reached through another door).
                //
                // `capture_failed` keeps this apart from the bare `stored:
                // false` that policy writes. That one means "we declined to
                // hoard these bytes", and presence + size is then the intended
                // assurance; this one means nothing about the content was ever
                // read, so presence + size assures nothing and the gate refuses
                // the tree rather than delete a file yomi meant to archive and
                // could not.
                //
                // An earlier run's capture is carried forward verbatim. The live
                // bytes are unreadable *now*; that `.zst` is the last copy of
                // them, and dropping the claim would make reconciliation treat
                // it as unclaimed and delete it — losing a good archive over a
                // permission bit. Same law as a vanished file: never destroy
                // what was already taken.
                //
                // The claim is grounded in the artifact actually being on disk,
                // not in the prior ledger's word for it. Hashes are deliberately
                // *not* required: a manifest written before D2/R1 carries none,
                // and refusing to salvage those forfeited a real, valid archive
                // — an entry that cannot be salvaged is no more a licence to
                // destroy its artifact than one that cannot be parsed. Their
                // absence is carried across too, so the gate keeps treating the
                // artifact as unverifiable rather than gaining a claim it cannot
                // check.
                let Some(bytes) = self.read_source(path, report)? else {
                    entry.capture_failed = true;
                    let salvaged = prior_by_rel.get(rel).filter(|p| {
                        p.stored
                            && std::fs::symlink_metadata(store_dir.join(rel.store_rel()))
                                .is_ok_and(|md| md.is_file())
                    });
                    match salvaged {
                        Some(p) => {
                            entry.stored = true;
                            entry.source_sha256.clone_from(&p.source_sha256);
                            entry.content_sha256.clone_from(&p.content_sha256);
                        }
                        None => entry.stored = false,
                    }
                    tracing::warn!(
                        path = %path.display(),
                        kept_earlier_capture = salvaged.is_some(),
                        "scratch source could not be captured; this tree will not be \
                         reclaimed until it can be read"
                    );
                    continue;
                };
                let dest = store_dir.join(rel.store_rel());
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let scan = self.scan_bytes(&bytes, false);
                self.tally(report, &scan);
                if scan.needs_quarantine {
                    let qrel = format!("{}/{}", sc.key, entry.path);
                    self.quarantine(&uuid_for_scratch(sc), &qrel, &bytes, report)?;
                }
                atomic_write(&dest, &compress_frame(&scan.redacted)?)?;
                set_600(&dest)?;
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
            let mf = ScratchManifest {
                key: sc.key.clone(),
                captured_at: now_iso(),
                total_bytes: total,
                over_total_cap: over_total,
                entries,
            };
            let mfp = store_dir.join("manifest.json");
            atomic_write(&mfp, (serde_json::to_string_pretty(&mf)? + "\n").as_bytes())?;
            set_600(&mfp)?;
            // Manifest first, then reconcile: a crash between them leaves a store
            // holding *more* than the ledger claims, which the GC gate ignores and
            // the next run cleans up. The reverse order would leave a ledger
            // claiming a `.zst` that is gone, which refuses the tree until someone
            // re-archives.
            if ledger_complete {
                report.scratch_orphans_removed +=
                    reconcile_scratch_store(&store_dir, &mf.entries, false)?;
            }
        } else if ledger_complete {
            report.scratch_orphans_removed += reconcile_scratch_store(&store_dir, &entries, true)?;
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
        session_uuid: &str,
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

        let (stored_sha, stored_bytes) = if self.dry_run {
            let frame = compress_frame(&scan.redacted)?;
            (sha256_hex(&frame), frame.len() as u64)
        } else {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            match append_from {
                Some(prior_len) => {
                    let remainder = &scan.redacted[prior_len..];
                    if !remainder.is_empty() {
                        append_frame(&dest, remainder)?;
                    }
                }
                None => atomic_write(&dest, &compress_frame(&scan.redacted)?)?,
            }
            set_600(&dest)?;
            let stored = std::fs::read(&dest)?;
            report.bytes_stored += stored.len() as u64;
            (sha256_hex(&stored), stored.len() as u64)
        };

        if needs_q {
            if self.dry_run {
                report.quarantined += 1;
            } else {
                self.quarantine(session_uuid, &quarantine_rel(rel), full, report)?;
            }
        }
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
        session_uuid: &str,
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

        let (stored_sha, stored_bytes) = if self.dry_run {
            (sha256_hex(&scan.redacted), scan.redacted.len() as u64)
        } else {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            atomic_write(&dest, &scan.redacted)?;
            set_600(&dest)?;
            report.bytes_stored += scan.redacted.len() as u64;
            (sha256_hex(&scan.redacted), scan.redacted.len() as u64)
        };

        if needs_q {
            if self.dry_run {
                report.quarantined += 1;
            } else {
                self.quarantine(session_uuid, &quarantine_rel(rel), source_bytes, report)?;
            }
        }
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

    fn quarantine(
        &self,
        session_uuid: &str,
        rel: &str,
        original: &[u8],
        report: &mut Report,
    ) -> Result<()> {
        crate::scan::quarantine::quarantine_original(
            &self.env.quarantine_dir(),
            session_uuid,
            rel,
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

/// Quarantine sub-path for an artifact's raw original: its stored rel minus the
/// `.zst` suffix, preserving directory structure for uniqueness (R10).
fn quarantine_rel(rel: &str) -> String {
    rel.strip_suffix(".zst").unwrap_or(rel).to_string()
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

fn uuid_for_scratch(sc: &ScratchDir) -> String {
    format!("_scratch--{}", sc.key)
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
    for e in &prior.entries {
        match e.rel() {
            Some(rel) if live.contains(&rel) => {}
            Some(rel) => {
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

/// Establish store law S for one scratch key: the `*.zst` under
/// `archive/_scratch/<K>/` are exactly the `store_rel()` of the manifest's
/// `stored: true` entries. Returns how many stale artifacts were removed — or,
/// under `dry_run`, how many would be.
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
    dry_run: bool,
) -> Result<u64> {
    if entries.iter().any(|e| e.rel().is_none()) {
        tracing::warn!(
            store = %store_dir.display(),
            "refusing to reconcile a store whose ledger holds an entry with an \
             undecodable identity"
        );
        return Ok(0);
    }
    if crate::scratch::classify_store_dir(store_dir) != StoreDir::Own {
        return Ok(0);
    }
    let expected: std::collections::HashSet<PathBuf> = entries
        .iter()
        .filter(|e| e.stored)
        .filter_map(|e| e.rel())
        .map(|rel| store_dir.join(rel.store_rel()))
        .collect();

    let mut removed = 0u64;
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
            removed += 1;
            continue;
        }
        match std::fs::remove_file(path) {
            Ok(()) => {
                tracing::info!(path = %path.display(), "removed stale scratch artifact");
                removed += 1;
            }
            Err(e) => tracing::warn!(
                path = %path.display(), error = %e,
                "could not remove stale scratch artifact"
            ),
        }
    }
    Ok(removed)
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

/// Write `bytes` to `dest` via a temp file + rename, so a crash can never leave
/// a half-written store (B3a).
fn atomic_write(dest: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = dest.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        now_iso().replace([':', '.'], "")
    ));
    std::fs::write(&tmp, bytes)?;
    set_600(&tmp)?;
    std::fs::rename(&tmp, dest)?;
    Ok(())
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

fn append_frame(dest: &Path, slice: &[u8]) -> Result<()> {
    use std::io::Write;
    let frame = compress_frame(slice)?;
    let mut f = std::fs::OpenOptions::new().append(true).open(dest)?;
    f.write_all(&frame)?;
    Ok(())
}

fn set_700(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn set_600(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
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
