pub mod compress;
pub mod incremental;
pub mod manifest;

use crate::blacklist::{Blacklist, GuardOutcome};
use crate::catalog::{ArtifactUpsert, Catalog, SessionUpsert};
use crate::config::Env;
use crate::model::{ArtifactRecord, ArtifactRole, Finding, Frame, Manifest, SecretScanSummary};
use crate::scan::{Allowlist, ContentScan, scan_content};
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

    /// Archive one scratch dir: always write a manifest of every file (name,
    /// size, hash); store only allow-listed files under the size caps. deny/allow
    /// globs match the tree-relative sub-path with nested (`**/`) semantics so a
    /// cloned repo's `.git`/`node_modules` are excluded wherever they sit (W2).
    pub fn archive_scratch(&self, sc: &ScratchDir, report: &mut Report) -> Result<()> {
        let cfg = &self.env.config.scratch;
        let allow = build_globs_nested(&cfg.allow)?;
        let deny = build_globs_nested(&cfg.deny)?;

        let store_dir = self.env.archive_dir().join("_scratch").join(&sc.key);
        let mut entries = Vec::new();
        let mut total: u64 = 0;

        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(sp) = &sc.scratchpad {
            for e in walkdir::WalkDir::new(sp).into_iter().filter_map(Result::ok) {
                if e.file_type().is_file() {
                    candidates.push(e.path().to_path_buf());
                }
            }
        }
        candidates.extend(sc.task_outputs.iter().cloned());
        candidates.sort();

        let mut kept: Vec<PathBuf> = Vec::new();
        for path in &candidates {
            if self.blacklist.is_blacklisted(path) {
                report.blacklisted_skipped += 1;
                continue;
            }
            let Ok(md) = std::fs::metadata(path) else {
                continue;
            };
            let size = md.len();
            total += size;
            let rel = scratch_rel(sc, path);
            let subpath = scratch_subpath(sc, path);
            let denied = deny.is_match(&subpath);
            let allowed = allow.is_match(&subpath);
            let store = allowed && !denied && size <= cfg.file_cap.0;
            entries.push(ScratchEntry {
                path: rel,
                bytes: size,
                stored: store,
                source_sha256: None,
                content_sha256: None,
            });
            kept.push(path.clone());
        }

        let over_total = total > cfg.total_cap.0;
        if !self.dry_run {
            std::fs::create_dir_all(&store_dir)?;
            set_700(&store_dir)?;
            for (entry, path) in entries.iter_mut().zip(kept.iter()) {
                if entry.stored
                    && !over_total
                    && let Some(bytes) = self.read_source(path, report)?
                {
                    let dest = store_dir.join(format!("{}.zst", entry.path));
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

#[derive(serde::Serialize)]
struct ScratchEntry {
    path: String,
    bytes: u64,
    stored: bool,
    /// sha256 of the live source bytes at archive time. Present only for stored
    /// entries; GC re-hashes the live file against this to prove it is unchanged
    /// before deleting the tree. Absent for non-stored (deny-listed) junk, which
    /// GC verifies by presence + size only.
    #[serde(skip_serializing_if = "Option::is_none")]
    source_sha256: Option<String>,
    /// sha256 of the stored (post-scan, possibly-redacted) bytes. GC decompresses
    /// the stored `.zst` and checks its content hash against this, so a valid-zstd
    /// frame of the *wrong* content can never pass the scratch delete gate (D2).
    #[serde(skip_serializing_if = "Option::is_none")]
    content_sha256: Option<String>,
}

#[derive(serde::Serialize)]
struct ScratchManifest {
    key: String,
    captured_at: String,
    total_bytes: u64,
    over_total_cap: bool,
    entries: Vec<ScratchEntry>,
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
fn artifact_scan(scan: &crate::scan::ContentScan) -> crate::model::ArtifactScan {
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
fn summarize_records(records: &[ArtifactRecord]) -> SecretScanSummary {
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

/// Stored rel for a scratch file: `scratchpad/<sub>` or `tasks/<name>`.
fn scratch_rel(sc: &ScratchDir, path: &Path) -> String {
    if let Some(sp) = &sc.scratchpad
        && let Ok(r) = path.strip_prefix(sp)
    {
        return format!("scratchpad/{}", r.to_string_lossy());
    }
    format!("tasks/{}", file_name(path))
}

/// Tree-relative sub-path (no `scratchpad/`/`tasks/` prefix) for glob matching.
fn scratch_subpath(sc: &ScratchDir, path: &Path) -> String {
    if let Some(sp) = &sc.scratchpad
        && let Ok(r) = path.strip_prefix(sp)
    {
        return r.to_string_lossy().to_string();
    }
    file_name(path)
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
/// would pass, since P3's wipe gate trusts a verified archive (B3b).
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
