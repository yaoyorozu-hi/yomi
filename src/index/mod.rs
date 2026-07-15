//! Index / search layer (P3). Builds an FTS5 index over the **redacted stored**
//! artifacts (never the live source), exposes an [`Index`] trait, and drives the
//! incremental / reindex runs. The catalog owns all SQL; this module owns the
//! decompress → parse → doc pipeline and the run orchestration.

pub mod ftsindex;
pub mod parse;
pub mod query;

pub use query::{Filters, Hit, Query};

use crate::archive::compress::decompress_all;
use crate::catalog::{Catalog, IndexCandidate};
use crate::config::Env;
use crate::scan::redact::PLACEHOLDER_OPEN;
use anyhow::{Context, Result};
use std::path::Path;

/// Quarantine marker open token (`src/scan/content.rs`). A stored artifact whose
/// text carries this was quarantined whole; its presence still counts as a
/// redaction for the `has_redaction` facet.
const QUARANTINE_MARKER_OPEN: &str = "\u{2039}QUARANTINED:";

/// Upper bound on the indexed text of a single doc, in chars. Caps a pathological
/// tool_result / paste from bloating the index.
const DOC_TEXT_CAP: usize = 256 * 1024;

/// The tokenizer the FTS5 vtable is actually born with, per `schema.sql`
/// (`tokenize='unicode61 remove_diacritics 2'`). `index_meta.tokenizer` must be
/// seeded with THIS on first index — never with the *configured* tokenizer —
/// otherwise a config of `trigram` against a unicode61 vtable records a matching
/// `trigram` and the mismatch that should force `--reindex` is never detected.
pub const DDL_TOKENIZER: &str = "unicode61";

/// Seed `index_meta.tokenizer` with the vtable's actual [`DDL_TOKENIZER`] if it
/// has never been recorded. Idempotent. Owned here because the index-state
/// invariant (recorded tokenizer == vtable tokenizer) belongs to the index
/// layer, not the CLI. Both the incremental and `--reindex` entry points call
/// this before consulting the recorded tokenizer.
pub fn bootstrap_tokenizer(cat: &Catalog) -> Result<()> {
    if cat.index_meta_get("tokenizer")?.is_none() {
        cat.index_meta_set("tokenizer", DDL_TOKENIZER)?;
    }
    Ok(())
}

/// One document to index, mirroring the `entries` table columns.
pub struct IndexDoc {
    pub entry_uuid: String,
    pub parent_uuid: Option<String>,
    pub session_uuid: String,
    pub artifact_id: i64,
    pub source_path: String,
    pub role: String,
    pub agent: String,
    pub tool_name: Option<String>,
    pub project_slug: Option<String>,
    pub cwd: Option<String>,
    pub git_branch: Option<String>,
    pub cc_version: Option<String>,
    pub timestamp: Option<String>,
    pub has_redaction: bool,
    pub seq: u64,
    pub text: String,
}

/// A restored row for `yomi read` / entry listing (a subset of a doc).
pub struct EntryRow {
    pub entry_uuid: String,
    pub parent_uuid: Option<String>,
    pub role: String,
    pub agent: String,
    pub tool_name: Option<String>,
    pub timestamp: Option<String>,
    pub has_redaction: bool,
    pub text: String,
}

pub trait Index {
    fn upsert(&self, docs: &[IndexDoc]) -> Result<usize>;
    fn query(&self, q: &Query) -> Result<Vec<Hit>>;
    fn delete_session(&self, session_uuid: &str) -> Result<usize>;
}

/// How an artifact role maps to index docs.
pub enum IndexMode {
    /// One doc per JSONL entry (transcript, subagent).
    PerEntry,
    /// One doc for the whole redacted text (mcp, paste, snapshot, history, tool-result).
    SingleDoc,
    /// Not indexed (subagent-meta, scratch-file).
    Skip,
}

pub fn index_mode_for_role(role: &str) -> IndexMode {
    match role {
        "transcript" | "subagent" => IndexMode::PerEntry,
        "tool-result" | "mcp" | "snapshot" | "paste" | "history" => IndexMode::SingleDoc,
        _ => IndexMode::Skip,
    }
}

/// Totals for one index run.
#[derive(Default)]
pub struct IndexRunReport {
    pub artifacts_indexed: u64,
    pub docs_written: u64,
    pub artifacts_up_to_date: u64,
    pub docs_deleted: u64,
    pub parse_skipped: u64,
}

/// Incremental: walk every index candidate; reindex only artifacts whose
/// `source_sha256` has moved past the recorded watermark.
pub fn index_incremental(
    env: &Env,
    cat: &Catalog,
    session: Option<&str>,
) -> Result<IndexRunReport> {
    bootstrap_tokenizer(cat)?;
    let cands = match session {
        Some(s) => cat.index_candidates_for_session(s)?,
        None => cat.index_candidates()?,
    };
    let mut report = IndexRunReport::default();
    for c in &cands {
        if matches!(index_mode_for_role(&c.role), IndexMode::Skip) {
            continue;
        }
        if let Some(st) = cat.index_status_for_source(&c.source_path)?
            && st.indexed_source_sha256 == c.source_sha256
        {
            report.artifacts_up_to_date += 1;
            continue;
        }
        index_artifact(env, cat, c, &mut report)?;
    }
    Ok(report)
}

/// `--reindex`: drop the target's entries + watermarks, rebuild the FTS vtable if
/// the configured tokenizer changed, then re-index every candidate from scratch.
pub fn reindex(env: &Env, cat: &Catalog, session: Option<&str>) -> Result<IndexRunReport> {
    bootstrap_tokenizer(cat)?;
    let tok = env.config.index.effective_tokenizer();
    let stored = cat.index_meta_get("tokenizer")?;
    if stored.as_deref() != Some(tok) {
        cat.rebuild_fts_with_tokenizer(env.config.index.tokenize_clause())?;
        cat.index_meta_set("tokenizer", tok)?;
    }
    match session {
        Some(s) => cat.transaction(|| {
            cat.delete_entries_for_session(s)?;
            cat.delete_index_state_for_session(s)?;
            Ok(())
        })?,
        None => cat.transaction(|| {
            cat.delete_all_entries()?;
            cat.delete_all_index_state()?;
            Ok(())
        })?,
    }
    index_incremental(env, cat, session)
}

/// Index one artifact: decompress the redacted stored bytes, parse to docs, then
/// atomically replace this artifact's entries and bump its watermark.
fn index_artifact(
    env: &Env,
    cat: &Catalog,
    c: &IndexCandidate,
    report: &mut IndexRunReport,
) -> Result<()> {
    let archive_dir = env.archive_dir();
    let raw = std::fs::read(archive_dir.join(&c.stored_path))
        .with_context(|| format!("read stored artifact {}", c.stored_path))?;
    let stored = decompress_all(&raw)
        .with_context(|| format!("decompress stored artifact {}", c.stored_path))?;

    if matches!(index_mode_for_role(&c.role), IndexMode::Skip) {
        return Ok(());
    }
    let (docs, skipped) = docs_for_stored(&archive_dir, c, &stored);
    report.parse_skipped += skipped;

    let doc_count = docs.len() as u64;
    cat.transaction(|| {
        let deleted = cat.delete_entries_for_artifact(c.artifact_id)?;
        report.docs_deleted += deleted as u64;
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
        )
    })?;
    report.artifacts_indexed += 1;
    report.docs_written += doc_count;
    Ok(())
}

/// Build index docs from already-in-memory stored bytes, with no disk read of the
/// stored artifact itself (the sibling subagent meta sidecar is still read for the
/// `agent` facet). Extracted from [`index_artifact`] so `rescan` can index the
/// in-memory re-redacted bytes *before* the stored file is swapped on disk — the
/// ordering invariant that keeps every crash point free of an indexed raw secret.
/// Returns the docs and the count of JSONL lines skipped as unparseable.
pub fn docs_for_stored(
    archive_dir: &Path,
    c: &IndexCandidate,
    stored: &[u8],
) -> (Vec<IndexDoc>, u64) {
    match index_mode_for_role(&c.role) {
        IndexMode::PerEntry => {
            let agent = agent_for_role(archive_dir, c);
            let (parsed, skipped) = parse::parse_transcript(stored);
            (build_entry_docs(parsed, c, &agent), skipped)
        }
        IndexMode::SingleDoc => (single_doc(stored, c).into_iter().collect(), 0),
        IndexMode::Skip => (Vec::new(), 0),
    }
}

fn build_entry_docs(
    parsed: Vec<parse::ParsedEntry>,
    c: &IndexCandidate,
    agent: &str,
) -> Vec<IndexDoc> {
    parsed
        .into_iter()
        .map(|pe| {
            let entry_uuid = if pe.entry_uuid.is_empty() {
                format!("line:{}:{}", c.artifact_id, pe.seq)
            } else {
                pe.entry_uuid
            };
            // Judge redaction on the full text: a placeholder past DOC_TEXT_CAP
            // would be truncated away and wrongly clear the facet.
            let has_red = has_redaction(&pe.text);
            let text = bounded(pe.text);
            IndexDoc {
                entry_uuid,
                parent_uuid: pe.parent_uuid,
                session_uuid: c.session_uuid.clone(),
                artifact_id: c.artifact_id,
                source_path: c.source_path.clone(),
                role: pe.role.as_str().to_string(),
                agent: agent.to_string(),
                tool_name: pe.tool_name,
                project_slug: c.project_slug.clone(),
                cwd: c.cwd.clone(),
                git_branch: c.git_branch.clone(),
                cc_version: c.cc_version.clone(),
                timestamp: pe.timestamp,
                has_redaction: has_red,
                seq: pe.seq,
                text,
            }
        })
        .collect()
}

fn single_doc(stored: &[u8], c: &IndexCandidate) -> Option<IndexDoc> {
    let full = String::from_utf8_lossy(stored);
    // Judge redaction on the full text before the DOC_TEXT_CAP truncation.
    let has_red = has_redaction(&full);
    let text = bounded(full.into_owned());
    if text.trim().is_empty() {
        return None;
    }
    Some(IndexDoc {
        entry_uuid: format!("art:{}", c.artifact_id),
        parent_uuid: None,
        session_uuid: c.session_uuid.clone(),
        artifact_id: c.artifact_id,
        source_path: c.source_path.clone(),
        role: c.role.clone(),
        agent: "main".to_string(),
        tool_name: None,
        project_slug: c.project_slug.clone(),
        cwd: c.cwd.clone(),
        git_branch: c.git_branch.clone(),
        cc_version: c.cc_version.clone(),
        timestamp: None,
        has_redaction: has_red,
        seq: 0,
        text,
    })
}

/// The agent facet for an artifact: `main` for a session transcript, else the
/// subagent's `agentType` read from its sibling `.meta.json`.
fn agent_for_role(archive_dir: &Path, c: &IndexCandidate) -> String {
    if c.role != "subagent" {
        return "main".to_string();
    }
    agent_for_subagent(archive_dir, &c.stored_path)
}

/// Read a subagent's `agentType` from the sibling meta sidecar
/// (`subagents/<stem>.jsonl.zst` → `subagents/<stem>.meta.json`). Falls back to
/// `"subagent"` if the sidecar is absent or unreadable.
fn agent_for_subagent(archive_dir: &Path, subagent_stored_path: &str) -> String {
    let meta_rel = subagent_stored_path
        .strip_suffix(".jsonl.zst")
        .map(|stem| format!("{stem}.meta.json"));
    let Some(meta_rel) = meta_rel else {
        return "subagent".to_string();
    };
    std::fs::read(archive_dir.join(&meta_rel))
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| {
            v.get("agentType")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| "subagent".to_string())
}

/// Whether text carries a redaction placeholder or quarantine marker.
fn has_redaction(text: &str) -> bool {
    text.contains(PLACEHOLDER_OPEN) || text.contains(QUARANTINE_MARKER_OPEN)
}

/// Truncate to `DOC_TEXT_CAP` chars on a UTF-8 boundary, appending a marker.
fn bounded(mut text: String) -> String {
    if text.chars().count() <= DOC_TEXT_CAP {
        return text;
    }
    let cut = text
        .char_indices()
        .nth(DOC_TEXT_CAP)
        .map(|(i, _)| i)
        .unwrap_or(text.len());
    text.truncate(cut);
    text.push_str("…[truncated]");
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_redaction_detects_placeholder_and_marker() {
        assert!(has_redaction(
            "before \u{2039}REDACTED:aws-key:deadbeef\u{203a} after"
        ));
        assert!(has_redaction("\u{2039}QUARANTINED:non-utf8:aaaa\u{203a}"));
        assert!(!has_redaction("nothing sensitive here"));
    }

    #[test]
    fn index_mode_matches_roles() {
        assert!(matches!(
            index_mode_for_role("transcript"),
            IndexMode::PerEntry
        ));
        assert!(matches!(
            index_mode_for_role("subagent"),
            IndexMode::PerEntry
        ));
        assert!(matches!(index_mode_for_role("mcp"), IndexMode::SingleDoc));
        assert!(matches!(
            index_mode_for_role("history"),
            IndexMode::SingleDoc
        ));
        assert!(matches!(
            index_mode_for_role("subagent-meta"),
            IndexMode::Skip
        ));
        assert!(matches!(
            index_mode_for_role("scratch-file"),
            IndexMode::Skip
        ));
    }
}
