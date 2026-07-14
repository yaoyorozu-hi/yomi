use super::SourceRoots;
use anyhow::Result;
use std::path::{Path, PathBuf};

/// One Claude Code session's on-disk artifacts.
pub struct DiscoveredSession {
    pub project_slug: String,
    pub session_uuid: String,
    pub transcript: PathBuf,
    pub subagent_transcripts: Vec<PathBuf>,
    pub subagent_metas: Vec<PathBuf>,
    pub tool_results: Vec<PathBuf>,
}

/// What set of sessions to archive.
pub enum Selector {
    All,
    Session(String),
    /// A single transcript `.jsonl` file path.
    TranscriptPath(PathBuf),
}

/// Discover sessions under `projects/<slug>/<uuid>.jsonl` with their companion
/// `<uuid>/{subagents,tool-results}` directories.
pub fn discover(roots: &SourceRoots, selector: &Selector) -> Result<Vec<DiscoveredSession>> {
    match selector {
        Selector::TranscriptPath(p) => {
            let s = session_from_transcript(p)?;
            Ok(s.into_iter().collect())
        }
        Selector::All => discover_all(roots, None),
        Selector::Session(uuid) => discover_all(roots, Some(uuid.as_str())),
    }
}

fn discover_all(roots: &SourceRoots, only_uuid: Option<&str>) -> Result<Vec<DiscoveredSession>> {
    let projects = roots.projects_dir();
    let mut out = Vec::new();
    if !projects.is_dir() {
        return Ok(out);
    }
    let slug_iter = match std::fs::read_dir(&projects) {
        Ok(it) => it,
        Err(e) => {
            tracing::warn!(dir = %projects.display(), error = %e, "skip unreadable projects dir");
            return Ok(out);
        }
    };
    // An unreadable slug or transcript must not abort the whole run; skip and
    // warn so one bad directory can't sink an otherwise-good archive (N14).
    for slug_entry in slug_iter.flatten() {
        if !slug_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let files = match std::fs::read_dir(slug_entry.path()) {
            Ok(it) => it,
            Err(e) => {
                tracing::warn!(dir = %slug_entry.path().display(), error = %e, "skip unreadable slug dir");
                continue;
            }
        };
        for file in files.flatten() {
            let path = file.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            if !file.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let uuid = match path.file_stem().and_then(|s| s.to_str()) {
                Some(u) => u.to_string(),
                None => continue,
            };
            if let Some(want) = only_uuid
                && want != uuid
            {
                continue;
            }
            match session_from_transcript(&path) {
                Ok(Some(s)) => out.push(s),
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "skip unreadable session");
                }
            }
        }
    }
    Ok(out)
}

/// Build a session descriptor from a transcript path, resolving its companion
/// `<uuid>/` directory for subagents and tool-results.
pub fn session_from_transcript(transcript: &Path) -> Result<Option<DiscoveredSession>> {
    if !transcript.is_file() {
        return Ok(None);
    }
    let uuid = match transcript.file_stem().and_then(|s| s.to_str()) {
        Some(u) => u.to_string(),
        None => return Ok(None),
    };
    let slug_dir = match transcript.parent() {
        Some(p) => p,
        None => return Ok(None),
    };
    let project_slug = slug_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    let companion = slug_dir.join(&uuid);
    let subagents_dir = companion.join("subagents");
    let tool_results_dir = companion.join("tool-results");

    let mut subagent_transcripts = list_files(&subagents_dir, "jsonl")?;
    subagent_transcripts.sort();
    let mut subagent_metas = list_files_suffixed(&subagents_dir, ".meta.json")?;
    subagent_metas.sort();
    let mut tool_results = list_files(&tool_results_dir, "txt")?;
    tool_results.sort();

    Ok(Some(DiscoveredSession {
        project_slug,
        session_uuid: uuid,
        transcript: transcript.to_path_buf(),
        subagent_transcripts,
        subagent_metas,
        tool_results,
    }))
}

fn list_files(dir: &Path, ext: &str) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let p = e.path();
        // `.meta.json` files also carry a `json` ext family; exclude them from `jsonl`.
        if p.extension().and_then(|x| x.to_str()) == Some(ext) && e.file_type()?.is_file() {
            out.push(p);
        }
    }
    Ok(out)
}

fn list_files_suffixed(dir: &Path, suffix: &str) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let p = e.path();
        if p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(suffix))
            && e.file_type()?.is_file()
        {
            out.push(p);
        }
    }
    Ok(out)
}
