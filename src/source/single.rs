use super::SourceRoots;
use anyhow::Result;
use std::path::PathBuf;
use walkdir::WalkDir;

/// A single-file source archived into a date/name-partitioned store.
pub struct SingleFile {
    pub source: PathBuf,
    /// Store category directory under `archive/` (e.g. `_mcp`, `_snapshots`).
    pub category: &'static str,
    /// Optional sub-directory within the category (e.g. mcp server name).
    pub subgroup: Option<String>,
}

/// One scratch working directory for a session.
pub struct ScratchDir {
    /// `<slug>--<uuid>` identity for the store path.
    pub key: String,
    /// The session directory itself, `<tmp_root>/<slug>/<uuid>`. The deleter
    /// removes this tree entire, so the writer enumerates it entire and
    /// `scratchpad/`/`tasks/` are ordinary prefixes inside it rather than
    /// enumeration roots. Carried as a field because the enumerator is the only
    /// layer that knows it first-hand: archive and gc each used to re-derive it
    /// from a member path, with two implementations and two failure behaviours.
    pub session_dir: PathBuf,
}

pub fn history(roots: &SourceRoots) -> Vec<SingleFile> {
    let f = roots.history_file();
    if f.is_file() {
        vec![SingleFile {
            source: f,
            category: "_history",
            subgroup: None,
        }]
    } else {
        Vec::new()
    }
}

pub fn snapshots(roots: &SourceRoots) -> Result<Vec<SingleFile>> {
    Ok(list_ext(&roots.snapshots_dir(), "sh")
        .into_iter()
        .map(|source| SingleFile {
            source,
            category: "_snapshots",
            subgroup: None,
        })
        .collect())
}

pub fn paste(roots: &SourceRoots) -> Result<Vec<SingleFile>> {
    Ok(list_ext(&roots.paste_dir(), "txt")
        .into_iter()
        .map(|source| SingleFile {
            source,
            category: "_paste",
            subgroup: None,
        })
        .collect())
}

/// MCP proxy debug logs: `<cache>/**/mcp-logs-<server>/*.jsonl`.
pub fn mcp(roots: &SourceRoots) -> Vec<SingleFile> {
    let mut out = Vec::new();
    if !roots.cache_home.is_dir() {
        return out;
    }
    for entry in WalkDir::new(&roots.cache_home)
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        let server = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix("mcp-logs-"))
            .map(|s| s.to_string());
        if let Some(server) = server {
            out.push(SingleFile {
                source: path.to_path_buf(),
                category: "_mcp",
                subgroup: Some(server),
            });
        }
    }
    out
}

/// Scratch working dirs: every `<tmp_root>/<slug>/<uuid>/` session directory.
///
/// The whole session dir is the unit, not `scratchpad/` + `tasks/*.output`: the
/// deleter removes `<slug>/<uuid>/` entire, so anything the writer declines to
/// enumerate is a live file the GC gate cannot account for, which refuses the
/// tree forever. Which files are *stored* is decided downstream by the
/// `[scratch]` allow/deny globs and caps — configurable, and the same rules for
/// every path in the tree. A hardcoded second filter here was the reason the
/// three layers could disagree at all.
///
/// `file_type` is not followed, so a symlinked slug or session directory is
/// skipped rather than walked out of `tmp_root`.
pub fn scratch(roots: &SourceRoots) -> Result<Vec<ScratchDir>> {
    let mut out = Vec::new();
    if !roots.tmp_root.is_dir() {
        return Ok(out);
    }
    for slug in std::fs::read_dir(&roots.tmp_root)? {
        let slug = slug?;
        if !slug.file_type()?.is_dir() {
            continue;
        }
        let slug_name = slug.file_name();
        for sess in std::fs::read_dir(slug.path())? {
            let sess = sess?;
            if !sess.file_type()?.is_dir() {
                continue;
            }
            // Emitted even when the tree currently holds no file. A tree whose
            // files have *all* vanished is the strongest case of "a vanished
            // file keeps its archive": skipping it would leave the manifest
            // claiming those files are still present while their `.zst` sit in
            // the store, and nothing would ever correct the record.
            out.push(ScratchDir {
                key: crate::scratch::store_key(&slug_name, &sess.file_name()),
                session_dir: sess.path(),
            });
        }
    }
    // `read_dir` yields in filesystem order; sort so a run's manifests, store
    // writes and gc candidates do not depend on it.
    out.sort_by(|a, b| a.session_dir.cmp(&b.session_dir));
    Ok(out)
}

fn list_ext(dir: &std::path::Path, ext: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some(ext)
                && e.file_type().map(|t| t.is_file()).unwrap_or(false)
            {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}
