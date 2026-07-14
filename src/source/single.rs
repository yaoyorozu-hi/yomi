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
    /// The `scratchpad/` directory (manifest-and-allowlist stored).
    pub scratchpad: Option<PathBuf>,
    /// `tasks/*.output` files (small, stored whole).
    pub task_outputs: Vec<PathBuf>,
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

/// Scratch working dirs: `<tmp_root>/<slug>/<uuid>/{scratchpad,tasks}`.
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
        let slug_name = slug.file_name().to_string_lossy().to_string();
        for sess in std::fs::read_dir(slug.path())? {
            let sess = sess?;
            if !sess.file_type()?.is_dir() {
                continue;
            }
            let scratchpad = sess.path().join("scratchpad");
            let tasks_dir = sess.path().join("tasks");
            let scratchpad = scratchpad.is_dir().then_some(scratchpad);
            let mut task_outputs: Vec<PathBuf> = Vec::new();
            if tasks_dir.is_dir() {
                for t in std::fs::read_dir(&tasks_dir)? {
                    let t = t?;
                    let p = t.path();
                    if p.extension().and_then(|e| e.to_str()) == Some("output")
                        && t.file_type()?.is_file()
                    {
                        task_outputs.push(p);
                    }
                }
                task_outputs.sort();
            }
            if scratchpad.is_none() && task_outputs.is_empty() {
                continue;
            }
            out.push(ScratchDir {
                key: format!("{slug_name}--{}", sess.file_name().to_string_lossy()),
                scratchpad,
                task_outputs,
            });
        }
    }
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
