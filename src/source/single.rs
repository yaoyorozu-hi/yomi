use super::SourceRoots;
use crate::util::root_owned_by_euid;
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

/// What an enumeration of `tmp_root` yielded.
///
/// "No trees under it" and "not a root this process owns" are the same empty list
/// to a caller that only reads, and opposite things to a caller that then
/// **stores what it read under this user's name**. The distinction is a variant
/// rather than an empty `Vec` so that a caller cannot get the second by
/// accident: every consumer of the scratch enumerator has to say what a foreign
/// root means to it.
pub enum ScratchScan {
    /// `tmp_root` is owned by this euid — or absent, which is nothing to
    /// enumerate rather than a hazard — and these are the session trees found
    /// under it.
    Trees(Vec<ScratchDir>),
    /// `tmp_root` resolves to something this euid does not own, so **nothing
    /// under it was enumerated**.
    ///
    /// Carries no message: what a foreign root means differs by caller, and gc
    /// already refuses every root it does not own one layer up with its own
    /// wording (`gc::candidates`). Warning here as well would report one fact
    /// twice for that caller, so each words its own refusal.
    ForeignRoot,
}

/// Scratch working dirs: every `<tmp_root>/<slug>/<uuid>/` session directory.
///
/// **Ownership of `tmp_root` is asserted before it is read**, and the refusal
/// lives here rather than in each caller so that every consumer — archive, gc,
/// and whatever enumerates next — inherits it. The hazard is not disclosure:
/// `/tmp/claude-<uid>` is mode 700, so a cross-uid read fails EACCES and lands
/// as a skipped source. It is a *poisoned root*. `YOMI_TMP_ROOT` pointing at a
/// foreign — or merely attacker-writable — tree makes every path under it
/// archivable, and each one lands in this user's store under a key derived from
/// a foreign directory name, with the secret scanner collecting whatever it finds
/// into this user's `quarantine/`. Nothing downstream can undo that: the store
/// key is the identity, and by then it is already another user's.
///
/// Two levels are deliberately *not* asserted here. Which names count as a
/// session tree is unchecked — `<X>/<Y>/` is a unit whatever `Y` looks like —
/// because the enumerator's unit and the deleter's unit must be the same one, and
/// narrowing this to uuid-shaped names would make the gate refuse trees it cannot
/// account for. And per-key store ownership stays with the writer
/// (`classify_store_dir`), which is a question about the store, not the source.
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
pub fn scratch(roots: &SourceRoots) -> Result<ScratchScan> {
    // Before the first `read_dir`, so a root this process cannot prove it owns is
    // never even listed. An absent root passes: on most hosts `tmp_root` does not
    // exist, and that is nothing to enumerate rather than a refusal.
    if !root_owned_by_euid(&roots.tmp_root) {
        return Ok(ScratchScan::ForeignRoot);
    }

    let mut out = Vec::new();
    if !roots.tmp_root.is_dir() {
        return Ok(ScratchScan::Trees(out));
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
    Ok(ScratchScan::Trees(out))
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
