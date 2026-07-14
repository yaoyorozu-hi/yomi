//! Cross-user READ-ONLY ephemeral-shape discovery. This path may run elevated
//! (the operator's `sudo`), but yomi itself never elevates and never deletes:
//! discovery produces `ShapeRecord`s — a type the wipe path cannot consume — so
//! foreign users' files are structurally incapable of becoming delete candidates.

use super::SourceRoots;
use anyhow::Result;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// One user's resolved roots, gathered by [`SourceRoots::discover_all_users`].
pub struct UserRoots {
    pub user: String,
    pub uid: Option<u32>,
    pub roots: SourceRoots,
}

/// Class of ephemeral output an inventory row describes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ShapeKind {
    Transcript,
    Subagents,
    ToolResults,
    Scratch,
    Paste,
    Snapshot,
    EmptyDir,
    Mcp,
    Unknown,
}

impl ShapeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ShapeKind::Transcript => "transcript",
            ShapeKind::Subagents => "subagents",
            ShapeKind::ToolResults => "tool-results",
            ShapeKind::Scratch => "scratch",
            ShapeKind::Paste => "paste",
            ShapeKind::Snapshot => "snapshot",
            ShapeKind::EmptyDir => "empty-dir",
            ShapeKind::Mcp => "mcp",
            ShapeKind::Unknown => "unknown",
        }
    }
}

/// An aggregated ephemeral-output shape across a user's tree. The deliverable of
/// discovery: a taxonomy, never a delete list.
pub struct ShapeRecord {
    pub user: String,
    pub kind: ShapeKind,
    pub rel_shape: String,
    pub example_path: PathBuf,
    pub bytes: u64,
    pub count: u64,
}

impl SourceRoots {
    /// READ-ONLY enumeration of every `<home_base>/<user>` that has a `.claude`
    /// dir, plus its `<tmp_base>/claude-<uid>` scratch root. Never used for
    /// deletion. `home_base`/`tmp_base` default to `/home` and `/tmp`, overridable
    /// by `YOMI_HOME_BASE`/`YOMI_TMP_BASE` (test seam).
    pub fn discover_all_users(home_base: &Path, tmp_base: &Path) -> Result<Vec<UserRoots>> {
        let passwd = load_passwd_uids();
        let mut out = Vec::new();
        let rd = match std::fs::read_dir(home_base) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(dir = %home_base.display(), error = %e, "home base unreadable");
                return Ok(out);
            }
        };
        for entry in rd.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let user = entry.file_name().to_string_lossy().to_string();
            let user_home = entry.path();
            let claude_home = user_home.join(".claude");
            if !claude_home.is_dir() {
                continue;
            }
            let uid = passwd.get(&user).copied();
            let tmp_root = match uid {
                Some(u) => tmp_base.join(format!("claude-{u}")),
                None => tmp_base.join(format!("claude-{user}")),
            };
            out.push(UserRoots {
                user,
                uid,
                roots: SourceRoots {
                    claude_home,
                    cache_home: user_home.join(".cache/claude-cli-nodejs"),
                    tmp_root,
                },
            });
        }
        Ok(out)
    }
}

/// Walk every user's roots and aggregate ephemeral shapes by their relative
/// template. Pure read + stat.
pub fn classify_shapes(users: &[UserRoots]) -> Vec<ShapeRecord> {
    let mut agg: BTreeMap<(String, String), (ShapeKind, PathBuf, u64, u64)> = BTreeMap::new();

    let mut add = |user: &str, kind: ShapeKind, rel: String, path: &Path, bytes: u64| {
        let e =
            agg.entry((user.to_string(), rel.clone()))
                .or_insert((kind, path.to_path_buf(), 0, 0));
        e.2 += bytes;
        e.3 += 1;
    };

    for u in users {
        let projects = u.roots.projects_dir();
        for entry in WalkDir::new(&projects).into_iter().filter_map(|e| e.ok()) {
            let p = entry.path();
            if !entry.file_type().is_file() {
                continue;
            }
            let bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
            let rel = shape_relative(&u.roots.claude_home, p);
            let kind = classify(p);
            add(&u.user, kind, rel, p, bytes);
        }
        for sf in super::single::mcp(&u.roots) {
            let bytes = std::fs::metadata(&sf.source).map(|m| m.len()).unwrap_or(0);
            add(
                &u.user,
                ShapeKind::Mcp,
                // MCP logs live under `cache_home`, not `.claude`; relativizing
                // against `claude_home` fails the strip and yields a garbage
                // absolute path. Template against the correct root (倶生N6).
                mcp_shape_relative(&u.roots.cache_home, &sf.source),
                &sf.source,
                bytes,
            );
        }
        if u.roots.tmp_root.is_dir() {
            for entry in WalkDir::new(&u.roots.tmp_root)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                let bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
                add(
                    &u.user,
                    ShapeKind::Scratch,
                    "/tmp/claude-<uid>/<slug>/<uuid>/scratch".to_string(),
                    entry.path(),
                    bytes,
                );
            }
        }
    }

    agg.into_iter()
        .map(
            |((user, rel_shape), (kind, example_path, bytes, count))| ShapeRecord {
                user,
                kind,
                rel_shape,
                example_path,
                bytes,
                count,
            },
        )
        .collect()
}

fn classify(path: &Path) -> ShapeKind {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let parent = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if name.ends_with(".meta.json") || parent == "subagents" {
        ShapeKind::Subagents
    } else if parent == "tool-results" {
        ShapeKind::ToolResults
    } else if name.ends_with(".jsonl") {
        ShapeKind::Transcript
    } else {
        ShapeKind::Unknown
    }
}

/// A path expressed relative to a user's `.claude`, with the slug/uuid collapsed
/// to a template so instances aggregate.
fn shape_relative(claude_home: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(claude_home).unwrap_or(path);
    let mut parts: Vec<String> = Vec::new();
    for (i, comp) in rel.components().enumerate() {
        let s = comp.as_os_str().to_string_lossy().to_string();
        // Collapse the project slug (1st) and any uuid-ish leaf to templates.
        if i == 1 {
            parts.push("<slug>".to_string());
        } else if looks_uuidish(&s) {
            parts.push("<uuid>".to_string());
        } else {
            parts.push(s);
        }
    }
    format!(".claude/{}", parts.join("/"))
}

/// An MCP log path expressed relative to `cache_home`, with the uuid-ish leaf
/// collapsed to a template so instances of one server's logs aggregate.
fn mcp_shape_relative(cache_home: &Path, path: &Path) -> String {
    let label = cache_home
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("cache");
    let rel = path.strip_prefix(cache_home).unwrap_or(path);
    let parts: Vec<String> = rel
        .components()
        .map(|c| {
            let s = c.as_os_str().to_string_lossy().to_string();
            if looks_uuidish(&s) {
                "<uuid>".to_string()
            } else {
                s
            }
        })
        .collect();
    format!("{label}/{}", parts.join("/"))
}

fn looks_uuidish(s: &str) -> bool {
    let stem = s.strip_suffix(".jsonl").unwrap_or(s);
    stem.len() >= 32 && stem.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Parse `/etc/passwd` into a user→uid map. Best-effort; a missing or unreadable
/// file yields an empty map (uid-keyed scratch roots are then skipped).
fn load_passwd_uids() -> BTreeMap<String, u32> {
    let mut map = BTreeMap::new();
    if let Ok(text) = std::fs::read_to_string("/etc/passwd") {
        for line in text.lines() {
            let mut f = line.split(':');
            if let (Some(name), Some(_), Some(uid)) = (f.next(), f.next(), f.next())
                && let Ok(uid) = uid.parse::<u32>()
            {
                map.insert(name.to_string(), uid);
            }
        }
    }
    map
}
