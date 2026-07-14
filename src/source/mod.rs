pub mod claude;
pub mod single;

use crate::util::home_dir;
use anyhow::Result;
use std::path::PathBuf;

/// Filesystem roots yomi reads from. Defaults track the real host layout;
/// each is overridable by env so tests (and unusual hosts) can redirect them.
pub struct SourceRoots {
    /// `~/.claude` (override `YOMI_CLAUDE_HOME`).
    pub claude_home: PathBuf,
    /// `~/.cache/claude-cli-nodejs` (override `YOMI_CACHE_HOME`).
    pub cache_home: PathBuf,
    /// `/tmp/claude-1007` scratch root (override `YOMI_TMP_ROOT`).
    pub tmp_root: PathBuf,
}

impl SourceRoots {
    pub fn resolve() -> Result<Self> {
        let home = home_dir()?;
        let claude_home = std::env::var_os("YOMI_CLAUDE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".claude"));
        let cache_home = std::env::var_os("YOMI_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".cache/claude-cli-nodejs"));
        let tmp_root = std::env::var_os("YOMI_TMP_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp/claude-1007"));
        Ok(SourceRoots {
            claude_home,
            cache_home,
            tmp_root,
        })
    }

    pub fn projects_dir(&self) -> PathBuf {
        self.claude_home.join("projects")
    }
    pub fn history_file(&self) -> PathBuf {
        self.claude_home.join("history.jsonl")
    }
    pub fn snapshots_dir(&self) -> PathBuf {
        self.claude_home.join("shell-snapshots")
    }
    pub fn paste_dir(&self) -> PathBuf {
        self.claude_home.join("paste-cache")
    }
}

/// Which source families to archive (from `--include`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Include {
    Transcript,
    Subagents,
    ToolResults,
    History,
    Mcp,
    Snapshots,
    Paste,
    Scratch,
}

impl Include {
    pub fn parse_list(spec: &str) -> Result<Vec<Include>> {
        use Include::*;
        let mut out = Vec::new();
        for tok in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match tok {
                "all" => {
                    return Ok(vec![
                        Transcript,
                        Subagents,
                        ToolResults,
                        History,
                        Mcp,
                        Snapshots,
                        Paste,
                        Scratch,
                    ]);
                }
                "transcript" => out.push(Transcript),
                "subagents" => out.push(Subagents),
                "tool-results" => out.push(ToolResults),
                "history" => out.push(History),
                "mcp" => out.push(Mcp),
                "snapshots" => out.push(Snapshots),
                "paste" => out.push(Paste),
                "scratch" => out.push(Scratch),
                other => anyhow::bail!("unknown --include value: {other}"),
            }
        }
        Ok(out)
    }

    /// The design default when `--include` is omitted: the session pillars.
    pub fn default_set() -> Vec<Include> {
        vec![
            Include::Transcript,
            Include::Subagents,
            Include::ToolResults,
        ]
    }
}
