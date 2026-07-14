use crate::util::{abs_normalize, home_dir};
use anyhow::Result;
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Compiled-in, non-overridable path denylist. Config may *add* patterns,
/// never remove these. Every source open is checked against it before any
/// `open()` — for read or delete.
pub struct Blacklist {
    set: GlobSet,
    patterns: Vec<String>,
    /// Cardinal credential file paths, re-stat'd live on every check so a
    /// hardlink to one — even created *after* compile — is refused by inode.
    /// This closes the compile-time-snapshot TOCTOU for the highest-value files.
    credential_paths: Vec<String>,
    /// Compile-time inode snapshot of rolling `backups/*` (lower value; a file
    /// rotated in mid-run is a narrow, non-cardinal window).
    backup_inodes: HashSet<(u64, u64)>,
}

impl Blacklist {
    /// Build the denylist, anchoring `~`-relative entries to the real `$HOME`
    /// and folding in any config-supplied additions.
    pub fn compile(extra: &[String]) -> Result<Self> {
        let home = home_dir()?;
        let home = home.to_string_lossy();

        let base = [
            "~/.claude/.credentials.json",
            "~/.claude.json",
            "~/.claude/backups/**",
            "~/.claude/mcp-needs-auth-cache.json",
            "~/.zaibatsu/**",
            "~/.local/share/claude/versions/**",
            "~/.local/state/claude/locks/**",
        ];

        let mut builder = GlobSetBuilder::new();
        let mut patterns = Vec::new();
        for pat in base
            .iter()
            .map(|s| s.to_string())
            .chain(extra.iter().cloned())
        {
            let anchored = if let Some(rest) = pat.strip_prefix("~/") {
                format!("{home}/{rest}")
            } else {
                pat.clone()
            };
            builder.add(Glob::new(&anchored)?);
            patterns.push(anchored);
        }

        // Cardinal credential files re-stat'd live per check (closes TOCTOU);
        // backups snapshotted at compile.
        let claude = format!("{home}/.claude");
        let credential_paths = vec![
            format!("{claude}/.credentials.json"),
            format!("{home}/.claude.json"),
            format!("{claude}/mcp-needs-auth-cache.json"),
        ];
        let mut backup_inodes = HashSet::new();
        if let Ok(entries) = std::fs::read_dir(format!("{claude}/backups")) {
            for e in entries.flatten() {
                if let Ok(md) = std::fs::metadata(e.path()) {
                    backup_inodes.insert((md.dev(), md.ino()));
                }
            }
        }

        Ok(Blacklist {
            set: builder.build()?,
            patterns,
            credential_paths,
            backup_inodes,
        })
    }

    /// True if the normalized path matches a denied glob (so relative/symlink
    /// forms cannot slip past).
    pub fn path_denied(&self, path: &Path) -> bool {
        self.set.is_match(abs_normalize(path))
    }

    /// True if `ino` is a denied credential's inode — a backup snapshotted at
    /// compile, or a cardinal credential re-stat'd live now (so a hardlink made
    /// after this Blacklist was built is still caught, B4 TOCTOU).
    pub fn inode_denied(&self, ino: (u64, u64)) -> bool {
        if self.backup_inodes.contains(&ino) {
            return true;
        }
        self.credential_paths.iter().any(|p| {
            std::fs::metadata(p)
                .map(|m| (m.dev(), m.ino()) == ino)
                .unwrap_or(false)
        })
    }

    /// Path-only convenience (stats the path itself). Callers that will open the
    /// file should instead gate on the opened fd's inode via [`Self::inode_denied`]
    /// to avoid a check→open race (S3).
    pub fn is_blacklisted(&self, path: &Path) -> bool {
        if self.path_denied(path) {
            return true;
        }
        match std::fs::metadata(path) {
            Ok(md) => self.inode_denied((md.dev(), md.ino())),
            Err(_) => false,
        }
    }

    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_home<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
        // Tests run single-threaded via `--test-threads` is not assumed; each
        // asserts against an explicit home, so set and restore around the call.
        let prev = std::env::var_os("HOME");
        // SAFETY: test-only, serialized by the blacklist test module.
        unsafe { std::env::set_var("HOME", dir) };
        let out = f();
        // SAFETY: restore prior value.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        out
    }

    #[test]
    fn denies_credentials_and_config() {
        let home = std::path::PathBuf::from("/home/tester");
        with_home(&home, || {
            let bl = Blacklist::compile(&[]).unwrap();
            assert!(bl.is_blacklisted(&home.join(".claude/.credentials.json")));
            assert!(bl.is_blacklisted(&home.join(".claude.json")));
            assert!(bl.is_blacklisted(&home.join(".claude/backups/.claude.json.backup.123")));
            assert!(bl.is_blacklisted(&home.join(".claude/mcp-needs-auth-cache.json")));
            assert!(bl.is_blacklisted(&home.join(".zaibatsu/memory/anything")));
            assert!(bl.is_blacklisted(&home.join(".local/share/claude/versions/2.1.207/x")));
            assert!(bl.is_blacklisted(&home.join(".local/state/claude/locks/a.lock")));
        });
    }

    #[test]
    fn permits_transcripts() {
        let home = std::path::PathBuf::from("/home/tester");
        with_home(&home, || {
            let bl = Blacklist::compile(&[]).unwrap();
            assert!(!bl.is_blacklisted(&home.join(".claude/projects/-home/uuid.jsonl")));
            assert!(!bl.is_blacklisted(&home.join(".claude/history.jsonl")));
        });
    }

    #[test]
    fn config_can_add_not_remove() {
        let home = std::path::PathBuf::from("/home/tester");
        with_home(&home, || {
            let bl = Blacklist::compile(&["~/.claude/secret-notes/**".into()]).unwrap();
            assert!(bl.is_blacklisted(&home.join(".claude/secret-notes/a.txt")));
            // base entries still enforced
            assert!(bl.is_blacklisted(&home.join(".claude/.credentials.json")));
        });
    }

    #[test]
    fn denies_hardlink_to_credentials() {
        let tmp = std::env::temp_dir().join(format!("yomi-bl-{}", std::process::id()));
        let claude = tmp.join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        let cred = claude.join(".credentials.json");
        std::fs::write(&cred, b"{\"token\":\"secret\"}").unwrap();
        // A hardlink at a path the glob does NOT deny.
        let link = tmp.join(".claude/projects/-x/evil.jsonl");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::fs::hard_link(&cred, &link).unwrap();

        with_home(&tmp, || {
            let bl = Blacklist::compile(&[]).unwrap();
            assert!(bl.is_blacklisted(&cred), "path glob failed");
            assert!(
                bl.is_blacklisted(&link),
                "hardlink to credentials bypassed the denylist"
            );
            // A distinct file at the same kind of path is still allowed.
            let benign = tmp.join(".claude/projects/-x/real.jsonl");
            std::fs::write(&benign, b"{}").unwrap();
            assert!(!bl.is_blacklisted(&benign));

            // TOCTOU: a hardlink created *after* the Blacklist was built is still
            // caught, because credential paths are re-stat'd live per check (B4).
            let late = tmp.join(".claude/projects/-x/late.jsonl");
            std::fs::hard_link(&cred, &late).unwrap();
            assert!(
                bl.is_blacklisted(&late),
                "post-compile hardlink to credentials bypassed the denylist"
            );
        });
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
