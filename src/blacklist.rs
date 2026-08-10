use crate::config::Env;
use crate::util::{abs_normalize, home_dir};
use anyhow::Result;
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::collections::HashSet;
use std::fs::{File, Metadata};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Result of a blacklist-gated open. The one open in the codebase: both
/// archive-read and gc-delete route through [`Blacklist::open_guarded`], so
/// no path can be read or unlinked without passing the same denylist.
pub enum GuardOutcome {
    /// Path-glob or opened-inode matched the denylist. Never touch.
    Denied,
    /// The path could not be opened or stat'd (missing, permission, race).
    Unreadable,
    /// Opened; the caller holds the fd and its metadata (pinned inode).
    Opened(File, Metadata),
}

/// Compiled-in, non-overridable path denylist. Config may *add* patterns,
/// never remove these. Every source open is checked against it before any
/// `open()` — for read or delete.
pub struct Blacklist {
    set: GlobSet,
    patterns: Vec<String>,
    /// Cardinal credential file paths, re-stat'd live on every check so a
    /// hardlink to one — even created *after* compile — is refused by inode.
    /// This closes the compile-time-snapshot TOCTOU for the highest-value files.
    credential_paths: Vec<PathBuf>,
    /// Compile-time inode snapshot of rolling `backups/*` (lower value; a file
    /// rotated in mid-run is a narrow, non-cardinal window).
    backup_inodes: HashSet<(u64, u64)>,
}

/// The compiled-in entries, `~`-relative. Config may add to this list, never
/// remove from it.
const BASE: [&str; 7] = [
    "~/.claude/.credentials.json",
    "~/.claude.json",
    "~/.claude/backups/**",
    "~/.claude/mcp-needs-auth-cache.json",
    "~/.zaibatsu/**",
    "~/.local/share/claude/versions/**",
    "~/.local/state/claude/locks/**",
];

impl Blacklist {
    /// Build the denylist for a run: the compiled-in entries anchored to the real
    /// `$HOME`, **yomi's own store root**, and the config's additions.
    ///
    /// The store root is taken from `env` rather than assumed, because
    /// `$YOMI_HOME` and `--home` move it.
    pub fn compile(env: &Env) -> Result<Self> {
        Self::compile_with_roots(&home_dir()?, &env.home, &env.config.blacklist_add)
    }

    /// [`Self::compile`] against an explicit home and store root. Callers (and
    /// tests) that need the denylist anchored somewhere other than `$HOME` use
    /// this instead of mutating the process-global environment, which races every
    /// other thread reading it.
    pub fn compile_with_roots(home: &Path, store_root: &Path, extra: &[String]) -> Result<Self> {
        // yomi's own store. `quarantine/` holds unredacted originals by design,
        // so a store that lands inside a walked source root — a scratch tree,
        // most plausibly, via `$YOMI_HOME` or `--home` — is otherwise read back
        // as ordinary work files: every run copies the previous run's raw
        // secrets one level deeper and quarantines them again, unbounded. Nothing
        // else refuses it; the default `~/.yomi` was safe only by sitting outside
        // the three source roots by accident.
        //
        // Self-exclusion belongs on the denylist rather than in the scratch walk
        // because this is the one gate every read and every unlink in yomi
        // already passes. The bare root as well as its contents: a source path
        // naming the store directory itself is refused too.
        let store = anchor_literal(store_root);
        let mut patterns = vec![format!("{store}/**"), store];
        patterns.extend(
            BASE.iter()
                .map(|s| anchor_pattern(s, home))
                .chain(extra.iter().map(|p| anchor_pattern(p, home))),
        );

        let mut builder = GlobSetBuilder::new();
        for pat in &patterns {
            builder.add(Glob::new(pat)?);
        }

        // Cardinal credential files re-stat'd live per check (closes TOCTOU);
        // backups snapshotted at compile. Filesystem paths rather than globs, so
        // they take the resolved home unescaped.
        let home = abs_normalize(home);
        let claude = home.join(".claude");
        let credential_paths = vec![
            claude.join(".credentials.json"),
            home.join(".claude.json"),
            claude.join("mcp-needs-auth-cache.json"),
        ];
        let mut backup_inodes = HashSet::new();
        if let Ok(entries) = std::fs::read_dir(claude.join("backups")) {
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

    /// Open `path` under the hard denylist, pinning the opened fd's inode. The
    /// path-name glob is checked first (cheap, covers globbed dirs); the file is
    /// then opened **once** and its own fstat'd `(dev,ino)` is checked against the
    /// live credential inodes, so a path swapped to a credential hardlink between
    /// check and open cannot slip through (S3/B4). Every read and every unlink in
    /// yomi goes through this — there is exactly one blacklist-gated open.
    pub fn open_guarded(&self, path: &Path) -> Result<GuardOutcome> {
        if self.path_denied(path) {
            return Ok(GuardOutcome::Denied);
        }
        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return Ok(GuardOutcome::Unreadable),
        };
        let md = match file.metadata() {
            Ok(m) => m,
            Err(_) => return Ok(GuardOutcome::Unreadable),
        };
        if self.inode_denied((md.dev(), md.ino())) {
            return Ok(GuardOutcome::Denied);
        }
        Ok(GuardOutcome::Opened(file, md))
    }
}

/// Glob metacharacters, exactly the set [`globset::escape`] neutralizes. The two
/// have to agree: this decides where a pattern's literal prefix ends, and that
/// prefix is what gets escaped.
const META: [char; 6] = ['?', '*', '[', ']', '{', '}'];

/// Anchor one denylist entry: substitute `$HOME` for a leading `~/`, then resolve
/// the entry's leading metacharacter-free path through the filesystem exactly the
/// way [`abs_normalize`] resolves the paths it will be matched against.
///
/// The resolution is what makes the glob cover what it claims. Patterns used to be
/// built from an unresolved `$HOME` while every subject was canonicalized, so on a
/// symlinked home — NFS homes, bind mounts, `/home` → `/mnt/home` — pattern and
/// subject named different strings and three entries silently stopped matching:
/// `~/.zaibatsu/**`, `~/.local/share/claude/versions/**` and
/// `~/.local/state/claude/locks/**`, the entries with no inode backstop behind
/// them. Resolving the whole literal prefix rather than just the home also covers
/// a symlink *inside* the denied path (`~/.zaibatsu` → `/mnt/secrets`), which a
/// per-entry inode snapshot could not, and costs nothing per entry added.
///
/// Only the literal prefix is resolved and escaped; every component from the first
/// one holding a metacharacter onward is the entry's glob and is left verbatim.
/// Escaping matters because the substituted home is a path, not a pattern: a real
/// directory named `a[1]` must match itself, not be read as a character class that
/// matches `a1`.
fn anchor_pattern(pattern: &str, home: &Path) -> String {
    let (literal, tail) = split_literal(pattern);
    let base = match pattern.strip_prefix("~/") {
        // `split_literal` ran on the whole pattern, so the literal still carries
        // the `~/`; the home replaces it.
        Some(_) => match literal.strip_prefix("~/") {
            Some(rest) => home.join(rest),
            // The glob starts in the very first component after `~/`.
            None => home.to_path_buf(),
        },
        // An absolute entry is resolved the same way. A relative one has no
        // filesystem anchor, and binding it to the process cwd would invent a
        // meaning it does not have, so it is left exactly as written.
        None if Path::new(literal).is_absolute() => PathBuf::from(literal),
        None => return pattern.to_string(),
    };
    let anchored = anchor_literal(&base);
    match tail {
        Some(tail) => {
            let mut p = PathBuf::from(anchored);
            p.push(tail);
            p.to_string_lossy().into_owned()
        }
        None => anchored,
    }
}

/// A literal path as a glob: resolved through the filesystem, then escaped so
/// none of its own characters are read as pattern syntax.
fn anchor_literal(path: &Path) -> String {
    globset::escape(&abs_normalize(path).to_string_lossy())
}

/// Split a pattern at the last `/` before its first metacharacter, into the
/// leading literal path and the glob tail: `"~/a/b/**"` → `("~/a/b", Some("**"))`,
/// `"~/a/b"` → `("~/a/b", None)`, `"**/x"` → `("", Some("**/x"))`.
fn split_literal(pattern: &str) -> (&str, Option<&str>) {
    let Some(at) = pattern.find(META) else {
        return (pattern, None);
    };
    match pattern[..at].rfind('/') {
        // Keep the root with the literal so an absolute pattern stays absolute.
        Some(0) => ("/", Some(&pattern[1..])),
        Some(slash) => (&pattern[..slash], Some(&pattern[slash + 1..])),
        None => ("", Some(pattern)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The denylist for a home, with that home's default store root.
    fn at(home: &Path, extra: &[String]) -> Blacklist {
        Blacklist::compile_with_roots(home, &home.join(".yomi"), extra).unwrap()
    }

    fn tmpdir(tag: &str) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("yomi-bl-{tag}-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Every compiled-in entry, as a home-relative path that must be refused.
    const DENIED_SUBJECTS: [&str; 7] = [
        ".claude/.credentials.json",
        ".claude.json",
        ".claude/backups/.claude.json.backup.1",
        ".claude/mcp-needs-auth-cache.json",
        ".zaibatsu/memory/x.jsonl",
        ".local/share/claude/versions/v/x.jsonl",
        ".local/state/claude/locks/a.jsonl",
    ];

    #[test]
    fn denies_credentials_and_config() {
        let home = std::path::PathBuf::from("/home/tester");
        let bl = at(&home, &[]);
        for rel in DENIED_SUBJECTS {
            assert!(bl.is_blacklisted(&home.join(rel)), "{rel} not refused");
        }
        assert!(bl.is_blacklisted(&home.join(".local/share/claude/versions/2.1.207/x")));
        assert!(bl.is_blacklisted(&home.join(".claude/backups/.claude.json.backup.123")));
    }

    #[test]
    fn permits_transcripts() {
        let home = std::path::PathBuf::from("/home/tester");
        let bl = at(&home, &[]);
        assert!(!bl.is_blacklisted(&home.join(".claude/projects/-home/uuid.jsonl")));
        assert!(!bl.is_blacklisted(&home.join(".claude/history.jsonl")));
    }

    #[test]
    fn config_can_add_not_remove() {
        let home = std::path::PathBuf::from("/home/tester");
        let bl = at(&home, &["~/.claude/secret-notes/**".into()]);
        assert!(bl.is_blacklisted(&home.join(".claude/secret-notes/a.txt")));
        // base entries still enforced
        assert!(bl.is_blacklisted(&home.join(".claude/.credentials.json")));
    }

    /// yomi's own store is refused as a source, wherever `$YOMI_HOME` puts it.
    ///
    /// The unbounded case this exists for: a store under a scratch tree, whose
    /// `quarantine/` holds unredacted originals that the next `archive --include
    /// scratch` would read back as ordinary `*.md`/`*.json` work files. See
    /// `tests/p18_self_ingest_break.rs` for the two-pass measurement.
    #[test]
    fn denies_its_own_store() {
        let base = tmpdir("store");
        let home = base.join("home");
        let store = base.join("tmp/-slug/s1/yomi");
        std::fs::create_dir_all(store.join("quarantine/_scratch/-slug--s1/scratchpad")).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        let leak = store.join("quarantine/_scratch/-slug--s1/scratchpad/leak.md");
        std::fs::write(&leak, b"x").unwrap();

        let bl = Blacklist::compile_with_roots(&home, &store, &[]).unwrap();
        assert!(bl.path_denied(&leak), "quarantined original re-ingestible");
        assert!(bl.path_denied(&store.join("archive/_scratch/-slug--s1/manifest.json")));
        assert!(bl.path_denied(&store.join("state/catalog.db")));
        assert!(bl.path_denied(&store.join(".yomi-store")));
        assert!(bl.path_denied(&store), "the store root itself");
        // A sibling inside the same scratch tree is still archivable — the
        // exclusion is the store, not the tree that happens to contain it.
        let sibling = base.join("tmp/-slug/s1/scratchpad/notes.md");
        std::fs::create_dir_all(sibling.parent().unwrap()).unwrap();
        std::fs::write(&sibling, b"x").unwrap();
        assert!(!bl.is_blacklisted(&sibling));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The three entries that fail *open* on a symlinked `$HOME`: glob-only, with
    /// no inode backstop behind them. The four cardinal ones survived it because
    /// they are re-stat'd (`.credentials.json`, `~/.claude.json`,
    /// `mcp-needs-auth-cache.json`) or inode-snapshotted (`backups/**`).
    ///
    /// `~/.zaibatsu` is the 八百万重工 secret-management tree, so this was a live
    /// exfiltration path on any host whose `$HOME` is a link — NFS homes, bind
    /// mounts, `/home` → `/mnt/home`.
    const GLOB_ONLY_SUBJECTS: [&str; 3] = [
        ".zaibatsu/memory/x.jsonl",
        ".local/share/claude/versions/v/x.jsonl",
        ".local/state/claude/locks/a.jsonl",
    ];

    /// A symlinked `$HOME` used to build patterns under the link while
    /// `abs_normalize` resolved every subject to the target, so the glob matched
    /// nothing. All seven entries must be refused through either name, by the glob
    /// alone — and the three without a backstop must reach the same verdict
    /// end-to-end, which is what [`Blacklist::is_blacklisted`] answers.
    #[test]
    fn a_symlinked_home_still_denies_every_entry() {
        let base = tmpdir("symhome");
        let real = base.join("real");
        let link = base.join("link");
        for rel in DENIED_SUBJECTS {
            let p = real.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"secret").unwrap();
        }
        std::os::unix::fs::symlink(&real, &link).unwrap();

        for home in [&link, &real] {
            let bl = at(home, &[]);
            for rel in DENIED_SUBJECTS {
                // Both spellings of the same inode, under either anchor.
                assert!(
                    bl.path_denied(&link.join(rel)),
                    "HOME={}: {rel} archivable through the link",
                    home.display()
                );
                assert!(
                    bl.path_denied(&real.join(rel)),
                    "HOME={}: {rel} archivable through the target",
                    home.display()
                );
            }
            for rel in GLOB_ONLY_SUBJECTS {
                assert!(
                    bl.is_blacklisted(&link.join(rel)),
                    "HOME={}: {rel} still reaches the archive",
                    home.display()
                );
            }
            assert!(!bl.path_denied(&link.join(".claude/projects/-x/u.jsonl")));
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The same resolution covers a symlink *inside* a denied path, which no
    /// per-entry inode snapshot could: `~/.zaibatsu` pointing at another volume.
    #[test]
    fn a_symlinked_denied_directory_is_still_denied() {
        let base = tmpdir("symdir");
        let home = base.join("home");
        let elsewhere = base.join("volume/zaibatsu");
        std::fs::create_dir_all(elsewhere.join("memory")).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(elsewhere.join("memory/x.jsonl"), b"secret").unwrap();
        std::os::unix::fs::symlink(&elsewhere, home.join(".zaibatsu")).unwrap();

        let bl = at(&home, &[]);
        assert!(bl.path_denied(&home.join(".zaibatsu/memory/x.jsonl")));
        assert!(
            bl.path_denied(&elsewhere.join("memory/x.jsonl")),
            "the real path of a denied tree slipped past"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A glob metacharacter in a real directory name is a literal, not syntax.
    /// Unescaped, `$HOME = .../a[1]` compiled to a character class that matched
    /// `.../a1` and left the actual home wide open.
    #[test]
    fn a_metacharacter_in_the_home_path_is_literal() {
        let base = tmpdir("meta");
        let home = base.join("a[1]");
        std::fs::create_dir_all(home.join(".zaibatsu/memory")).unwrap();
        std::fs::write(home.join(".zaibatsu/memory/x.jsonl"), b"secret").unwrap();

        let bl = at(&home, &[]);
        assert!(bl.path_denied(&home.join(".zaibatsu/memory/x.jsonl")));
        assert!(!bl.path_denied(&base.join("a1/.zaibatsu/memory/x.jsonl")));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn splits_a_pattern_at_its_first_metacharacter() {
        assert_eq!(split_literal("~/.zaibatsu/**"), ("~/.zaibatsu", Some("**")));
        assert_eq!(
            split_literal("~/.claude/.credentials.json"),
            ("~/.claude/.credentials.json", None)
        );
        assert_eq!(split_literal("~/*.md"), ("~", Some("*.md")));
        assert_eq!(split_literal("~/**"), ("~", Some("**")));
        assert_eq!(split_literal("**/x"), ("", Some("**/x")));
        assert_eq!(split_literal("/a[1]/b"), ("/", Some("a[1]/b")));
        assert_eq!(split_literal("/a/b/*.log"), ("/a/b", Some("*.log")));
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

        let bl = at(&tmp, &[]);
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
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
