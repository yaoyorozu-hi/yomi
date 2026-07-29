use crate::util::{expand_tilde, home_dir};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Parsed `config.toml`, with design-default values when absent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub blacklist_add: Vec<String>,
    pub scratch: ScratchConfig,
    pub scan: ScanConfig,
    pub gc: GcConfig,
    pub index: IndexConfig,
}

/// `[index]` policy. `#[serde(default)]` keeps existing configs (with no
/// `[index]` block) parsing unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IndexConfig {
    /// FTS5 tokenizer: `"unicode61"` (default, best for English/code, supports
    /// prefix/AND/OR/NEAR operators) or `"trigram"` (substring match across all
    /// scripts including CJK, opt-in for Japanese-heavy corpora). Changing this
    /// requires `yomi index --reindex` (a destructive FTS rebuild).
    pub tokenizer: String,
}

impl Default for IndexConfig {
    fn default() -> Self {
        IndexConfig {
            tokenizer: "unicode61".to_string(),
        }
    }
}

impl IndexConfig {
    /// The full FTS5 `tokenize=` clause for the configured tokenizer.
    pub fn tokenize_clause(&self) -> &'static str {
        match self.tokenizer.as_str() {
            "trigram" => "trigram",
            _ => "unicode61 remove_diacritics 2",
        }
    }

    /// The stable identity recorded in `index_meta` and compared for reindex
    /// detection (normalized so an unknown value falls back to the default).
    pub fn effective_tokenizer(&self) -> &'static str {
        match self.tokenizer.as_str() {
            "trigram" => "trigram",
            _ => "unicode61",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScratchConfig {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub file_cap: ByteSize,
    pub total_cap: ByteSize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// Regexes or secret-sha8 values known benign; a match suppresses a finding.
    pub allow: Vec<String>,
}

/// A human byte size like "5MB", stored as bytes. Like [`DurationSetting`] it
/// *fails closed*: a malformed or overflowing value (`"5XB"`, `"99999999999GB"`)
/// is a hard config error, never a silent `0` cap that would quietly change the
/// archive's storage behavior.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ByteSize(pub u64);

impl TryFrom<String> for ByteSize {
    type Error = String;
    fn try_from(s: String) -> std::result::Result<Self, String> {
        parse_bytes(&s)
            .map(ByteSize)
            .ok_or_else(|| format!("invalid byte size {s:?} (use e.g. \"5MB\", \"20MB\", \"1GB\")"))
    }
}

impl From<ByteSize> for String {
    fn from(b: ByteSize) -> String {
        format!("{}", b.0)
    }
}

fn parse_bytes(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix("GB") {
        (n, 1024u64 * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("MB") {
        (n, 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("KB") {
        (n, 1024)
    } else if let Some(n) = s.strip_suffix("B") {
        (n, 1)
    } else {
        (s, 1)
    };
    num.trim()
        .parse::<u64>()
        .ok()
        .and_then(|v| v.checked_mul(mult))
}

/// A human duration like "7d", stored as a `Duration`. Mirrors [`ByteSize`],
/// but *fails closed*: a malformed value (`"7dd"`, `""`) is a hard config error,
/// never a silent `Duration::ZERO`. GC is a destructive tool — it must refuse to
/// run under an unparseable retain/floor policy rather than treat it as "delete
/// everything, age 0" (R2).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DurationSetting(pub Duration);

impl TryFrom<String> for DurationSetting {
    type Error = String;
    fn try_from(s: String) -> std::result::Result<Self, String> {
        parse_duration(&s).map(DurationSetting).ok_or_else(|| {
            format!("invalid duration setting {s:?} (use e.g. \"7d\", \"90d\", \"1h\", \"1w\")")
        })
    }
}

impl From<DurationSetting> for String {
    fn from(d: DurationSetting) -> String {
        humanize_duration(d.0.as_secs())
    }
}

/// Render seconds as the largest whole unit that divides evenly (`604800` →
/// `"1w"`, `3600` → `"1h"`), falling back to bare seconds (`"0s"` for zero).
/// The result always round-trips through [`parse_duration`].
fn humanize_duration(secs: u64) -> String {
    for (unit, mult) in [("w", 604_800u64), ("d", 86_400), ("h", 3_600), ("m", 60)] {
        if secs != 0 && secs.is_multiple_of(mult) {
            return format!("{}{unit}", secs / mult);
        }
    }
    format!("{secs}s")
}

/// Parse `"7d"` → 7 days. Units: `s`, `m`, `h`, `d`, `w`; a bare number is
/// seconds. Returns `None` on a malformed value.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix('w') {
        (n, 604_800u64)
    } else if let Some(n) = s.strip_suffix('d') {
        (n, 86_400)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3_600)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1)
    } else {
        (s, 1)
    };
    num.trim()
        .parse::<u64>()
        .ok()
        .and_then(|v| v.checked_mul(mult))
        .map(Duration::from_secs)
}

/// `[gc]` policy: per-target retain windows plus the hard `min_age` floor.
/// `#[serde(default)]` means an absent `[gc]` block yields these defaults, so
/// existing configs keep parsing unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GcConfig {
    /// Hard floor: nothing younger is ever deleted, whatever the target.
    pub min_age: DurationSetting,
    pub transcript_retain: DurationSetting,
    pub scratch_retain: DurationSetting,
    pub mcp_log_retain: DurationSetting,
    pub paste_retain: DurationSetting,
    pub snapshot_retain: DurationSetting,
    /// mtime-liveness window (issue #2 `active_window`, default 1h): any target
    /// whose newest mtime falls within this is treated as live and protected.
    pub active_window: DurationSetting,
    /// Inert in P2 (history is not a GC target); a `true` value warns and is ignored.
    pub history_compact: bool,
    /// Default false. When `true` the GC delete gate (P3) consults per-source
    /// `index_state`: a source is deletable only if indexed at its current source
    /// sha; un-indexed or stale-indexed sources are skipped (fail-closed).
    pub require_indexed: bool,
}

impl Default for GcConfig {
    fn default() -> Self {
        GcConfig {
            min_age: DurationSetting(Duration::from_secs(7 * 86_400)),
            transcript_retain: DurationSetting(Duration::from_secs(90 * 86_400)),
            scratch_retain: DurationSetting(Duration::from_secs(3 * 86_400)),
            mcp_log_retain: DurationSetting(Duration::from_secs(14 * 86_400)),
            paste_retain: DurationSetting(Duration::from_secs(14 * 86_400)),
            snapshot_retain: DurationSetting(Duration::from_secs(30 * 86_400)),
            active_window: DurationSetting(Duration::from_secs(3_600)),
            history_compact: false,
            require_indexed: false,
        }
    }
}

impl Default for ScratchConfig {
    fn default() -> Self {
        ScratchConfig {
            allow: [
                "*.md", "*.txt", "*.json", "*.output", "*.log", "*.csv", "*.sh", "*.py",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            deny: [
                ".git/**",
                "node_modules/**",
                "target/**",
                "**/*.mp4",
                "**/*.zip",
                "**/*.tar",
                "**/*.iso",
                "**/*.bin",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            file_cap: ByteSize(5 * 1024 * 1024),
            total_cap: ByteSize(20 * 1024 * 1024),
        }
    }
}

/// Resolved runtime paths and settings for a yomi invocation.
pub struct Env {
    pub home: PathBuf,
    pub config: Config,
    pub config_path: PathBuf,
}

impl Env {
    /// Resolve `YOMI_HOME` from (in order) `home_override`, `$YOMI_HOME`,
    /// then `~/.yomi`; load `config.toml` if present.
    pub fn resolve(home_override: Option<&Path>, config_override: Option<&Path>) -> Result<Self> {
        let home = if let Some(h) = home_override {
            h.to_path_buf()
        } else if let Some(v) = std::env::var_os("YOMI_HOME") {
            PathBuf::from(v)
        } else {
            home_dir()?.join(".yomi")
        };

        let config_path = config_override
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| home.join("config.toml"));

        let config = if config_path.exists() {
            let text = std::fs::read_to_string(&config_path)
                .with_context(|| format!("read {}", config_path.display()))?;
            toml::from_str(&text).with_context(|| format!("parse {}", config_path.display()))?
        } else {
            Config::default()
        };

        Ok(Env {
            home,
            config,
            config_path,
        })
    }

    pub fn archive_dir(&self) -> PathBuf {
        self.home.join("archive")
    }
    pub fn quarantine_dir(&self) -> PathBuf {
        self.home.join("quarantine")
    }
    pub fn state_dir(&self) -> PathBuf {
        self.home.join("state")
    }
    pub fn catalog_path(&self) -> PathBuf {
        self.state_dir().join("catalog.db")
    }
    pub fn lock_path(&self) -> PathBuf {
        self.home.join(".yomi.lock")
    }

    /// Marker proving this directory is a yomi store (guards `--fix-perms`).
    pub fn marker_path(&self) -> PathBuf {
        self.home.join(".yomi-store")
    }

    /// Session archive directory `archive/<slug>/<uuid>/`.
    pub fn session_dir(&self, slug: &str, uuid: &str) -> PathBuf {
        self.archive_dir().join(slug).join(uuid)
    }

    /// Whether the store exists and has been initialized by yomi.
    ///
    /// **Not a lock gate** — see [`Env::store_exists`]. This asks whether yomi's
    /// bookkeeping is present, which is the right question for "is there
    /// anything here worth writing an inventory beside".
    pub fn is_initialized(&self) -> bool {
        self.marker_path().exists() || self.catalog_path().exists()
    }

    /// Whether a store is **there** — the question a read-side command must ask
    /// before taking the write lock.
    ///
    /// Distinct from [`Env::is_initialized`] deliberately, rather than widening
    /// it: that predicate's other caller asks a different question and must not
    /// change meaning. A lock gate exists so a read-side command does not
    /// *create* a store on a fresh home; for that the question is whether a store
    /// is present, not whether it still has its bookkeeping. A store that lost
    /// its marker and its `catalog.db` while `archive/` survives intact is
    /// entirely present — and gating on the bookkeeping made `verify` never
    /// attempt the lock there, so `exclusive` was false on every run forever and
    /// the pass could confirm but never accuse. Taking the lock inside an
    /// existing store directory creates only `.yomi.lock`, which every mutating
    /// command already does.
    pub fn store_exists(&self) -> bool {
        self.marker_path().exists() || self.archive_dir().exists() || self.state_dir().exists()
    }

    /// The fixed set of directories yomi asserts it owns, outermost first.
    ///
    /// **Membership is decided by one question: would a foreign member make
    /// every later operation untrustworthy?** That is what earns an abort, and
    /// only these four answer yes — each is load-bearing for *every* artifact.
    /// A foreign `~/.yomi/` puts the whole store elsewhere; a foreign `archive/`
    /// puts every stored artifact there; a foreign `state/` puts the catalog
    /// every gate consults there; a foreign `quarantine/` puts every unredacted
    /// original there, which is an exfiltration channel as well as a loss.
    ///
    /// **`archive/_scratch/` is deliberately not a member**, and the reason it
    /// once looked like one is worth keeping: it is the root of *one artifact
    /// family*, not of the store. A symlink on it costs the scratch artifacts
    /// and nothing else — transcript capture, the catalog and the quarantine
    /// tree are untouched — so refusing the whole run over it aborts work that
    /// is provably still safe.
    ///
    /// It also needs no assertion here to be guarded: the scratch root is
    /// classified together with the key at every one of the five sites that
    /// resolve a key *through* it — archive's writer, its reconciler, the GC
    /// gate, `verify` and `ScratchStore::open`. A layout-level check would be a
    /// pure duplicate of a guard already made per use, whose only remaining
    /// effect is the abort.
    fn owned_dirs(&self) -> [PathBuf; 4] {
        [
            self.home.clone(),
            self.archive_dir(),
            self.quarantine_dir(),
            self.state_dir(),
        ]
    }

    /// True if `home` is an existing dir that yomi may safely operate on: it is
    /// empty, or already carries the yomi marker/layout. Prevents `--fix-perms`
    /// from chmod-700-ing an unrelated directory (R7).
    fn looks_like_store(&self) -> bool {
        if !self.home.exists() {
            return true;
        }
        if self.marker_path().exists() || self.archive_dir().exists() || self.state_dir().exists() {
            return true;
        }
        std::fs::read_dir(&self.home)
            .map(|mut it| it.next().is_none())
            .unwrap_or(false)
    }

    /// Create the store root and required subdirectories with mode 700.
    /// Refuses (returns Err) if an existing root is looser than 700 and
    /// `fix_perms` is false.
    ///
    /// **Mutates process-global state and never restores it.** This sets the
    /// process umask to `0o077` and discards the previous value, so every later
    /// file created by *any* thread of the calling process is owner-only. That is
    /// exactly what the `yomi` binary wants; a library consumer that calls this
    /// has its own umask permanently rewritten with no way to recover what it was.
    pub fn ensure_layout(&self, fix_perms: bool) -> Result<()> {
        // Tighten umask so nested creates never widen beyond owner. Spelled in
        // octal because that is how a umask is read and reasoned about.
        rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o077));

        // The store root, classified before anything is created or chmod'd
        // through it. Every mutating run re-asserts this, because ownership is a
        // property of the moment a write happens and not of the moment a store
        // was created.
        //
        // Refused, never repaired, for the reason a store directory is: a symlink
        // there may be an operator who deliberately put part of the store on
        // another volume, and replacing it would orphan that data and silently
        // begin an empty one. Refusing is reversible by hand; replacing is not.
        //
        // **This is the one member still checked through a path**, because it is
        // the outermost boundary — the path `--home` names, with no descriptor
        // above it to descend from. The three below it are asserted differently;
        // see the descent after the permission check.
        if crate::scratch::classify_store_dir(&self.home) == crate::scratch::StoreDir::Foreign {
            bail!(
                "refuse: {} is not a directory this run owns (a symlink, a \
                 file, or a path it cannot stat); yomi will not write through \
                 it. Move or remove it — it is not repaired automatically, \
                 because it may be deliberate.",
                self.home.display()
            );
        }

        if self.home.exists() {
            let mode = std::fs::metadata(&self.home)?.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                if fix_perms {
                    if !self.looks_like_store() {
                        bail!(
                            "refuse: {} is not a yomi store (no marker/layout); \
                             will not chmod an unrelated directory",
                            self.home.display()
                        );
                    }
                    std::fs::set_permissions(&self.home, std::fs::Permissions::from_mode(0o700))?;
                } else {
                    bail!(
                        "refuse: {} is mode {:o}, looser than 700 (run with --fix-perms)",
                        self.home.display(),
                        mode
                    );
                }
            }
        } else {
            std::fs::create_dir_all(&self.home)?;
            std::fs::set_permissions(&self.home, std::fs::Permissions::from_mode(0o700))?;
        }

        // **The assertion and the creation are one operation**, sharing the store
        // root's descriptor. Classifying by path and then creating by path left a
        // window between them: a symlink planted after the check was followed by
        // the `create_dir_all` and the `set_permissions` that came next, so the
        // guard proved a fact about a moment that had already passed. `child`
        // does `mkdirat`, then `openat` with `O_NOFOLLOW`, then `fchmod` through
        // the descriptor it just obtained — there is no interval in which a
        // different object can be substituted, because nothing is re-resolved.
        //
        // Uniform across the set: every member is created and tightened the same
        // way, because "the fixed set is asserted" is the whole contract and a
        // special case dissolves it.
        let root = crate::safefs::Dir::open_root(&self.home)
            .with_context(|| format!("open store root {}", self.home.display()))?;
        for dir in self.owned_dirs().into_iter().skip(1) {
            let name = dir
                .file_name()
                .expect("every owned directory below the root is named");
            root.child(name, 0o700).with_context(|| {
                format!(
                    "refuse: {} is not a directory this run owns (a symlink, a \
                     file, or a path it cannot stat); yomi will not write through \
                     it. Move or remove it — it is not repaired automatically, \
                     because it may be deliberate.",
                    dir.display()
                )
            })?;
        }

        // Through the same descriptor, so a link planted at the marker's name
        // cannot capture the write either. Still only when absent: an existing
        // marker is left exactly as it is.
        let marker = self.marker_path();
        if !marker.exists() {
            root.write_atomic(
                marker
                    .file_name()
                    .expect("the marker path always has a name"),
                b"yomi store\n",
                0o600,
            )?;
        }
        Ok(())
    }

    /// Tighten a just-written sensitive file to mode 600.
    pub fn chmod_600(path: &Path) -> Result<()> {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
}

/// Expand `~`-relative config-provided paths (used for blacklist additions).
pub fn expand_paths(paths: &[String]) -> Result<Vec<PathBuf>> {
    paths.iter().map(|p| expand_tilde(p)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_byte_sizes() {
        assert_eq!(parse_bytes("5MB"), Some(5 * 1024 * 1024));
        assert_eq!(parse_bytes("20 MB"), Some(20 * 1024 * 1024));
        assert_eq!(parse_bytes("1GB"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_bytes("512"), Some(512));
        // A hostile config that would overflow u64 floors to None (checked_mul),
        // so config load bails rather than panicking (debug) or wrapping (release).
        assert_eq!(parse_bytes("99999999999999GB"), None);
        assert!(ByteSize::try_from("99999999999999GB".to_string()).is_err());
        assert!(toml::from_str::<Config>("[scratch]\nfile_cap = \"99999999999999GB\"\n").is_err());
    }

    #[test]
    fn defaults_match_design() {
        let c = Config::default();
        assert_eq!(c.scratch.file_cap.0, 5 * 1024 * 1024);
        assert_eq!(c.scratch.total_cap.0, 20 * 1024 * 1024);
        assert!(c.scratch.allow.contains(&"*.md".to_string()));
    }

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("7d"), Some(Duration::from_secs(7 * 86_400)));
        assert_eq!(parse_duration("3d"), Some(Duration::from_secs(3 * 86_400)));
        assert_eq!(parse_duration("1h"), Some(Duration::from_secs(3_600)));
        assert_eq!(
            parse_duration("90d"),
            Some(Duration::from_secs(90 * 86_400))
        );
        assert_eq!(parse_duration("1w"), Some(Duration::from_secs(604_800)));
        assert_eq!(parse_duration("512"), Some(Duration::from_secs(512)));
        assert_eq!(parse_duration(""), None);
        // Overflow floors to None rather than panicking/wrapping (N5).
        assert_eq!(parse_duration("100000000000000000000w"), None);
    }

    #[test]
    fn malformed_duration_setting_is_a_hard_error() {
        // A destructive tool must refuse an unparseable policy, not floor to 0 (R2).
        assert!(DurationSetting::try_from(String::new()).is_err());
        assert!(DurationSetting::try_from("7dd".to_string()).is_err());
        assert!(DurationSetting::try_from("later".to_string()).is_err());
        assert_eq!(
            DurationSetting::try_from("7d".to_string()).unwrap().0,
            Duration::from_secs(7 * 86_400)
        );
    }

    #[test]
    fn duration_setting_serializes_human_readable_and_round_trips() {
        let cases = [
            (604_800u64, "1w"),
            (7 * 86_400, "1w"),
            (90 * 86_400, "90d"),
            (3 * 86_400, "3d"),
            (3_600, "1h"),
            (14 * 86_400, "2w"),
            (0, "0s"),
            (512, "512s"),
        ];
        for (secs, want) in cases {
            let emitted = String::from(DurationSetting(Duration::from_secs(secs)));
            assert_eq!(emitted, want, "for {secs}s");
            assert_eq!(
                DurationSetting::try_from(emitted).unwrap().0,
                Duration::from_secs(secs),
                "round-trip {secs}s",
            );
        }
    }

    #[test]
    fn malformed_gc_duration_refuses_config_load() {
        let err = toml::from_str::<Config>("[gc]\nmin_age = \"7dd\"\n").unwrap_err();
        assert!(
            err.to_string().contains("invalid duration"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn gc_defaults_match_design() {
        let g = GcConfig::default();
        assert_eq!(g.min_age.0, Duration::from_secs(7 * 86_400));
        assert_eq!(g.transcript_retain.0, Duration::from_secs(90 * 86_400));
        assert_eq!(g.scratch_retain.0, Duration::from_secs(3 * 86_400));
        assert!(!g.require_indexed);
        assert!(!g.history_compact);
    }

    #[test]
    fn absent_gc_block_yields_defaults() {
        let c: Config = toml::from_str("blacklist_add = []").unwrap();
        assert_eq!(c.gc.min_age.0, Duration::from_secs(7 * 86_400));
    }
}
