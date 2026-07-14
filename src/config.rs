use crate::util::{expand_tilde, home_dir};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Parsed `config.toml`, with design-default values when absent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub blacklist_add: Vec<String>,
    pub scratch: ScratchConfig,
    pub scan: ScanConfig,
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

/// A human byte size like "5MB", stored as bytes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub struct ByteSize(pub u64);

impl From<String> for ByteSize {
    fn from(s: String) -> Self {
        ByteSize(parse_bytes(&s).unwrap_or(0))
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
    num.trim().parse::<u64>().ok().map(|v| v * mult)
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
    pub fn is_initialized(&self) -> bool {
        self.marker_path().exists() || self.catalog_path().exists()
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
    pub fn ensure_layout(&self, fix_perms: bool) -> Result<()> {
        // Tighten umask so nested creates never widen beyond owner.
        // SAFETY: process-global, set once at start of a write command.
        unsafe { libc::umask(0o077) };

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

        for dir in [self.archive_dir(), self.quarantine_dir(), self.state_dir()] {
            std::fs::create_dir_all(&dir)?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }

        let marker = self.marker_path();
        if !marker.exists() {
            std::fs::write(&marker, b"yomi store\n")?;
            Self::chmod_600(&marker)?;
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
    }

    #[test]
    fn defaults_match_design() {
        let c = Config::default();
        assert_eq!(c.scratch.file_cap.0, 5 * 1024 * 1024);
        assert_eq!(c.scratch.total_cap.0, 20 * 1024 * 1024);
        assert!(c.scratch.allow.contains(&"*.md".to_string()));
    }
}
