use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Current UTC time as an ISO-8601 / RFC-3339 string.
pub fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Lowercase hex sha256 of a byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex(&h.finalize())
}

/// First 8 hex chars of sha256 — an audit tag for a secret, never the secret.
pub fn sha8(bytes: &[u8]) -> String {
    sha256_hex(bytes)[..8].to_string()
}

/// Stream a reader through sha256 without holding the whole content in memory,
/// so the GC live-source re-hash bounds its footprint regardless of file size.
pub fn sha256_stream<R: std::io::Read>(reader: &mut R) -> std::io::Result<String> {
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Resolve the user's home directory from `$HOME`.
pub fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("$HOME is not set")
}

/// Expand a leading `~` against `$HOME`.
pub fn expand_tilde(path: &str) -> Result<PathBuf> {
    if let Some(rest) = path.strip_prefix("~/") {
        Ok(home_dir()?.join(rest))
    } else if path == "~" {
        home_dir()
    } else {
        Ok(PathBuf::from(path))
    }
}

/// Canonicalize if the path exists, else lexically normalize against cwd.
/// Used so blacklist matching is stable whether or not a path is present.
pub fn abs_normalize(path: &Path) -> PathBuf {
    if let Ok(c) = path.canonicalize() {
        return c;
    }
    let base = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().unwrap_or_default()
    };
    let mut out = base;
    for comp in path.components() {
        use std::path::Component;
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::RootDir => {
                out = PathBuf::from("/");
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}
