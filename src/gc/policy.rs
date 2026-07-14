//! Retain-window and age arithmetic. Pure functions over config + metadata.

use crate::config::GcConfig;
use crate::gc::Target;
use std::time::{Duration, SystemTime};

/// Retain window for a target family. `EmptyDirs` carries no data, so it holds
/// only to the hard `min_age` floor.
pub fn retain_for(cfg: &GcConfig, target: Target) -> Duration {
    match target {
        Target::Transcripts => cfg.transcript_retain.0,
        Target::Scratch => cfg.scratch_retain.0,
        Target::Mcp => cfg.mcp_log_retain.0,
        Target::Paste => cfg.paste_retain.0,
        Target::Snapshots => cfg.snapshot_retain.0,
        Target::EmptyDirs => cfg.min_age.0,
    }
}

/// Live-source age from mtime. GC keeps no stored age column by design.
pub fn age_of(md: &std::fs::Metadata) -> Duration {
    match md.modified() {
        Ok(t) => SystemTime::now()
            .duration_since(t)
            .unwrap_or(Duration::ZERO),
        Err(_) => Duration::ZERO,
    }
}

/// The effective floor: `max(cfg.min_age, override)`. The override may only
/// **raise** the floor, never lower it — a hard design law.
pub fn effective_min_age(cfg: &GcConfig, override_: Option<Duration>) -> Duration {
    match override_ {
        Some(o) => o.max(cfg.min_age.0),
        None => cfg.min_age.0,
    }
}

/// A candidate is old enough only if it clears BOTH the hard floor AND its
/// family's retain window.
pub fn age_ok(age: Duration, min_age: Duration, retain: Duration) -> bool {
    age >= min_age.max(retain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DurationSetting;

    #[test]
    fn override_only_raises_the_floor() {
        let cfg = GcConfig {
            min_age: DurationSetting(Duration::from_secs(7 * 86_400)),
            ..GcConfig::default()
        };
        // A 1d override cannot lower the 7d floor.
        assert_eq!(
            effective_min_age(&cfg, Some(Duration::from_secs(86_400))),
            Duration::from_secs(7 * 86_400)
        );
        // A 30d override raises it.
        assert_eq!(
            effective_min_age(&cfg, Some(Duration::from_secs(30 * 86_400))),
            Duration::from_secs(30 * 86_400)
        );
    }

    #[test]
    fn age_ok_needs_both_floor_and_retain() {
        let min = Duration::from_secs(7 * 86_400);
        let retain = Duration::from_secs(3 * 86_400);
        assert!(!age_ok(Duration::from_secs(5 * 86_400), min, retain));
        assert!(age_ok(Duration::from_secs(8 * 86_400), min, retain));
        // Retain higher than floor governs.
        assert!(!age_ok(
            Duration::from_secs(50 * 86_400),
            min,
            Duration::from_secs(90 * 86_400)
        ));
    }
}
