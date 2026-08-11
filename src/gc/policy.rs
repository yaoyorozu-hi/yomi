//! Retain-window and age arithmetic. Pure functions over config + metadata.

use crate::config::GcConfig;
use crate::gc::{ScratchMode, Target};
use std::time::{Duration, SystemTime};

/// Retain window for a target family. `EmptyDirs` carries no data, so it holds
/// only to the hard `min_age` floor.
///
/// `--full` and `--wipe` drop every family's window to zero: both verbs are stated
/// over what has been captured, not over how long ago it was written. What still
/// keeps a working tree out of their reach is the floor below — which is never
/// zero.
pub fn retain_for(cfg: &GcConfig, target: Target, mode: ScratchMode) -> Duration {
    match mode {
        ScratchMode::Full | ScratchMode::Wipe => Duration::ZERO,
        ScratchMode::Aged => match target {
            Target::Transcripts => cfg.transcript_retain.0,
            Target::Scratch => cfg.scratch_retain.0,
            Target::Mcp => cfg.mcp_log_retain.0,
            Target::Paste => cfg.paste_retain.0,
            Target::Snapshots => cfg.snapshot_retain.0,
            Target::EmptyDirs => cfg.min_age.0,
        },
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

/// The effective floor: `max(base floor, override)`, where the base floor is
/// `cfg.min_age` under the aged policy and [`relaxed_min_age_floor`] under
/// `--full`/`--wipe`. The override may only **raise** whichever floor is in
/// force, never lower it — a hard design law, and it holds under the relaxed
/// floor exactly as it does under `min_age`.
pub fn effective_min_age(
    cfg: &GcConfig,
    override_: Option<Duration>,
    mode: ScratchMode,
) -> Duration {
    let floor = match mode {
        ScratchMode::Aged => cfg.min_age.0,
        ScratchMode::Full | ScratchMode::Wipe => relaxed_min_age_floor(cfg),
    };
    match override_ {
        Some(o) => o.max(floor),
        None => floor,
    }
}

/// The floor `--full`/`--wipe` lower to — **never zero**. Equals
/// `cfg.active_window` (default 1h).
///
/// Zero would leave the tree of the session running this very command guarded by
/// the uuid liveness set alone, and that set has three silent paths to empty: no
/// `~/.claude/sessions/<pid>.json`, one that will not parse, and one whose
/// `sessionId` does not match the directory name. The lock leg that was meant to
/// back it up is already dead on this host — `locks/` holds `2.1.226.lock`, a
/// version name and not a uuid (issue #37) — so an mtime floor that depends on no
/// oracle at all is the only guard left standing.
///
/// It is also precisely what makes `--full` safe to run from inside a Claude Code
/// session: that session's own tree is being written continuously, so its newest
/// mtime is seconds old and the floor holds it back without consulting anything.
pub fn relaxed_min_age_floor(cfg: &GcConfig) -> Duration {
    cfg.active_window.0
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
            effective_min_age(&cfg, Some(Duration::from_secs(86_400)), ScratchMode::Aged),
            Duration::from_secs(7 * 86_400)
        );
        // A 30d override raises it.
        assert_eq!(
            effective_min_age(
                &cfg,
                Some(Duration::from_secs(30 * 86_400)),
                ScratchMode::Aged
            ),
            Duration::from_secs(30 * 86_400)
        );
    }

    /// `--full` relaxes the floor to `active_window` and **not below it**, and the
    /// override law is unchanged there: it raises, never lowers.
    #[test]
    fn full_lowers_the_floor_to_active_window_and_no_further() {
        let cfg = GcConfig {
            min_age: DurationSetting(Duration::from_secs(7 * 86_400)),
            active_window: DurationSetting(Duration::from_secs(3_600)),
            ..GcConfig::default()
        };
        assert_eq!(relaxed_min_age_floor(&cfg), Duration::from_secs(3_600));
        assert_eq!(
            effective_min_age(&cfg, None, ScratchMode::Full),
            Duration::from_secs(3_600)
        );
        // A 1-minute override cannot take the floor under the active window.
        assert_eq!(
            effective_min_age(&cfg, Some(Duration::from_secs(60)), ScratchMode::Full),
            Duration::from_secs(3_600)
        );
        // Zero — the value an operator would reach for to mean "no floor" — is
        // likewise refused.
        assert_eq!(
            effective_min_age(&cfg, Some(Duration::ZERO), ScratchMode::Full),
            Duration::from_secs(3_600)
        );
        // Raising still works.
        assert_eq!(
            effective_min_age(
                &cfg,
                Some(Duration::from_secs(3 * 86_400)),
                ScratchMode::Full
            ),
            Duration::from_secs(3 * 86_400)
        );
        // The aged policy is untouched by any of this.
        assert_eq!(
            effective_min_age(&cfg, None, ScratchMode::Aged),
            Duration::from_secs(7 * 86_400)
        );
    }

    /// `--full` zeroes every family's retain window; the aged policy keeps them.
    #[test]
    fn full_zeroes_every_retain_window() {
        let cfg = GcConfig::default();
        for target in Target::all() {
            assert_eq!(
                retain_for(&cfg, target, ScratchMode::Full),
                Duration::ZERO,
                "{} kept a retain window under --full",
                target.as_str()
            );
            assert_eq!(
                retain_for(&cfg, target, ScratchMode::Wipe),
                Duration::ZERO,
                "{} kept a retain window under --wipe",
                target.as_str()
            );
        }
        assert_eq!(
            retain_for(&cfg, Target::Scratch, ScratchMode::Aged),
            Duration::from_secs(3 * 86_400)
        );
        assert_eq!(
            retain_for(&cfg, Target::Transcripts, ScratchMode::Aged),
            Duration::from_secs(90 * 86_400)
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
