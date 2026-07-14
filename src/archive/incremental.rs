use crate::util::sha256_hex;

/// Prior capture state for an appendable artifact, from the catalog.
#[derive(Debug, Clone)]
pub struct Prior {
    /// sha256 of the committed source prefix `[0..last_src_offset]`.
    pub source_sha256: String,
    pub last_src_offset: u64,
    /// Byte length of the stored `.zst` after the last committed capture. Used
    /// to detect a crash-interrupted append (store grew, catalog did not).
    pub stored_bytes: u64,
}

/// What to do on (re-)archiving an appendable source.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// No new complete lines since last capture.
    Skip,
    /// First capture, or the source prefix diverged (rotation/rewrite);
    /// capture the whole newline-aligned content as a fresh version.
    Full { end: u64 },
    /// Append the tail `[from..end]` as a new zstd frame.
    Tail { from: u64, end: u64 },
}

/// Byte offset just past the last `\n`, i.e. the end of the last complete line.
/// A trailing partial line (mid-write) is deferred to the next capture.
pub fn last_line_end(bytes: &[u8]) -> u64 {
    match bytes.iter().rposition(|&b| b == b'\n') {
        Some(i) => (i + 1) as u64,
        None => 0,
    }
}

/// Decide the capture plan for an appendable source given its prior state.
pub fn plan(prior: Option<&Prior>, current: &[u8]) -> Plan {
    let end = last_line_end(current);
    let Some(prior) = prior else {
        return Plan::Full { end };
    };

    let off = prior.last_src_offset as usize;
    // Prefix must still be present and hash-identical, or the file was rotated.
    if off > current.len() {
        return Plan::Full { end };
    }
    let prefix_sha = sha256_hex(&current[..off]);
    if prefix_sha != prior.source_sha256 {
        return Plan::Full { end };
    }
    if end <= prior.last_src_offset {
        Plan::Skip
    } else {
        Plan::Tail {
            from: prior.last_src_offset,
            end,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_capture_is_full_to_last_line() {
        let cur = b"a\nb\npartial";
        assert_eq!(plan(None, cur), Plan::Full { end: 4 });
    }

    #[test]
    fn unchanged_prefix_no_new_line_skips() {
        let cur = b"a\nb\n";
        let prior = Prior {
            source_sha256: sha256_hex(b"a\nb\n"),
            last_src_offset: 4,
            stored_bytes: 0,
        };
        assert_eq!(plan(Some(&prior), cur), Plan::Skip);
    }

    #[test]
    fn growth_yields_tail() {
        let cur = b"a\nb\nc\n";
        let prior = Prior {
            source_sha256: sha256_hex(b"a\nb\n"),
            last_src_offset: 4,
            stored_bytes: 0,
        };
        assert_eq!(plan(Some(&prior), cur), Plan::Tail { from: 4, end: 6 });
    }

    #[test]
    fn diverged_prefix_recaptures_full() {
        let cur = b"X\nb\nc\n";
        let prior = Prior {
            source_sha256: sha256_hex(b"a\nb\n"),
            last_src_offset: 4,
            stored_bytes: 0,
        };
        assert_eq!(plan(Some(&prior), cur), Plan::Full { end: 6 });
    }

    #[test]
    fn trailing_partial_line_deferred() {
        let cur = b"a\nb\nc"; // "c" not yet terminated
        let prior = Prior {
            source_sha256: sha256_hex(b"a\nb\n"),
            last_src_offset: 4,
            stored_bytes: 0,
        };
        assert_eq!(plan(Some(&prior), cur), Plan::Skip);
    }
}
