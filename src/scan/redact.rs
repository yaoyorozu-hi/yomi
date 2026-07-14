use crate::model::{Finding, FindingAction, Severity};
use crate::scan::rules::scan_text;
use crate::util::sha8;
use regex::Regex;

/// Outcome of scanning one artifact's content.
pub struct ScanOutcome {
    /// Whether the content was UTF-8 and therefore scannable.
    pub scanned: bool,
    /// Content with HIGH/MED spans replaced by placeholders (unchanged if none).
    pub redacted: Vec<u8>,
    /// Whether any span was redacted (content differs from source).
    pub was_redacted: bool,
    /// Whether any HIGH finding fired (original must be quarantined).
    pub needs_quarantine: bool,
    pub findings: Vec<Finding>,
    pub flagged: u32,
    pub redacted_count: u32,
}

/// Compiled allowlist: literal secret-sha8 tags and regexes of known-benign
/// secrets. A match on either suppresses a finding.
pub struct Allowlist {
    sha8: Vec<String>,
    regexes: Vec<Regex>,
}

impl Allowlist {
    pub fn compile(entries: &[String]) -> Self {
        let mut sha8 = Vec::new();
        let mut regexes = Vec::new();
        for e in entries {
            // An 8-hex-char entry is treated as a secret-sha8 tag; otherwise a regex.
            if e.len() == 8 && e.chars().all(|c| c.is_ascii_hexdigit()) {
                sha8.push(e.to_ascii_lowercase());
            } else if let Ok(re) = Regex::new(e) {
                regexes.push(re);
            }
        }
        Allowlist { sha8, regexes }
    }

    pub(crate) fn allows(&self, secret: &str, tag: &str) -> bool {
        self.sha8.iter().any(|s| s == tag) || self.regexes.iter().any(|r| r.is_match(secret))
    }
}

/// Opening token of a redaction placeholder (`‹REDACTED:`). Public so the
/// content scanner can detect a source that pre-injects a spoofed placeholder.
pub const PLACEHOLDER_OPEN: &str = "\u{2039}REDACTED:"; // ‹
const PLACEHOLDER_CLOSE: &str = "\u{203a}"; // ›

fn placeholder(kind: &str, tag: &str) -> String {
    format!("{PLACEHOLDER_OPEN}{kind}:{tag}{PLACEHOLDER_CLOSE}")
}

/// Scan `content` and apply the design's action model:
/// HIGH → redact + quarantine, MED → redact, LOW → flag, allowlist → suppress.
pub fn scan_and_redact(content: &[u8], allow: &Allowlist) -> ScanOutcome {
    let Ok(text) = std::str::from_utf8(content) else {
        return ScanOutcome {
            scanned: false,
            redacted: content.to_vec(),
            was_redacted: false,
            needs_quarantine: false,
            findings: Vec::new(),
            flagged: 0,
            redacted_count: 0,
        };
    };

    let raw = scan_text(text);

    let mut findings = Vec::new();
    let mut needs_quarantine = false;
    let mut flagged = 0u32;
    let mut redacted_count = 0u32;
    // Accepted, non-overlapping redaction spans, in source order.
    let mut redactions: Vec<(usize, usize, String, String)> = Vec::new();
    let mut cursor = 0usize; // no accepted redaction may start before this

    for m in &raw {
        let tag = sha8(m.secret.as_bytes());
        if allow.allows(m.secret, &tag) {
            findings.push(Finding {
                kind: m.kind.to_string(),
                severity: m.severity,
                secret_sha8: tag,
                action: FindingAction::Allowed,
                span_start: m.start,
                span_len: m.end - m.start,
            });
            continue;
        }

        let action = match m.severity {
            Severity::High => FindingAction::Quarantine,
            Severity::Med => FindingAction::Redact,
            Severity::Low => FindingAction::Flag,
        };

        match action {
            FindingAction::Quarantine | FindingAction::Redact => {
                // Redacting mutators must not overlap an already-accepted span.
                if m.start < cursor {
                    continue;
                }
                if action == FindingAction::Quarantine {
                    needs_quarantine = true;
                }
                redacted_count += 1;
                redactions.push((m.start, m.end, m.kind.to_string(), tag.clone()));
                cursor = m.end;
            }
            FindingAction::Flag => {
                flagged += 1;
            }
            FindingAction::Allowed => unreachable!(),
        }

        findings.push(Finding {
            kind: m.kind.to_string(),
            severity: m.severity,
            secret_sha8: tag,
            action,
            span_start: m.start,
            span_len: m.end - m.start,
        });
    }

    let was_redacted = !redactions.is_empty();
    let redacted = if was_redacted {
        let mut out = String::with_capacity(text.len());
        let mut last = 0usize;
        for (start, end, kind, tag) in &redactions {
            out.push_str(&text[last..*start]);
            out.push_str(&placeholder(kind, tag));
            last = *end;
        }
        out.push_str(&text[last..]);
        out.into_bytes()
    } else {
        content.to_vec()
    };

    ScanOutcome {
        scanned: true,
        redacted,
        was_redacted,
        needs_quarantine,
        findings,
        flagged,
        redacted_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_redacts_and_quarantines() {
        let content = b"key AKIAIOSFODNN7EXAMPLE tail";
        let out = scan_and_redact(content, &Allowlist::compile(&[]));
        assert!(out.was_redacted);
        assert!(out.needs_quarantine);
        let s = String::from_utf8(out.redacted).unwrap();
        assert!(!s.contains("AKIAIOSFODNN7EXAMPLE"), "secret leaked: {s}");
        assert!(s.contains("\u{2039}REDACTED:aws-key:"));
    }

    #[test]
    fn med_redacts_without_quarantine() {
        let content =
            b"tok eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w end";
        let out = scan_and_redact(content, &Allowlist::compile(&[]));
        assert!(out.was_redacted);
        assert!(!out.needs_quarantine);
    }

    #[test]
    fn low_flags_only() {
        let content = b"Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345";
        let out = scan_and_redact(content, &Allowlist::compile(&[]));
        assert!(!out.was_redacted);
        assert_eq!(out.flagged, 1);
        assert_eq!(out.redacted, content.to_vec());
    }

    #[test]
    fn allowlist_suppresses_by_regex() {
        let content = b"key AKIAIOSFODNN7EXAMPLE tail";
        let allow = Allowlist::compile(&["AKIAIOSFODNN7EXAMPLE".to_string()]);
        let out = scan_and_redact(content, &allow);
        assert!(!out.was_redacted);
        assert!(!out.needs_quarantine);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].action, FindingAction::Allowed);
    }

    #[test]
    fn allowlist_suppresses_by_sha8() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let tag = sha8(secret.as_bytes());
        let allow = Allowlist::compile(&[tag]);
        let content = format!("key {secret} tail").into_bytes();
        let out = scan_and_redact(&content, &allow);
        assert!(!out.was_redacted);
    }
}
