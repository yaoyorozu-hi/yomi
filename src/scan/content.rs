use crate::model::{Finding, FindingAction, Severity};
use crate::scan::redact::{Allowlist, PLACEHOLDER_OPEN, scan_and_redact};
use crate::scan::rules::scan_text;
use crate::util::{sha8, sha256_hex};
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;
use unicode_properties::{GeneralCategory, UnicodeGeneralCategory};

/// Sliding-window width (bytes) for interleaved-NUL (UTF-16 island) detection.
/// Sized to contain the UTF-16 encoding of any single detector's secret.
const NUL_WINDOW: usize = 48;

/// Outcome of scanning one logical artifact's content.
///
/// Invariant (**scannable-or-quarantine**): an artifact reaches the browsable,
/// searchable store *only* if it is fully scannable in a *canonical readable
/// form* — NFKC-folded with zero-width/format/combining characters stripped.
/// Anything that cannot — non-UTF-8, an ambiguous encoding (e.g. BOM-less or
/// island UTF-16), a malformed JSONL line, or a secret hidden behind escaping or
/// invisible-separator token-splitting — has its **whole** artifact quarantined:
/// the raw bytes go to quarantine and only an opaque marker is stored. yomi is a
/// secret-aggregation point, so "only what we could fully read is searchable" is
/// the safe default; exotic/binary content becoming quarantine-not-searchable is
/// the accepted trade-off.
pub struct ContentScan {
    /// False when the artifact was quarantined whole (not fully scannable).
    pub scanned: bool,
    /// Stored content: redacted text, or an opaque marker for a quarantined artifact.
    pub redacted: Vec<u8>,
    pub was_redacted: bool,
    /// The raw original must be quarantined (a HIGH finding, or unscannable).
    pub needs_quarantine: bool,
    pub findings: Vec<Finding>,
    pub flagged: u32,
    pub redacted_count: u32,
}

const MARKER_OPEN: &str = "\u{2039}QUARANTINED:"; // ‹
const MARKER_CLOSE: &str = "\u{203a}"; // ›

/// Defanged rewrites of a source-forged audit token: the opening guillemet is
/// swapped for an ASCII `<` so the stored/indexed text no longer contains a
/// string that a reader or tool would mistake for a genuine redaction tag.
const DEFANGED_PLACEHOLDER: &str = "<REDACTED:";
const DEFANGED_MARKER: &str = "<QUARANTINED:";

/// Result of normalizing raw bytes toward a scannable UTF-8 string.
enum Norm {
    Text(String),
    /// Not fully scannable; the artifact is quarantined whole with this reason.
    Unscannable(&'static str),
}

/// Quarantine the whole artifact: store a marker, send the raw bytes to
/// quarantine, and record the reason as a HIGH finding.
fn quarantine_whole(bytes: &[u8], reason: &'static str) -> ContentScan {
    let tag = sha8(bytes);
    let marker = format!("{MARKER_OPEN}{reason}:{tag}{MARKER_CLOSE}\n").into_bytes();
    ContentScan {
        scanned: false,
        redacted: marker,
        was_redacted: true,
        needs_quarantine: true,
        findings: vec![Finding {
            kind: reason.to_string(),
            severity: Severity::High,
            secret_sha8: tag,
            action: FindingAction::Quarantine,
            span_start: 0,
            span_len: bytes.len(),
        }],
        flagged: 0,
        redacted_count: 1,
    }
}

/// Scan artifact content under the scannable-or-quarantine invariant.
pub fn scan_content(bytes: &[u8], is_jsonl: bool, allow: &Allowlist) -> ContentScan {
    let mut text = match normalize_utf8(bytes) {
        Norm::Text(t) => t,
        Norm::Unscannable(reason) => return quarantine_whole(bytes, reason),
    };

    // A source that pre-injects our own token is trying to forge an audit tag.
    // Flag it AND defang it: the opening guillemet is rewritten to ASCII `<` so
    // the stored/indexed text carries no counterfeit `‹REDACTED:…›` /
    // `‹QUARANTINED:…›` that would spoof a real redaction. Genuine placeholders
    // are inserted downstream by the redactor and are never touched.
    let mut findings = Vec::new();
    let mut flagged = 0u32;
    let mut forged_tag = false;
    if text.contains(PLACEHOLDER_OPEN) || text.contains(MARKER_OPEN) {
        flagged += 1;
        forged_tag = true;
        text = text
            .replace(PLACEHOLDER_OPEN, DEFANGED_PLACEHOLDER)
            .replace(MARKER_OPEN, DEFANGED_MARKER);
        findings.push(Finding {
            kind: "preinjected-placeholder".to_string(),
            severity: Severity::Low,
            secret_sha8: "00000000".to_string(),
            action: FindingAction::Flag,
            span_start: 0,
            span_len: 0,
        });
    }

    // Structural gate + escape-hidden-secret detection. If either fails, the
    // whole artifact is quarantined rather than stored searchable.
    if is_jsonl {
        let mut candidates: Vec<String> = Vec::new();
        for line in text.split_inclusive('\n') {
            let line = line.strip_suffix('\n').unwrap_or(line);
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(line) {
                Ok(v) => collect_json_strings(&v, &mut candidates),
                Err(_) => return quarantine_whole(bytes, "malformed-jsonl"),
            }
        }
        if has_hidden_secret(&text, candidates.iter().map(String::as_str), allow) {
            return quarantine_whole(bytes, "escape-hidden-secret");
        }
    } else if has_hidden_secret(&text, std::iter::once(text.as_str()), allow) {
        return quarantine_whole(bytes, "escape-hidden-secret");
    }

    // Visible secrets are redacted in place; the content stays searchable.
    let lex = scan_and_redact(text.as_bytes(), allow);
    let mut needs_quarantine = lex.needs_quarantine;
    let mut redacted_count = 0u32;
    for f in &lex.findings {
        match f.action {
            FindingAction::Flag => flagged += 1,
            FindingAction::Quarantine => {
                needs_quarantine = true;
                redacted_count += 1;
            }
            FindingAction::Redact => redacted_count += 1,
            FindingAction::Allowed => {}
        }
    }
    findings.extend(lex.findings);

    let was_redacted = forged_tag || lex.redacted != text.as_bytes();
    ContentScan {
        scanned: true,
        redacted: lex.redacted,
        was_redacted,
        needs_quarantine,
        findings,
        flagged,
        redacted_count,
    }
}

/// Convenience: sha256 of the content a scan would store.
pub fn content_sha(scan: &ContentScan) -> String {
    sha256_hex(&scan.redacted)
}

/// Normalize raw bytes to a scannable UTF-8 string, or classify why not.
///
/// BOMs are honored (UTF-8, UTF-16 LE/BE). BOM-less bytes that are valid UTF-8
/// but NUL-dense are treated as BOM-less UTF-16 (an ASCII secret encoded as
/// `A\0K\0I\0A\0…` passes strict UTF-8 yet hides from a byte-regex) and are
/// quarantined rather than mis-scanned.
fn normalize_utf8(bytes: &[u8]) -> Norm {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return match std::str::from_utf8(rest) {
            Ok(s) => Norm::Text(s.to_string()),
            Err(_) => Norm::Unscannable("non-utf8"),
        };
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return decode_utf16(rest, true);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return decode_utf16(rest, false);
    }
    match std::str::from_utf8(bytes) {
        Ok(s) => {
            if has_nul_island(bytes) {
                Norm::Unscannable("utf16-ambiguous")
            } else {
                Norm::Text(s.to_string())
            }
        }
        Err(_) => Norm::Unscannable("non-utf8"),
    }
}

/// True if any `NUL_WINDOW`-byte window is ≥25% NUL — a windowed check so a
/// small interleaved-NUL (UTF-16) secret island buried in a large ASCII body is
/// caught (a global ratio would be diluted to near zero). A lone stray NUL does
/// not trip it.
fn has_nul_island(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if bytes.len() < NUL_WINDOW {
        let nul = bytes.iter().filter(|&&b| b == 0).count();
        return nul > 0 && nul * 4 >= bytes.len();
    }
    let mut nul_in_window = 0usize;
    for i in 0..bytes.len() {
        if bytes[i] == 0 {
            nul_in_window += 1;
        }
        if i >= NUL_WINDOW && bytes[i - NUL_WINDOW] == 0 {
            nul_in_window -= 1;
        }
        if i + 1 >= NUL_WINDOW && nul_in_window * 4 >= NUL_WINDOW {
            return true;
        }
    }
    false
}

fn decode_utf16(rest: &[u8], little_endian: bool) -> Norm {
    if !rest.len().is_multiple_of(2) {
        return Norm::Unscannable("utf16-decode-failed");
    }
    let units: Vec<u16> = rest
        .chunks_exact(2)
        .map(|c| {
            if little_endian {
                u16::from_le_bytes([c[0], c[1]])
            } else {
                u16::from_be_bytes([c[0], c[1]])
            }
        })
        .collect();
    match String::from_utf16(&units) {
        Ok(s) => Norm::Text(s),
        Err(_) => Norm::Unscannable("utf16-decode-failed"),
    }
}

fn collect_json_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => {
            for x in a {
                collect_json_strings(x, out);
            }
        }
        Value::Object(o) => {
            for (k, x) in o {
                out.push(k.clone());
                collect_json_strings(x, out);
            }
        }
        _ => {}
    }
}

/// True if normalizing any candidate string reveals a HIGH/MED secret that is
/// **not** present literally in `raw_text` — i.e. it was hidden by escaping
/// (`\uXXXX`) or by invisible-separator token-splitting (zero-width/format/
/// combining chars, fullwidth forms) that a byte-regex over the raw text cannot
/// see. Such a normalization gap is quarantined whole (never redacted): in the
/// raw bytes the secret is entangled with invisible characters, so an in-place
/// redaction span would be ambiguous. A *visible* secret (present in raw_text)
/// is left for the lexical redactor and does not trip this.
fn has_hidden_secret<'a>(
    raw_text: &str,
    candidates: impl Iterator<Item = &'a str>,
    allow: &Allowlist,
) -> bool {
    for s in candidates {
        let deep = unescape_deep(s);
        let canon = canonical_scan_form(&deep);
        for form in [deep.as_str(), canon.as_str()] {
            for m in scan_text(form) {
                if matches!(m.severity, Severity::High | Severity::Med) {
                    let tag = sha8(m.secret.as_bytes());
                    if !allow.allows(m.secret, &tag) && !raw_text.contains(m.secret) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// A detection-only "canonical readable form": NFKC-fold (collapsing fullwidth
/// and compatibility variants), then drop characters a human/renderer treats as
/// invisible or non-spacing — zero-width and format controls, combining marks,
/// and non-ASCII spaces (NBSP et al.). What remains is what a reader actually
/// sees, so a secret split by invisible separators becomes contiguous here.
fn canonical_scan_form(text: &str) -> String {
    // Strip invisibles first (NFKC folds e.g. NBSP → ordinary space, which we
    // keep — so removing them beforehand is what actually closes NBSP-splitting),
    // fold, then strip again for anything the fold introduced.
    let stripped: String = text.chars().filter(|&c| !is_strippable(c)).collect();
    stripped.nfkc().filter(|&c| !is_strippable(c)).collect()
}

fn is_strippable(c: char) -> bool {
    match c.general_category() {
        GeneralCategory::Format
        | GeneralCategory::NonspacingMark
        | GeneralCategory::EnclosingMark
        | GeneralCategory::SpacingMark => true,
        GeneralCategory::SpaceSeparator => c != ' ',
        GeneralCategory::Control => !matches!(c, '\n' | '\t' | '\r'),
        _ => false,
    }
}

fn escape_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})").unwrap())
}

/// Repeatedly decode `\uXXXX` / `\xXX` escapes until stable, so a secret hidden
/// behind one or several layers of escaping is exposed to the scanner.
fn unescape_deep(s: &str) -> String {
    let mut cur = s.to_string();
    for _ in 0..4 {
        let next = escape_re().replace_all(&cur, |caps: &regex::Captures| {
            let code = caps
                .get(1)
                .or_else(|| caps.get(2))
                .map(|m| u32::from_str_radix(m.as_str(), 16).unwrap_or(0))
                .unwrap_or(0);
            char::from_u32(code).map(String::from).unwrap_or_default()
        });
        if next == cur {
            break;
        }
        cur = next.into_owned();
    }
    cur
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow() -> Allowlist {
        Allowlist::compile(&[])
    }

    const AKIA: &str = "AKIAIOSFODNN7EXAMPLE";

    fn is_quarantine_whole(out: &ContentScan) -> bool {
        !out.scanned
            && out.needs_quarantine
            && String::from_utf8_lossy(&out.redacted).contains("QUARANTINED:")
    }

    #[test]
    fn non_utf8_is_quarantined_whole() {
        let mut bytes = vec![0xff, 0xfe, 0x00];
        bytes.extend_from_slice(AKIA.as_bytes());
        let out = scan_content(&bytes, false, &allow());
        assert!(is_quarantine_whole(&out));
        assert!(
            !out.redacted
                .windows(AKIA.len())
                .any(|w| w == AKIA.as_bytes())
        );
    }

    #[test]
    fn bomless_utf16_ascii_secret_is_quarantined() {
        // "AKIA…" as BOM-less UTF-16LE: every char followed by a NUL byte —
        // valid UTF-8, but a byte-regex would never see the key.
        let mut bytes = Vec::new();
        for c in AKIA.bytes() {
            bytes.push(c);
            bytes.push(0);
        }
        let out = scan_content(&bytes, false, &allow());
        assert!(
            is_quarantine_whole(&out),
            "BOM-less UTF-16 secret not quarantined"
        );
    }

    #[test]
    fn utf16le_bom_secret_is_quarantined() {
        let mut bytes = vec![0xFF, 0xFE];
        for c in format!("key {AKIA} end").encode_utf16() {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        let out = scan_content(&bytes, false, &allow());
        // Decoded UTF-16 exposes a visible secret; it must not stay searchable raw.
        assert!(
            !out.redacted
                .windows(AKIA.len())
                .any(|w| w == AKIA.as_bytes()),
            "utf16 secret leaked to store"
        );
        assert!(out.needs_quarantine);
    }

    #[test]
    fn json_value_escaped_secret_is_quarantined_whole() {
        let escaped: String = AKIA
            .chars()
            .map(|c| format!("\\u{:04x}", c as u32))
            .collect();
        let line = format!("{{\"message\":\"key {escaped} end\"}}\n");
        let out = scan_content(line.as_bytes(), true, &allow());
        assert!(
            is_quarantine_whole(&out),
            "value-escaped secret not quarantined"
        );
        assert!(!String::from_utf8_lossy(&out.redacted).contains(AKIA));
    }

    #[test]
    fn json_key_escaped_secret_is_quarantined_whole() {
        let escaped: String = AKIA
            .chars()
            .map(|c| format!("\\u{:04x}", c as u32))
            .collect();
        let line = format!("{{\"{escaped}\":\"value\"}}\n");
        let out = scan_content(line.as_bytes(), true, &allow());
        assert!(
            is_quarantine_whole(&out),
            "key-escaped secret not quarantined"
        );
    }

    #[test]
    fn malformed_jsonl_line_quarantines_whole() {
        let text = "{\"ok\":1}\nthis is not json at all\n{\"ok\":2}\n";
        let out = scan_content(text.as_bytes(), true, &allow());
        assert!(is_quarantine_whole(&out));
    }

    #[test]
    fn plain_role_escaped_secret_is_quarantined() {
        let escaped: String = AKIA
            .chars()
            .map(|c| format!("\\u{:04x}", c as u32))
            .collect();
        let text = format!("log line key={escaped}\n");
        let out = scan_content(text.as_bytes(), false, &allow());
        assert!(
            is_quarantine_whole(&out),
            "plain escaped secret not quarantined"
        );
    }

    #[test]
    fn visible_secret_in_clean_jsonl_is_redacted_not_quarantined() {
        let line = format!("{{\"message\":\"deploy {AKIA} now\"}}\n");
        let out = scan_content(line.as_bytes(), true, &allow());
        assert!(out.scanned, "clean line was quarantined");
        let s = String::from_utf8(out.redacted).unwrap();
        assert!(!s.contains(AKIA));
        assert!(s.contains("REDACTED:aws-key"));
        assert!(out.needs_quarantine); // HIGH → original quarantined too
    }

    #[test]
    fn multiline_pem_visible_in_plain_is_redacted() {
        let text = "prefix\n-----BEGIN RSA PRIVATE KEY-----\nMIIBfakebody\n-----END RSA PRIVATE KEY-----\nsuffix\n";
        let out = scan_content(text.as_bytes(), false, &allow());
        assert!(out.scanned);
        let s = String::from_utf8(out.redacted).unwrap();
        assert!(s.contains("REDACTED:private-key"));
    }

    #[test]
    fn clean_jsonl_is_byte_faithful() {
        let line = "{\"message\":\"hello world\",\"n\":1}\n";
        let out = scan_content(line.as_bytes(), true, &allow());
        assert!(out.scanned);
        assert!(!out.was_redacted);
        assert_eq!(out.redacted, line.as_bytes());
    }

    // ---- S1: invisible-separator token-splitting ----

    fn split_with(sep: &str) -> String {
        // Insert `sep` into the middle of the key so no contiguous run survives.
        format!("{}{sep}{}", &AKIA[..4], &AKIA[4..])
    }

    #[test]
    fn zero_width_space_split_in_json_value_is_quarantined() {
        let line = format!("{{\"message\":\"key {} end\"}}\n", split_with("\u{200b}"));
        let out = scan_content(line.as_bytes(), true, &allow());
        assert!(
            is_quarantine_whole(&out),
            "ZWSP-split value not quarantined"
        );
    }

    #[test]
    fn word_joiner_split_in_json_key_is_quarantined() {
        let line = format!("{{\"{}\":\"v\"}}\n", split_with("\u{2060}"));
        let out = scan_content(line.as_bytes(), true, &allow());
        assert!(
            is_quarantine_whole(&out),
            "word-joiner-split key not quarantined"
        );
    }

    #[test]
    fn nbsp_split_in_plain_is_quarantined() {
        let text = format!("token={}\n", split_with("\u{00a0}"));
        let out = scan_content(text.as_bytes(), false, &allow());
        assert!(
            is_quarantine_whole(&out),
            "NBSP-split plain not quarantined"
        );
    }

    #[test]
    fn combining_mark_split_is_quarantined() {
        // A combining acute accent (U+0301, Mn) inserted mid-key.
        let text = format!("k={}\n", split_with("\u{0301}"));
        let out = scan_content(text.as_bytes(), false, &allow());
        assert!(
            is_quarantine_whole(&out),
            "combining-mark-split not quarantined"
        );
    }

    #[test]
    fn fullwidth_secret_is_quarantined() {
        // NFKC folds fullwidth Latin/digits to ASCII, exposing a key that never
        // appeared as ASCII in the raw text.
        let fullwidth: String = AKIA
            .chars()
            .map(|c| {
                let u = c as u32;
                if c.is_ascii_alphanumeric() {
                    char::from_u32(u - 0x21 + 0xFF01).unwrap()
                } else {
                    c
                }
            })
            .collect();
        let text = format!("key {fullwidth} end\n");
        assert!(!text.contains(AKIA), "fixture already ASCII-visible");
        let out = scan_content(text.as_bytes(), false, &allow());
        assert!(
            is_quarantine_whole(&out),
            "fullwidth secret not quarantined"
        );
    }

    // ---- S2: windowed NUL / UTF-16 island ----

    #[test]
    fn utf16_island_in_large_ascii_body_is_quarantined() {
        // A small UTF-16LE key island buried in a big ASCII body: global NUL
        // ratio ~1%, but the windowed check catches the island.
        let mut bytes = vec![b'x'; 2000];
        let mut island = Vec::new();
        for c in AKIA.bytes() {
            island.push(c);
            island.push(0);
        }
        let at = 1000;
        bytes.splice(at..at, island);
        assert!(
            std::str::from_utf8(&bytes).is_ok(),
            "fixture must be valid utf8"
        );
        let out = scan_content(&bytes, false, &allow());
        assert!(
            is_quarantine_whole(&out),
            "diluted UTF-16 island not quarantined"
        );
    }

    #[test]
    fn lone_nul_does_not_trip_island_detector() {
        let mut bytes = vec![b'a'; 200];
        bytes[100] = 0;
        let out = scan_content(&bytes, false, &allow());
        assert!(out.scanned, "a single stray NUL over-quarantined");
    }

    // ---- Non-regression: clean, legitimately non-ASCII content stays searchable ----

    #[test]
    fn preinjected_placeholder_is_flagged_and_defanged() {
        // A source forging a redaction tag: it must be flagged AND the counterfeit
        // token defanged so the stored text carries no spoofed `‹REDACTED:…›`.
        let line = "{\"message\":\"audit \u{2039}REDACTED:aws-key:deadbeef\u{203a} and \u{2039}QUARANTINED:x:00\u{203a}\"}\n";
        let out = scan_content(line.as_bytes(), true, &allow());
        assert!(
            out.scanned,
            "clean-but-forged content should stay searchable"
        );
        assert_eq!(out.flagged, 1, "forged tag not flagged");
        let s = String::from_utf8(out.redacted).unwrap();
        assert!(
            !s.contains(PLACEHOLDER_OPEN),
            "spoofed redaction tag survived"
        );
        assert!(!s.contains(MARKER_OPEN), "spoofed quarantine tag survived");
        assert!(s.contains("<REDACTED:aws-key"), "defanged form missing");
        assert!(s.contains("<QUARANTINED:x"), "defanged marker missing");
    }

    #[test]
    fn clean_japanese_and_emoji_stay_searchable() {
        // Japanese text and a ZWJ emoji sequence — canonicalization touches them
        // (strips ZWJ) but reveals no secret, so the artifact stays searchable.
        let line = "{\"message\":\"日本語のテキスト、絵文字 👨\u{200d}👩\u{200d}👧 と記号 ①②③\"}\n";
        let out = scan_content(line.as_bytes(), true, &allow());
        assert!(out.scanned, "clean CJK/emoji content was quarantined");
        assert!(!out.was_redacted);
        assert_eq!(
            out.redacted,
            line.as_bytes(),
            "clean content not byte-faithful"
        );
    }
}
