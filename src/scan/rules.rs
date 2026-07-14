use crate::model::Severity;
use regex::Regex;
use std::sync::OnceLock;

/// A compiled secret detector.
pub struct Rule {
    pub kind: &'static str,
    pub severity: Severity,
    pub re: Regex,
}

/// A raw match against artifact content: the detector, the byte span, and the
/// matched secret text.
pub struct RawMatch<'a> {
    pub kind: &'static str,
    pub severity: Severity,
    pub start: usize,
    pub end: usize,
    pub secret: &'a str,
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let mut v = Vec::new();
        let mut add = |kind: &'static str, sev: Severity, pat: &str| {
            v.push(Rule {
                kind,
                severity: sev,
                re: Regex::new(pat).expect("static detector regex compiles"),
            });
        };
        add("aws-key", Severity::High, r"A(?:KIA|SIA)[0-9A-Z]{16}");
        add(
            "private-key",
            Severity::High,
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
        );
        add("github-token", Severity::High, r"gh[pousr]_[A-Za-z0-9]{36}");
        add(
            "github-pat",
            Severity::High,
            r"github_pat_[A-Za-z0-9_]{22,}",
        );
        add(
            "slack-token",
            Severity::High,
            r"xox[baprs]-[A-Za-z0-9-]{10,}",
        );
        add("anthropic-key", Severity::High, r"sk-ant-[A-Za-z0-9-]{20,}");
        // OpenAI keys. The modern segmented forms (`sk-proj-`, `sk-svcacct-`,
        // `sk-admin-`, `sk-cred-`, restricted `rk-`) carry `-`/`_` in the key
        // body, which the old `sk-[A-Za-z0-9]{20,}` class terminated at — so a
        // `sk-proj-…` key slipped through undetected. A `[A-Za-z0-9_-]` body with
        // a leading word boundary catches every prefix (segmented and bare) while
        // the `\b` keeps `sk-` inside words like `ask-`/`disk-`/`task-` from
        // matching.
        add("openai-key", Severity::High, r"\b[sr]k-[A-Za-z0-9_-]{20,}");
        add(
            "stripe-key",
            Severity::High,
            r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}",
        );
        add("google-api-key", Severity::High, r"AIza[0-9A-Za-z_-]{35}");
        // Clean-prefix, unambiguous tokens: the prefix pins the class, so a High
        // redact carries no false-positive risk.
        add("npm-token", Severity::High, r"npm_[A-Za-z0-9]{36,}");
        add("pypi-token", Severity::High, r"pypi-[A-Za-z0-9_-]{16,}");
        add(
            "sendgrid-key",
            Severity::High,
            r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        );
        // Connection-string password: `scheme://user:PASSWORD@host`. The user
        // class stops at `/` (so a path like `host/a:b@c` never looks like
        // userinfo), but the password class admits *every* non-whitespace byte —
        // including `/` and `@` — and the greedy match backtracks to the LAST
        // `@`, the host delimiter. That captures a raw `/` in the password
        // (`aB3/xY9z`, common in generated RDS creds) and an embedded `@`
        // (`s3cr3t@x`) whole. The span covers user+password+`@`; the host after
        // `@` is left intact and searchable.
        add(
            "connection-string",
            Severity::High,
            r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s]*@",
        );
        add(
            "jwt",
            Severity::Med,
            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        );
        // `Authorization: Bearer <token>` / `bearer <token>`. Redacts (MED): the
        // 20-char-minimum, space-free token class keeps ordinary prose ("bearer
        // of news") out — a match is a live credential, not a word.
        add(
            "bearer",
            Severity::Med,
            r"(?i)bearer\s+[A-Za-z0-9._~+/-]{20,}=*",
        );
        // `Authorization: Basic <base64>`. Anchored on the header name so the
        // common English word "Basic" alone never fires; the base64 blob is the
        // encoded `user:password`, redacted MED.
        add(
            "http-basic",
            Severity::Med,
            r"(?i)authorization\s*:\s*basic\s+[A-Za-z0-9+/]{16,}={0,2}",
        );
        // `password=` / `passwd=` / `pwd=` assignment. The value class excludes a
        // leading `=` so a `password==foo` comparison is not mistaken for an
        // assignment, and stops at whitespace / common delimiters. An empty value
        // (`password=`) does not match.
        add(
            "password-assignment",
            Severity::Med,
            r#"(?i)\b(?:password|passwd|pwd)=[^\s&;"'=][^\s&;"']*"#,
        );
        // Keyword-proximity high-entropy value. Redacts (MED) rather than merely
        // flagging: a 40+ char contiguous token right after `secret`/`token`/
        // `api_key`/`password` is almost certainly a credential, and the keyword
        // anchor keeps false positives off ordinary prose (which has spaces). The
        // body admits `-`/`_` so dashed/underscored keyed secrets are not split.
        add(
            "generic-entropy",
            Severity::Med,
            r#"(?i)(?:secret|token|api[_-]?key|password|passwd)["'\s:=]+[A-Za-z0-9+/_-]{40,}={0,2}"#,
        );
        v
    })
}

/// Run every detector over `content`, returning matches sorted so that
/// overlapping hits can be resolved earliest-first, highest-severity-first.
pub fn scan_text(content: &str) -> Vec<RawMatch<'_>> {
    let mut matches: Vec<RawMatch<'_>> = Vec::new();
    for rule in rules() {
        for m in rule.re.find_iter(content) {
            matches.push(RawMatch {
                kind: rule.kind,
                severity: rule.severity,
                start: m.start(),
                end: m.end(),
                secret: &content[m.start()..m.end()],
            });
        }
    }
    matches.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(b.severity.cmp(&a.severity))
            .then(b.end.cmp(&a.end))
    });
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_high_severity_fixtures() {
        let text = "aws AKIAIOSFODNN7EXAMPLE end\ngh ghp_EXAMPLEFAKEGITHUBTOKENNOTREAL0000000";
        let hits = scan_text(text);
        let kinds: Vec<_> = hits.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&"aws-key"), "aws not caught: {kinds:?}");
        assert!(kinds.contains(&"github-token"), "gh not caught: {kinds:?}");
    }

    #[test]
    fn catches_private_key_block() {
        let text = "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIBanessecret\n-----END RSA PRIVATE KEY-----\nafter";
        let hits = scan_text(text);
        assert!(hits.iter().any(|m| m.kind == "private-key"));
        assert_eq!(hits.iter().filter(|m| m.kind == "private-key").count(), 1);
    }

    #[test]
    fn jwt_is_medium() {
        let text = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w";
        let hits = scan_text(text);
        let jwt = hits.iter().find(|m| m.kind == "jwt").expect("jwt caught");
        assert_eq!(jwt.severity, Severity::Med);
    }

    fn caught(text: &str, kind: &str) -> bool {
        scan_text(text)
            .iter()
            .any(|m| m.kind == kind && !m.secret.is_empty())
    }

    fn covers(text: &str, kind: &str, secret: &str) -> bool {
        scan_text(text)
            .iter()
            .any(|m| m.kind == kind && m.secret.contains(secret))
    }

    #[test]
    fn openai_segmented_prefixes_are_high() {
        for key in [
            "sk-proj-EXAMPLEFAKEKEYNOTAREALSECRET000000",
            "sk-cred-EXAMPLEFAKECREDENTIALNOTREAL0000",
            "sk-svcacct-EXAMPLEFAKESVCACCTNOTREAL0000",
            "sk-admin-EXAMPLEFAKEADMINKEYNOTREAL00000",
        ] {
            let text = format!("export OPENAI_API_KEY={key}\n");
            let hit = scan_text(&text)
                .into_iter()
                .find(|m| m.kind == "openai-key")
                .unwrap_or_else(|| panic!("openai key not caught: {key}"));
            assert_eq!(hit.severity, Severity::High);
            assert!(hit.secret.contains(key), "span does not cover the key");
        }
    }

    #[test]
    fn bare_legacy_openai_key_still_caught() {
        assert!(caught(
            "key sk-EXAMPLEFAKELEGACYKEYNOTREAL000000 end",
            "openai-key"
        ));
    }

    #[test]
    fn sk_inside_ordinary_words_does_not_match() {
        // `ask-`, `task-`, `disk-` all contain `sk-` but never at a word start.
        for w in [
            "please ask-me-about-something-really-long-here-friend",
            "the task-management-workflow-is-quite-involved-today",
            "my disk-usage-was-extremely-high-again-this-morning",
        ] {
            assert!(
                !caught(w, "openai-key"),
                "false positive on ordinary hyphenated word: {w}"
            );
        }
    }

    #[test]
    fn connection_string_password_with_embedded_at_is_covered() {
        let url = "postgres://admin:S3cr3tP@ssw0rd@db.internal:5432/prod";
        assert!(
            covers(url, "connection-string", "S3cr3tP@ssw0rd"),
            "password not covered by connection-string span"
        );
        // Host is outside the span (left searchable).
        let hit = scan_text(url)
            .into_iter()
            .find(|m| m.kind == "connection-string")
            .unwrap();
        assert!(!hit.secret.contains("db.internal"), "host swallowed");
    }

    #[test]
    fn plain_urls_and_ports_are_not_connection_strings() {
        for u in [
            "https://example.com/path/to/page",
            "https://example.com:8080/status",
            "https://user@example.com/profile",
        ] {
            assert!(!caught(u, "connection-string"), "false positive on {u}");
        }
    }

    #[test]
    fn stripe_live_key_is_high() {
        // Split literal so the contiguous `sk_live_<body>` never appears in
        // source (trips external structural secret scanners); yomi scans the
        // reconstructed runtime value, so detector fidelity is unchanged.
        assert!(caught(
            &format!("sk_live_{}", "EXAMPLEFAKESTRIPE00000000"),
            "stripe-key"
        ));
    }

    #[test]
    fn connection_string_slash_password_is_covered() {
        let url = "postgres://admin:aB3/xY9z@db.internal:5432/prod";
        assert!(
            covers(url, "connection-string", "aB3/xY9z"),
            "slash password not covered"
        );
        let hit = scan_text(url)
            .into_iter()
            .find(|m| m.kind == "connection-string")
            .unwrap();
        assert!(!hit.secret.contains("db.internal"), "host swallowed");
    }

    #[test]
    fn bearer_is_now_redacting_med() {
        let text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345";
        let hit = scan_text(text)
            .into_iter()
            .find(|m| m.kind == "bearer")
            .expect("bearer token not caught");
        assert_eq!(hit.severity, Severity::Med, "must redact, not just flag");
    }

    #[test]
    fn bearer_does_not_match_prose() {
        assert!(
            !caught("the bearer of news arrived at dawn today", "bearer"),
            "false positive on the word 'bearer' in prose"
        );
    }

    #[test]
    fn http_basic_is_redacting_med() {
        let text = "Authorization: Basic dXNlcjpzdXBlcnNlY3JldHBhc3N3b3Jk";
        let hit = scan_text(text)
            .into_iter()
            .find(|m| m.kind == "http-basic")
            .expect("basic creds not caught");
        assert_eq!(hit.severity, Severity::Med);
    }

    #[test]
    fn bare_basic_word_is_not_http_basic() {
        assert!(
            !caught(
                "a Basic understanding of the underlying material",
                "http-basic"
            ),
            "false positive on the word 'Basic'"
        );
    }

    #[test]
    fn password_assignment_is_redacting_med() {
        let text = "db password=SuperSecretDbPass123 end";
        let hit = scan_text(text)
            .into_iter()
            .find(|m| m.kind == "password-assignment")
            .expect("password assignment not caught");
        assert_eq!(hit.severity, Severity::Med);
        assert!(hit.secret.contains("SuperSecretDbPass123"));
    }

    #[test]
    fn password_assignment_ignores_empty_and_comparison() {
        assert!(
            !caught("password= (unset)", "password-assignment"),
            "empty value matched"
        );
        assert!(
            !caught("if password==expected {", "password-assignment"),
            "equality comparison matched as assignment"
        );
    }

    #[test]
    fn clean_prefix_tokens_are_high() {
        for (secret, kind) in [
            ("npm_EXAMPLEFAKENPMTOKENNOTREAL0000000000", "npm-token"),
            ("pypi-EXAMPLEFAKEPYPITOKENNOTREAL00", "pypi-token"),
            (
                "SG.EXAMPLEFAKE00000000000.EXAMPLEFAKESENDGRIDKEY000000000000000000000",
                "sendgrid-key",
            ),
        ] {
            let text = format!("token {secret} end");
            let hit = scan_text(&text)
                .into_iter()
                .find(|m| m.kind == kind)
                .unwrap_or_else(|| panic!("{kind} not caught"));
            assert_eq!(hit.severity, Severity::High);
            assert!(hit.secret.contains(secret));
        }
    }

    #[test]
    fn short_prefix_lookalikes_do_not_match() {
        assert!(!caught("npm_install everything now", "npm-token"));
        assert!(!caught("pypi-org here", "pypi-token"));
        assert!(!caught("SG.short.tail here", "sendgrid-key"));
    }

    #[test]
    fn keyword_high_entropy_is_now_redacting_med() {
        let hex = "deadbeefcafebabe0123456789abcdeffedcba9876543210";
        let text = format!("token {hex} here");
        let hit = scan_text(&text)
            .into_iter()
            .find(|m| m.kind == "generic-entropy")
            .expect("keyword'd hex token not caught");
        assert_eq!(hit.severity, Severity::Med, "must redact, not just flag");
        assert!(hit.secret.contains(hex));
    }
}
