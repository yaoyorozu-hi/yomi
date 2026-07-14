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
        add("openai-key", Severity::High, r"sk-[A-Za-z0-9]{20,}");
        add("google-api-key", Severity::High, r"AIza[0-9A-Za-z_-]{35}");
        add(
            "jwt",
            Severity::Med,
            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        );
        add(
            "bearer",
            Severity::Low,
            r"(?i)bearer\s+[A-Za-z0-9._~+/-]{20,}=*",
        );
        add(
            "generic-entropy",
            Severity::Low,
            r#"(?i)(?:secret|token|api[_-]?key|password|passwd)["'\s:=]+[A-Za-z0-9+/]{40,}={0,2}"#,
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
        let text = "aws AKIAIOSFODNN7EXAMPLE end\ngh ghp_0123456789012345678901234567890123456";
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
}
