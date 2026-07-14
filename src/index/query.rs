//! Search query model: parse a raw query string (free text + inline
//! `field:value`) into a structured [`Query`], build a safe FTS5 MATCH string,
//! and resolve date bounds. All FTS text is quoted/escaped so a query can never
//! be a syntax error or an injection.

use anyhow::{Context, Result};

/// A fully-resolved search request handed to the catalog.
pub struct Query {
    /// FTS5 MATCH string (empty ⇒ metadata-only, filter-driven query).
    pub fts: String,
    pub filters: Filters,
    pub limit: usize,
    pub context_tokens: usize,
}

/// Facet filters, merged from CLI flags and inline `field:value` tokens.
#[derive(Default, Clone)]
pub struct Filters {
    pub project: Option<String>,
    pub session: Option<String>,
    pub agent: Option<String>,
    pub role: Option<String>,
    pub tool: Option<String>,
    pub branch: Option<String>,
    pub cwd: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
}

/// One ranked search result.
pub struct Hit {
    pub entry_uuid: String,
    pub session_uuid: String,
    pub project_slug: Option<String>,
    pub role: String,
    pub agent: String,
    pub tool_name: Option<String>,
    pub timestamp: Option<String>,
    pub has_redaction: bool,
    pub snippet: String,
    pub rank: f64,
}

/// Parse the raw query: split off inline `field:value` tokens into `cli` filters
/// (a CLI flag already set wins over an inline token), then quote the remaining
/// free-text terms into a safe FTS5 MATCH string.
pub fn parse_query(raw: &str, mut cli: Filters, limit: usize, context_tokens: usize) -> Query {
    let mut free = Vec::new();
    for tok in raw.split_whitespace() {
        if let Some((field, value)) = tok.split_once(':')
            && apply_inline_filter(&mut cli, field, value)
        {
            continue;
        }
        free.push(tok);
    }
    let fts = sanitize_fts(&free);
    Query {
        fts,
        filters: cli,
        limit,
        context_tokens,
    }
}

/// Route an inline `field:value` into `filters`, honoring CLI precedence (a slot
/// already `Some` from a CLI flag is not overwritten). Returns whether `field`
/// was a recognized filter (so an unrecognized `foo:bar` stays free-text).
fn apply_inline_filter(filters: &mut Filters, field: &str, value: &str) -> bool {
    let slot = match field {
        "project" => &mut filters.project,
        "session" => &mut filters.session,
        "agent" => &mut filters.agent,
        "role" => &mut filters.role,
        "tool" => &mut filters.tool,
        "branch" => &mut filters.branch,
        "cwd" => &mut filters.cwd,
        "since" => &mut filters.since,
        "until" => &mut filters.until,
        _ => return false,
    };
    if slot.is_none() && !value.is_empty() {
        *slot = Some(value.to_string());
    }
    true
}

/// Quote each free-text term as an FTS5 string literal (doubling embedded `"`),
/// joined by spaces (implicit AND). This yields a predictable AND-of-terms query
/// and makes operator characters (`OR`, `*`, `(`) inert, closing the injection
/// and syntax-error surface. An all-whitespace input yields an empty string,
/// which the caller routes to the metadata-only path.
fn sanitize_fts(terms: &[&str]) -> String {
    terms
        .iter()
        .filter(|t| !t.is_empty())
        .map(|t| format!("\"{}\"", t.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Resolve `--on` / `--since` / `--until` into `[since, until)` string bounds
/// (timestamps are RFC3339 UTC, so lexicographic comparison is correct). `--on D`
/// expands to `since=D`, `until=D+1day`. Explicit `--since`/`--until` pass through
/// (a bare `YYYY-MM-DD` sorts correctly against a full RFC3339 stamp).
pub fn date_bounds(
    on: Option<&str>,
    since: Option<&str>,
    until: Option<&str>,
) -> Result<(Option<String>, Option<String>)> {
    if let Some(day) = on {
        let d = chrono::NaiveDate::parse_from_str(day, "%Y-%m-%d")
            .with_context(|| format!("invalid --on date {day:?} (use YYYY-MM-DD)"))?;
        let next = d
            .succ_opt()
            .context("date overflow computing --on upper bound")?;
        return Ok((Some(d.to_string()), Some(next.to_string())));
    }
    Ok((since.map(str::to_string), until.map(str::to_string)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_query_inline_fields() {
        let q = parse_query("project:x tool:Bash foo bar", Filters::default(), 20, 12);
        assert_eq!(q.filters.project.as_deref(), Some("x"));
        assert_eq!(q.filters.tool.as_deref(), Some("Bash"));
        assert_eq!(q.fts, "\"foo\" \"bar\"");
    }

    #[test]
    fn cli_flag_overrides_inline() {
        let cli = Filters {
            project: Some("y".to_string()),
            ..Filters::default()
        };
        let q = parse_query("project:x foo", cli, 20, 12);
        assert_eq!(q.filters.project.as_deref(), Some("y"));
        assert_eq!(q.fts, "\"foo\"");
    }

    #[test]
    fn sanitize_fts_escapes_quotes() {
        assert_eq!(sanitize_fts(&["a\"b"]), "\"a\"\"b\"");
        // An operator-looking term is neutralized into a literal.
        assert_eq!(sanitize_fts(&["OR", "x*"]), "\"OR\" \"x*\"");
    }

    #[test]
    fn unknown_field_stays_free_text() {
        let q = parse_query("weird:token real", Filters::default(), 20, 12);
        assert_eq!(q.fts, "\"weird:token\" \"real\"");
    }

    #[test]
    fn date_bounds_on() {
        let (since, until) = date_bounds(Some("2026-07-12"), None, None).unwrap();
        assert_eq!(since.as_deref(), Some("2026-07-12"));
        assert_eq!(until.as_deref(), Some("2026-07-13"));
    }

    #[test]
    fn date_bounds_since_until_passthrough() {
        let (since, until) = date_bounds(None, Some("2026-01-01"), Some("2026-02-01")).unwrap();
        assert_eq!(since.as_deref(), Some("2026-01-01"));
        assert_eq!(until.as_deref(), Some("2026-02-01"));
    }
}
