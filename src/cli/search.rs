use super::EXIT_OK;
use crate::catalog;
use crate::config::Env;
use crate::index::query::{self, Filters, Hit};
use anyhow::Result;

#[derive(clap::Args)]
pub struct SearchArgs {
    /// Free-text terms plus inline `field:value` filters (e.g. `tool:Bash cargo`).
    pub query: Vec<String>,
    #[arg(long)]
    pub project: Option<String>,
    #[arg(long)]
    pub session: Option<String>,
    #[arg(long)]
    pub agent: Option<String>,
    #[arg(long)]
    pub role: Option<String>,
    #[arg(long)]
    pub tool: Option<String>,
    #[arg(long)]
    pub branch: Option<String>,
    #[arg(long)]
    pub cwd: Option<String>,
    #[arg(long)]
    pub since: Option<String>,
    #[arg(long)]
    pub until: Option<String>,
    #[arg(long)]
    pub on: Option<String>,
    #[arg(long, default_value_t = 20)]
    pub limit: usize,
    /// Snippet width in tokens (FTS5 caps this at 64).
    #[arg(long, default_value_t = 12)]
    pub context: usize,
}

pub fn run(env: &Env, args: &SearchArgs, json: bool) -> Result<i32> {
    // Read-only: a fresh/missing home yields an empty in-memory catalog → 0 hits,
    // never an error (R8).
    let cat = catalog::open_env_read(env)?;
    let (since, until) = query::date_bounds(
        args.on.as_deref(),
        args.since.as_deref(),
        args.until.as_deref(),
    )?;
    let filters = Filters {
        project: args.project.clone(),
        session: args.session.clone(),
        agent: args.agent.clone(),
        role: args.role.clone(),
        tool: args.tool.clone(),
        branch: args.branch.clone(),
        cwd: args.cwd.clone(),
        since,
        until,
    };
    let q = query::parse_query(&args.query.join(" "), filters, args.limit, args.context);
    let hits = cat.query_entries(&q)?;
    emit(&hits, json);
    Ok(EXIT_OK)
}

fn emit(hits: &[Hit], json: bool) {
    if json {
        let items: Vec<_> = hits
            .iter()
            .map(|h| {
                serde_json::json!({
                    "entry_uuid": h.entry_uuid,
                    "session": h.session_uuid,
                    "project": h.project_slug,
                    "role": h.role,
                    "agent": h.agent,
                    "tool": h.tool_name,
                    "timestamp": h.timestamp,
                    "has_redaction": h.has_redaction,
                    "snippet": h.snippet,
                    "rank": h.rank,
                })
            })
            .collect();
        let v = serde_json::json!({ "hits": items, "count": hits.len() });
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return;
    }
    if hits.is_empty() {
        println!("No matches.");
        return;
    }
    for h in hits {
        let session8: String = h.session_uuid.chars().take(8).collect();
        let ts = h.timestamp.as_deref().unwrap_or("-");
        let project = h.project_slug.as_deref().unwrap_or("-");
        let tool = h
            .tool_name
            .as_deref()
            .map(|t| format!("/{t}"))
            .unwrap_or_default();
        let redacted = if h.has_redaction { " [redacted]" } else { "" };
        println!(
            "{session8} · {ts} · {project} · {}{}{redacted}",
            h.agent, tool
        );
        println!("    {}", h.snippet.replace('\n', " "));
        println!(
            "    ↳ yomi read {} --entry {}",
            h.session_uuid, h.entry_uuid
        );
    }
}
