use super::{EXIT_OK, EXIT_PARTIAL};
use crate::archive::compress::decompress_all;
use crate::catalog;
use crate::config::Env;
use crate::index::EntryRow;
use anyhow::Result;

#[derive(clap::Args)]
pub struct ReadArgs {
    /// Session UUID to read.
    pub session: String,
    /// Jump to a single entry by its entry_uuid.
    #[arg(long)]
    pub entry: Option<String>,
    /// Include subagent transcripts, not just the main thread.
    #[arg(long)]
    pub agents: bool,
    /// Show only entries whose text contains this literal substring.
    #[arg(long)]
    pub grep: Option<String>,
    /// Emit the raw decompressed stored JSONL (index-independent).
    #[arg(long)]
    pub raw: bool,
}

pub fn run(env: &Env, args: &ReadArgs, json: bool) -> Result<i32> {
    let cat = catalog::open_env_read(env)?;

    if args.raw {
        return read_raw(env, &cat, &args.session);
    }

    if let Some(entry_uuid) = &args.entry {
        return match cat.entry_by_uuid(&args.session, entry_uuid)? {
            Some(row) => {
                emit_entries(std::slice::from_ref(&row), json);
                Ok(EXIT_OK)
            }
            None => {
                eprintln!(
                    "entry {entry_uuid} not found in session {} (run `yomi index` if not yet indexed)",
                    args.session
                );
                Ok(EXIT_PARTIAL)
            }
        };
    }

    let rows = cat.entries_for_session(&args.session, args.agents)?;
    let filtered: Vec<EntryRow> = match &args.grep {
        Some(needle) => rows
            .into_iter()
            .filter(|r| r.text.contains(needle))
            .collect(),
        None => rows,
    };
    if filtered.is_empty() {
        eprintln!(
            "no indexed entries for session {} (run `yomi index`, or use --raw for the stored transcript)",
            args.session
        );
        return Ok(EXIT_PARTIAL);
    }
    emit_entries(&filtered, json);
    Ok(EXIT_OK)
}

/// Decompress and print the stored transcript (and, per session, subagent)
/// artifacts. Independent of the index, so it works before `yomi index` runs.
fn read_raw(env: &Env, cat: &catalog::Catalog, session: &str) -> Result<i32> {
    let archive_dir = env.archive_dir();
    let mut printed = false;
    for c in cat.index_candidates_for_session(session)? {
        if c.role != "transcript" && c.role != "subagent" {
            continue;
        }
        let Ok(raw) = std::fs::read(archive_dir.join(&c.stored_path)) else {
            continue;
        };
        let Ok(text) = decompress_all(&raw) else {
            continue;
        };
        print!("{}", String::from_utf8_lossy(&text));
        printed = true;
    }
    if !printed {
        eprintln!("no stored transcript for session {session}");
        return Ok(EXIT_PARTIAL);
    }
    Ok(EXIT_OK)
}

fn emit_entries(rows: &[EntryRow], json: bool) {
    if json {
        let items: Vec<_> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "entry_uuid": r.entry_uuid,
                    "parent_uuid": r.parent_uuid,
                    "role": r.role,
                    "agent": r.agent,
                    "tool": r.tool_name,
                    "timestamp": r.timestamp,
                    "has_redaction": r.has_redaction,
                    "text": r.text,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&items).unwrap_or_default()
        );
        return;
    }
    for r in rows {
        let ts = r.timestamp.as_deref().unwrap_or("-");
        let tool = r
            .tool_name
            .as_deref()
            .map(|t| format!("/{t}"))
            .unwrap_or_default();
        let redacted = if r.has_redaction { " [redacted]" } else { "" };
        println!("── {} · {}{} · {ts}{redacted}", r.role, r.agent, tool);
        println!("{}", r.text);
        println!();
    }
}
