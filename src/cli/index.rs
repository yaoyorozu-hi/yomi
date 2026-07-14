use super::{EXIT_OK, EXIT_REFUSED};
use crate::catalog;
use crate::config::Env;
use crate::index;
use crate::lock::WriteLock;
use anyhow::Result;

#[derive(clap::Args)]
pub struct IndexArgs {
    /// Drop all indexed entries and rebuild from scratch (also switches tokenizer).
    #[arg(long)]
    pub reindex: bool,
    /// Limit indexing to one session UUID.
    #[arg(long)]
    pub session: Option<String>,
    /// Correct a too-loose store root to 700 instead of refusing.
    #[arg(long)]
    pub fix_perms: bool,
}

pub fn run(env: &Env, args: &IndexArgs, json: bool) -> Result<i32> {
    // Indexing mutates catalog.db → require the store layout and the single-writer
    // lock (same discipline as `gc --commit`), so index and GC can never interleave.
    if let Err(e) = env.ensure_layout(args.fix_perms) {
        eprintln!("{e}");
        return Ok(EXIT_REFUSED);
    }
    let _lock = match WriteLock::acquire(&env.lock_path()) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{e}");
            return Ok(EXIT_REFUSED);
        }
    };
    let cat = catalog::open_env(env)?;

    // Record the tokenizer the FTS vtable was actually created with (unicode61,
    // the schema.sql DDL), so a configured `trigram` shows up as a mismatch and is
    // routed through the destructive `--reindex` rebuild rather than silently
    // recording a tokenizer the vtable does not use.
    index::bootstrap_tokenizer(&cat)?;
    let effective = env.config.index.effective_tokenizer();
    let stored_tok = cat.index_meta_get("tokenizer")?;
    if let Some(st) = &stored_tok
        && st != effective
        && !args.reindex
    {
        eprintln!(
            "refuse: index tokenizer changed ({st} -> {effective}); run `yomi index --reindex`"
        );
        return Ok(EXIT_REFUSED);
    }

    let report = if args.reindex {
        index::reindex(env, &cat, args.session.as_deref())?
    } else {
        index::index_incremental(env, &cat, args.session.as_deref())?
    };

    emit(&report, json);
    Ok(EXIT_OK)
}

fn emit(r: &index::IndexRunReport, json: bool) {
    if json {
        let v = serde_json::json!({
            "artifacts_indexed": r.artifacts_indexed,
            "docs_written": r.docs_written,
            "artifacts_up_to_date": r.artifacts_up_to_date,
            "docs_deleted": r.docs_deleted,
            "parse_skipped": r.parse_skipped,
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
    } else {
        println!(
            "Indexed {} artifact(s), {} doc(s) written ({} up-to-date, {} replaced, {} lines skipped).",
            r.artifacts_indexed,
            r.docs_written,
            r.artifacts_up_to_date,
            r.docs_deleted,
            r.parse_skipped
        );
    }
}
