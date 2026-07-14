use super::{EXIT_OK, EXIT_REFUSED};
use crate::archive::{Archiver, Report};
use crate::blacklist::Blacklist;
use crate::catalog;
use crate::config::Env;
use crate::lock::WriteLock;
use crate::scan::Allowlist;
use crate::source::claude::{self, Selector};
use crate::source::single;
use crate::source::{Include, SourceRoots};
use anyhow::Result;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct ArchiveArgs {
    /// Archive every discoverable session.
    #[arg(long)]
    pub all: bool,
    /// Archive only this session UUID.
    #[arg(long)]
    pub session: Option<String>,
    /// Archive a single transcript `.jsonl` path.
    pub path: Option<PathBuf>,
    /// Comma list: transcript,subagents,tool-results,history,mcp,snapshots,paste,scratch,all.
    #[arg(long)]
    pub include: Option<String>,
    /// Skip the secret scan (store raw). Not recommended.
    #[arg(long)]
    pub no_scan: bool,
    /// Quarantine the original on any redacting finding, not just HIGH.
    #[arg(long)]
    pub quarantine_on_secret: bool,
    /// Compute and report, but write nothing.
    #[arg(long)]
    pub dry_run: bool,
    /// Correct a too-loose store root to mode 700 instead of refusing.
    #[arg(long)]
    pub fix_perms: bool,
}

pub fn run(env: &Env, args: &ArchiveArgs, json: bool) -> Result<i32> {
    if !args.dry_run
        && let Err(e) = env.ensure_layout(args.fix_perms)
    {
        eprintln!("{e}");
        return Ok(EXIT_REFUSED);
    }

    let includes = match &args.include {
        Some(spec) => Include::parse_list(spec)?,
        None => Include::default_set(),
    };

    let blacklist = Blacklist::compile(&env.config.blacklist_add)?;
    let allow = Allowlist::compile(&env.config.scan.allow);
    let roots = SourceRoots::resolve()?;

    // Single-writer lock for the duration of the run.
    let _lock = if args.dry_run {
        None
    } else {
        match WriteLock::acquire(&env.lock_path()) {
            Ok(l) => Some(l),
            Err(e) => {
                eprintln!("{e}");
                return Ok(EXIT_REFUSED);
            }
        }
    };

    // A real run initializes and writes the catalog; a dry run opens read-only
    // (empty if the home is fresh) and never touches disk (W1/R8).
    let cat = if args.dry_run {
        catalog::open_env_read(env)?
    } else {
        catalog::open_env(env)?
    };
    let archiver = Archiver {
        env,
        blacklist: &blacklist,
        allow: &allow,
        catalog: &cat,
        scan_enabled: !args.no_scan,
        quarantine_all: args.quarantine_on_secret,
        dry_run: args.dry_run,
    };

    let mut report = Report::default();

    // Session sources (transcript / subagents / tool-results).
    if includes.iter().any(|i| {
        matches!(
            i,
            Include::Transcript | Include::Subagents | Include::ToolResults
        )
    }) {
        let selector = if let Some(p) = &args.path {
            Selector::TranscriptPath(p.clone())
        } else if let Some(u) = &args.session {
            Selector::Session(u.clone())
        } else if args.all {
            Selector::All
        } else {
            anyhow::bail!("specify one of --all, --session <uuid>, or a transcript PATH");
        };
        for session in claude::discover(&roots, &selector)? {
            archiver.archive_session(&session, &includes, &mut report)?;
        }
    }

    // Single-file sources.
    if includes.contains(&Include::History) {
        for sf in single::history(&roots) {
            archiver.archive_single(&sf, &mut report)?;
        }
    }
    if includes.contains(&Include::Mcp) {
        for sf in single::mcp(&roots) {
            archiver.archive_single(&sf, &mut report)?;
        }
    }
    if includes.contains(&Include::Snapshots) {
        for sf in single::snapshots(&roots)? {
            archiver.archive_single(&sf, &mut report)?;
        }
    }
    if includes.contains(&Include::Paste) {
        for sf in single::paste(&roots)? {
            archiver.archive_single(&sf, &mut report)?;
        }
    }
    if includes.contains(&Include::Scratch) {
        for sc in single::scratch(&roots)? {
            archiver.archive_scratch(&sc, &mut report)?;
        }
    }

    emit(&report, args.dry_run, json);
    Ok(EXIT_OK)
}

fn emit(r: &Report, dry_run: bool, json: bool) {
    if json {
        let v = serde_json::json!({
            "dry_run": dry_run,
            "sessions": r.sessions,
            "artifacts_written": r.artifacts_written,
            "artifacts_skipped": r.artifacts_skipped,
            "bytes_stored": r.bytes_stored,
            "findings": r.findings,
            "redacted": r.redacted,
            "quarantined": r.quarantined,
            "flagged": r.flagged,
            "blacklisted_skipped": r.blacklisted_skipped,
            "oversize_skipped": r.oversize_skipped,
        });
        println!("{}", serde_json::to_string(&v).unwrap_or_default());
        return;
    }
    let prefix = if dry_run { "[dry-run] " } else { "" };
    println!(
        "{prefix}{} sessions, {} artifacts written, {} unchanged, {} bytes stored.",
        r.sessions, r.artifacts_written, r.artifacts_skipped, r.bytes_stored
    );
    if r.findings > 0 {
        println!(
            "{prefix}secrets: {} findings, {} redacted, {} quarantined, {} flagged.",
            r.findings, r.redacted, r.quarantined, r.flagged
        );
    }
    if r.blacklisted_skipped > 0 {
        println!(
            "{prefix}{} blacklisted paths refused.",
            r.blacklisted_skipped
        );
    }
    if r.oversize_skipped > 0 {
        println!("{prefix}{} oversized sources skipped.", r.oversize_skipped);
    }
}
