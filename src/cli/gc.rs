use super::{EXIT_OK, EXIT_PARTIAL, EXIT_REFUSED};
use crate::blacklist::Blacklist;
use crate::catalog;
use crate::config::{Env, parse_duration};
use crate::gc::live::ProcLiveness;
use crate::gc::{self, CommitReport, Plan, Target, Verdict};
use crate::lock::WriteLock;
use crate::source::{self, SourceRoots};
use anyhow::Result;
use std::path::PathBuf;
use std::time::Duration;

#[derive(clap::Args)]
pub struct GcArgs {
    /// Comma list: transcripts,scratch,mcp,empty-dirs,paste,snapshots (default: all).
    #[arg(long)]
    pub targets: Option<String>,
    /// Actually delete. Without this, prints the plan and does nothing.
    #[arg(long)]
    pub commit: bool,
    /// Raise the hard min-age floor for this run (never lowers config min_age).
    #[arg(long)]
    pub min_age: Option<String>,
    /// Cross-user READ-ONLY discovery of ephemeral shapes (never deletes).
    #[arg(long)]
    pub discover_all_users: bool,
    /// Correct a too-loose store root to 700 instead of refusing.
    #[arg(long)]
    pub fix_perms: bool,
}

pub fn run(env: &Env, args: &GcArgs, json: bool) -> Result<i32> {
    if args.discover_all_users {
        return run_discovery(env, json);
    }

    let targets = match &args.targets {
        Some(s) => Target::parse_list(s)?,
        None => Target::all(),
    };
    let cfg = &env.config.gc;
    if cfg.history_compact {
        eprintln!(
            "warning: history_compact=true is inert in P2 (history is not a GC target); ignored"
        );
    }

    let bl = Blacklist::compile(&env.config.blacklist_add)?;
    let roots = SourceRoots::resolve()?;
    let live = ProcLiveness::resolve(&roots, cfg.active_window.0);
    let min_over: Option<Duration> = match &args.min_age {
        Some(s) => Some(parse_duration(s).ok_or_else(|| anyhow::anyhow!("bad --min-age: {s}"))?),
        None => None,
    };

    if args.commit {
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
        let plan = gc::plan(env, cfg, &targets, &cat, &bl, &live, min_over)?;
        let report = gc::commit(env, cfg, &plan, &cat, &bl, &live, min_over)?;
        emit_commit(&plan, &report, json);
        let partial = plan.unverified + report.flipped_unverified > 0;
        Ok(if partial { EXIT_PARTIAL } else { EXIT_OK })
    } else {
        let cat = catalog::open_env_read(env)?;
        let plan = gc::plan(env, cfg, &targets, &cat, &bl, &live, min_over)?;
        emit_plan(&plan, json);
        Ok(EXIT_OK)
    }
}

fn run_discovery(env: &Env, json: bool) -> Result<i32> {
    let home_base = std::env::var_os("YOMI_HOME_BASE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home"));
    let tmp_base = std::env::var_os("YOMI_TMP_BASE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let users = SourceRoots::discover_all_users(&home_base, &tmp_base)?;
    let shapes = source::discover::classify_shapes(&users);

    if json {
        let items: Vec<_> = shapes
            .iter()
            .map(|s| {
                serde_json::json!({
                    "user": s.user, "kind": s.kind.as_str(), "rel_shape": s.rel_shape,
                    "example_path": s.example_path.to_string_lossy(),
                    "bytes": s.bytes, "count": s.count,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        println!(
            "Discovered {} ephemeral shapes across {} user(s) (READ-ONLY, nothing deleted):",
            shapes.len(),
            users.len()
        );
        for s in &shapes {
            println!(
                "  [{}] {} ×{} ({} bytes) — {}",
                s.user,
                s.kind.as_str(),
                s.count,
                s.bytes,
                s.rel_shape
            );
        }
    }

    // Optionally persist the inventory next to the store, if a store exists.
    if env.is_initialized() {
        let path = env.home.join("shapes.json");
        let items: Vec<_> = shapes
            .iter()
            .map(|s| {
                serde_json::json!({
                    "user": s.user, "kind": s.kind.as_str(), "rel_shape": s.rel_shape,
                    "bytes": s.bytes, "count": s.count,
                })
            })
            .collect();
        std::fs::write(&path, serde_json::to_string_pretty(&items)? + "\n")?;
        let _ = Env::chmod_600(&path);
    }
    Ok(EXIT_OK)
}

fn emit_plan(plan: &Plan, json: bool) {
    if json {
        let items: Vec<_> = plan
            .items
            .iter()
            .map(|it| {
                let (verdict, reason) = verdict_strs(&it.verdict);
                serde_json::json!({
                    "source": it.candidate.source.to_string_lossy(),
                    "target": it.candidate.target.as_str(),
                    "verdict": verdict, "reason": reason, "bytes": it.bytes,
                })
            })
            .collect();
        let v = serde_json::json!({
            "committed": false,
            "deletable": plan.deletable,
            "protected": plan.protected,
            "unverified": plan.unverified,
            "reclaimable_bytes": plan.reclaimable_bytes,
            "items": items,
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return;
    }
    println!(
        "[dry-run] plan: {} deletable ({} bytes reclaimable), {} protected, {} unverified.",
        plan.deletable, plan.reclaimable_bytes, plan.protected, plan.unverified
    );
    for it in &plan.items {
        match &it.verdict {
            Verdict::Delete { .. } => println!(
                "  would-delete  {} ({} bytes)",
                it.candidate.source.display(),
                it.bytes
            ),
            Verdict::Protected { reason } => println!(
                "  protected     {} — {}",
                it.candidate.source.display(),
                reason.as_str()
            ),
            Verdict::Unverified { reason } => println!(
                "  unverified    {} — {}",
                it.candidate.source.display(),
                reason.as_str()
            ),
        }
    }
    println!("Run with --commit to apply.");
}

fn emit_commit(plan: &Plan, report: &CommitReport, json: bool) {
    if json {
        let v = serde_json::json!({
            "committed": true,
            "deleted": report.deleted,
            "reclaimed_bytes": report.reclaimed_bytes,
            "protected": plan.protected,
            "unverified": plan.unverified,
            "flipped_unverified": report.flipped_unverified,
            "flipped_protected": report.flipped_protected,
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return;
    }
    println!(
        "Deleted {} items ({} bytes reclaimed); {} protected, {} unverified.",
        report.deleted, report.reclaimed_bytes, plan.protected, plan.unverified
    );
    if report.flipped_unverified > 0 {
        println!(
            "{} planned deletes were skipped at commit (drifted to unverified).",
            report.flipped_unverified
        );
    }
}

fn verdict_strs(v: &Verdict) -> (&'static str, &'static str) {
    match v {
        Verdict::Delete { .. } => ("delete", ""),
        Verdict::Protected { reason } => ("protected", reason.as_str()),
        Verdict::Unverified { reason } => ("unverified", reason.as_str()),
    }
}
