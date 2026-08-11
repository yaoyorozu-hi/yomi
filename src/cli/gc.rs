use super::{EXIT_OK, EXIT_PARTIAL, EXIT_REFUSED};
use crate::blacklist::Blacklist;
use crate::catalog;
use crate::config::{Env, parse_duration};
use crate::gc::live::ProcLiveness;
use crate::gc::{self, CommitReport, Plan, ScratchMode, Target, Verdict};
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
    /// Reclaim what is already archived, ignoring retain windows: every family's
    /// window drops to zero and the min-age floor relaxes to [gc] active_window,
    /// never below it. A scratch tree additionally needs a caps-lifted ledger with
    /// an empty captured set.
    #[arg(long)]
    pub full: bool,
    /// Reclaim every scratch tree in scope whatever it holds: the age policy relaxes
    /// exactly as under --full, and no ledger is consulted to authorize the delete.
    /// Transcripts and the other catalog-backed families keep all five archive gates.
    /// Cannot be combined with --full.
    //
    // Refused at parse time rather than resolved to the wider level. The two flags
    // name two predicates, and honouring only one of a pair the operator typed is
    // the failure mode this CLI already refuses elsewhere (§8, `read --scratch`). The
    // asymmetry decides it: an operator who believes `--full` narrows what `--wipe`
    // takes has, under a wipe-wins rule, just deleted every captured tree in scope.
    #[arg(long, conflicts_with_all = ["full"])]
    pub wipe: bool,
    /// Cross-user READ-ONLY discovery of ephemeral shapes (never deletes).
    /// Cannot be combined with --full or --wipe.
    //
    // Refused at parse time: discovery returns before a target is even parsed, and
    // `candidates()` refuses any root this euid does not own, so the pair can only
    // mislead about what the run did. A parse error is the cheapest correct answer
    // and cannot drift from the code.
    #[arg(long, conflicts_with_all = ["full", "wipe"])]
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

    let bl = Blacklist::compile(env)?;
    let roots = SourceRoots::resolve()?;
    let live = ProcLiveness::resolve(&roots, cfg.active_window.0);
    let min_over: Option<Duration> = match &args.min_age {
        Some(s) => Some(parse_duration(s).ok_or_else(|| anyhow::anyhow!("bad --min-age: {s}"))?),
        None => None,
    };
    let mode = if args.wipe {
        ScratchMode::Wipe
    } else if args.full {
        ScratchMode::Full
    } else {
        ScratchMode::Aged
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
        let plan = gc::plan(env, cfg, &targets, &cat, &bl, &live, min_over, mode)?;
        announce_wipe(&plan, json);
        let report = gc::commit(env, cfg, &plan, &cat, &bl, &live, min_over, mode)?;
        emit_commit(&plan, &report, json);
        let partial = plan.unverified + report.flipped_unverified > 0;
        Ok(if partial { EXIT_PARTIAL } else { EXIT_OK })
    } else {
        let cat = catalog::open_env_read(env)?.catalog;
        let plan = gc::plan(env, cfg, &targets, &cat, &bl, &live, min_over, mode)?;
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
                    "archived_bytes": it.split.archived,
                    "unarchived_bytes": it.split.unarchived,
                })
            })
            .collect();
        let v = serde_json::json!({
            "committed": false,
            "deletable": plan.deletable,
            "protected": plan.protected,
            "unverified": plan.unverified,
            "reclaimable_bytes": plan.reclaimable_bytes,
            "reclaimable_archived_bytes": plan.reclaimable_archived_bytes,
            "reclaimable_unarchived_bytes": plan.reclaimable_unarchived_bytes,
            "scratch_no_ledger": plan.scratch_no_ledger,
            "scratch_not_fully_archived": plan.scratch_not_fully_archived,
            "items": items,
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return;
    }
    println!(
        "[dry-run] plan: {} deletable ({} bytes reclaimable), {} protected, {} unverified.",
        plan.deletable, plan.reclaimable_bytes, plan.protected, plan.unverified
    );
    emit_split(
        "reclaimable",
        plan.reclaimable_archived_bytes,
        plan.reclaimable_unarchived_bytes,
    );
    emit_full_advice(plan);
    emit_wipe_notice(plan);
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
            "reclaimed_archived_bytes": report.reclaimed_archived_bytes,
            "reclaimed_unarchived_bytes": report.reclaimed_unarchived_bytes,
            "protected": plan.protected,
            "unverified": plan.unverified,
            "flipped_unverified": report.flipped_unverified,
            "flipped_protected": report.flipped_protected,
            "scratch_no_ledger": plan.scratch_no_ledger,
            "scratch_not_fully_archived": plan.scratch_not_fully_archived,
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return;
    }
    println!(
        "Deleted {} items ({} bytes reclaimed); {} protected, {} unverified.",
        report.deleted, report.reclaimed_bytes, plan.protected, plan.unverified
    );
    emit_split(
        "reclaimed",
        report.reclaimed_archived_bytes,
        report.reclaimed_unarchived_bytes,
    );
    emit_full_advice(plan);
    if report.flipped_unverified > 0 {
        println!(
            "{} planned deletes were skipped at commit (drifted to unverified).",
            report.flipped_unverified
        );
    }
}

/// How much of what this run takes exists somewhere else afterwards. A total on
/// its own cannot say that, and it is the difference between reclaiming build
/// output and reclaiming the only copy of something.
fn emit_split(label: &str, archived: u64, unarchived: u64) {
    println!("Of the {label} bytes: {archived} archived, {unarchived} with no archived copy.");
}

/// What an operator must run before `--full` has anything to take. Without it a
/// fresh host sees "0 deletable" and nothing naming the cause — the flag looks
/// broken where in fact no tree has ever been offered to it.
fn emit_full_advice(plan: &Plan) {
    if plan.mode != ScratchMode::Full {
        return;
    }
    if plan.scratch_no_ledger > 0 {
        println!(
            "{} scratch tree(s) are not covered by a ledger this run could verify, so --full \
             leaves them alone. Run `yomi archive --all --full` first: a tree yomi never \
             captured is not a tree whose captured set is empty.",
            plan.scratch_no_ledger
        );
    }
    if plan.scratch_not_fully_archived > 0 {
        println!(
            "{} scratch tree(s) were last archived with the [scratch] caps in force, so what \
             they hold is not established under --full. Run `yomi archive --all --full` to \
             settle it.",
            plan.scratch_not_fully_archived
        );
    }
}

/// What `--wipe` claims, said where a dry run can still stop it. `--full`'s advice
/// names a command that widens what the verb may take; there is no such command here,
/// so this names the consequence instead — the unarchived figure on the line above is
/// what will exist in no copy afterwards.
fn emit_wipe_notice(plan: &Plan) {
    if plan.mode != ScratchMode::Wipe || plan.deletable == 0 {
        return;
    }
    println!(
        "--wipe consults no ledger: {} scratch tree(s) are in scope whatever they hold, and the \
         {} bytes with no archived copy exist nowhere else once this runs.",
        plan.deletable_trees(),
        plan.reclaimable_unarchived_bytes
    );
}

/// What a `--wipe --commit` is about to destroy, printed **before the first unlink**.
///
/// Decision #6 keeps `--commit` as the only gate — a second one would make this the
/// single verb in the binary with its own confirmation idiom, and an interactive
/// prompt would break the non-interactive use this CLI is built for. What stands in
/// for it is information: this line plus the `gc.log` run header, so a run killed
/// halfway still leaves its numbers in the operator's scrollback and in the log.
///
/// Under `--json` it goes to stderr. A human line on stdout would make the report
/// unparseable, and the report is the one thing a caller must be able to read.
fn announce_wipe(plan: &Plan, json: bool) {
    if plan.mode != ScratchMode::Wipe || plan.deletable == 0 {
        return;
    }
    let line = format!(
        "wipe: deleting {} scratch tree(s), {} candidate(s) in total, {} bytes — {} archived, \
         {} with no archived copy anywhere.",
        plan.deletable_trees(),
        plan.deletable,
        plan.reclaimable_bytes,
        plan.reclaimable_archived_bytes,
        plan.reclaimable_unarchived_bytes,
    );
    if json {
        eprintln!("{line}");
    } else {
        println!("{line}");
    }
}

fn verdict_strs(v: &Verdict) -> (&'static str, &'static str) {
    match v {
        Verdict::Delete { .. } => ("delete", ""),
        Verdict::Protected { reason } => ("protected", reason.as_str()),
        Verdict::Unverified { reason } => ("unverified", reason.as_str()),
    }
}
