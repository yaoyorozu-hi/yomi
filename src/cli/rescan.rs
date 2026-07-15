use super::{EXIT_OK, EXIT_PARTIAL, EXIT_REFUSED};
use crate::catalog;
use crate::config::Env;
use crate::lock::WriteLock;
use crate::rescan::{self, RescanPlan, RescanReport};
use crate::scan::Allowlist;
use anyhow::Result;

#[derive(clap::Args)]
pub struct RescanArgs {
    /// Actually re-redact. Without this, prints the plan and mutates nothing.
    #[arg(long)]
    pub commit: bool,
    /// Limit the sweep to one session UUID.
    #[arg(long)]
    pub session: Option<String>,
    /// Correct a too-loose store root to 700 instead of refusing.
    #[arg(long)]
    pub fix_perms: bool,
}

pub fn run(env: &Env, args: &RescanArgs, json: bool) -> Result<i32> {
    let allow = Allowlist::compile(&env.config.scan.allow);
    if args.commit {
        // Mutates the store and catalog → require the layout and the single-writer
        // lock (same discipline as `gc --commit` / `index`), so rescan never
        // interleaves with archive / index / gc.
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
        let report = rescan::commit(env, &cat, &allow, args.session.as_deref())?;
        emit_commit(&report, json);
        let partial = report.verify_failures + report.failed.len() as u64 > 0;
        Ok(if partial { EXIT_PARTIAL } else { EXIT_OK })
    } else {
        let cat = catalog::open_env_read(env)?;
        let plan = rescan::plan(env, &cat, &allow, args.session.as_deref())?;
        emit_plan(&plan, json);
        Ok(EXIT_OK)
    }
}

/// Render `kind×count` pairs for one preview row — never a secret value.
fn kind_summary(counts: &std::collections::BTreeMap<String, u32>) -> String {
    if counts.is_empty() {
        return "—".to_string();
    }
    counts
        .iter()
        .map(|(k, n)| format!("{k}×{n}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn emit_plan(plan: &RescanPlan, json: bool) {
    if json {
        let items: Vec<_> = plan
            .previews
            .iter()
            .map(|p| {
                serde_json::json!({
                    "session": p.session_uuid,
                    "source": p.source_path,
                    "role": p.role,
                    "transition": p.transition.as_str(),
                    "kinds": p.kind_counts,
                    "index_rows_affected": p.index_rows_affected,
                })
            })
            .collect();
        let v = serde_json::json!({
            "committed": false,
            "scanned": plan.scanned,
            "targeted": plan.previews.len(),
            "targets": items,
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return;
    }
    println!(
        "[dry-run] rescan plan: {} artifact(s) would be re-redacted (scanned {}).",
        plan.previews.len(),
        plan.scanned
    );
    for p in &plan.previews {
        println!(
            "  {:<11} {}  [{}]  {}  ({} index rows)",
            p.role,
            p.source_path,
            p.transition.as_str(),
            kind_summary(&p.kind_counts),
            p.index_rows_affected
        );
    }
    if !plan.previews.is_empty() {
        println!("Run with --commit to apply.");
    }
}

fn emit_commit(report: &RescanReport, json: bool) {
    if json {
        let v = serde_json::json!({
            "committed": true,
            "scanned": report.scanned,
            "targeted": report.targeted,
            "reredacted": report.reredacted,
            "secrets_removed": report.secrets_removed,
            "index_rows_purged": report.index_rows_purged,
            "index_rows_rebuilt": report.index_rows_rebuilt,
            "visible_quarantine_transitions": report.visible_quarantine_transitions,
            "whole_quarantine_transitions": report.whole_quarantine_transitions,
            "skipped_markers": report.skipped_markers,
            "verify_failures": report.verify_failures,
            "failed": report.failed,
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return;
    }
    println!(
        "Re-redacted {} artifact(s): {} secret(s) removed, {} index rows rebuilt ({} purged); \
         {} visible-quarantine, {} whole-quarantine transition(s). Verify: {}.",
        report.reredacted,
        report.secrets_removed,
        report.index_rows_rebuilt,
        report.index_rows_purged,
        report.visible_quarantine_transitions,
        report.whole_quarantine_transitions,
        if report.verify_failures == 0 {
            "pass"
        } else {
            "FAIL"
        }
    );
    if !report.failed.is_empty() {
        println!("Skipped/failed ({}):", report.failed.len());
        for f in &report.failed {
            println!("  {f}");
        }
    }
}
