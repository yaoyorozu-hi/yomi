use super::{EXIT_OK, EXIT_PARTIAL};
use crate::archive::verify_stored;
use crate::catalog;
use crate::config::Env;
use crate::lock::WriteLock;
use crate::model::Severity;
use anyhow::Result;

#[derive(clap::Args)]
pub struct StatusArgs {
    /// List secret-scan findings for human review.
    #[arg(long)]
    pub secrets: bool,
    /// List artifacts not yet verified.
    #[arg(long)]
    pub unverified: bool,
    /// Show stored-bytes footprint.
    #[arg(long)]
    pub storage: bool,
}

#[derive(clap::Args)]
pub struct VerifyArgs {
    /// Verify one session UUID. Omitting it verifies everything.
    pub session: Option<String>,
    /// Verify every stored artifact — an explicit alias for omitting <SESSION>,
    /// not an independent mode. Passing both is a usage error rather than a
    /// silently ignored flag.
    #[arg(long, conflicts_with = "session")]
    pub all: bool,
}

pub fn run_status(env: &Env, args: &StatusArgs, json: bool) -> Result<i32> {
    // Read-side: a fresh, uninitialized home reports "nothing archived" rather
    // than erroring (W1/R8).
    let cat = catalog::open_env_read(env)?;
    let counts = cat.counts()?;

    if args.secrets {
        let rows = cat.secret_rows(Severity::Low)?;
        if json {
            let items: Vec<_> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "session": r.session_uuid, "source": r.source_path,
                        "kind": r.kind, "severity": r.severity,
                        "action": r.action, "secret_sha8": r.secret_sha8,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&items)?);
        } else if rows.is_empty() {
            println!("No secret-scan findings recorded.");
        } else {
            println!("Secret-scan findings ({}):", rows.len());
            for r in &rows {
                println!(
                    "  [{}] {} {} ({}) in {} — {}",
                    r.severity, r.kind, r.secret_sha8, r.action, r.source_path, r.session_uuid
                );
            }
        }
        return Ok(EXIT_OK);
    }

    if args.unverified {
        let rows = cat.unverified_sources()?;
        if json {
            println!("{}", serde_json::to_string_pretty(&rows)?);
        } else if rows.is_empty() {
            println!("All artifacts verified.");
        } else {
            println!("Unverified artifacts ({}):", rows.len());
            for r in &rows {
                println!("  {r}");
            }
        }
        return Ok(if rows.is_empty() {
            EXIT_OK
        } else {
            EXIT_PARTIAL
        });
    }

    if json {
        let v = serde_json::json!({
            "sessions": counts.sessions,
            "artifacts": counts.artifacts,
            "redacted": counts.redacted,
            "quarantined": counts.quarantined,
            "unverified": counts.unverified,
            "stored_bytes": counts.stored_bytes,
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        println!("Sessions:    {}", counts.sessions);
        println!("Artifacts:   {}", counts.artifacts);
        println!("Redacted:    {}", counts.redacted);
        println!("Quarantined: {}", counts.quarantined);
        println!("Unverified:  {}", counts.unverified);
        if args.storage {
            println!("Stored:      {} bytes", counts.stored_bytes);
        }
    }
    Ok(EXIT_OK)
}

pub fn run_verify(env: &Env, args: &VerifyArgs, json: bool) -> Result<i32> {
    let cat = catalog::open_env_read(env)?;
    let rows = match &args.session {
        Some(uuid) => cat.verify_rows_for_session(uuid)?,
        None => cat.verify_rows()?,
    };
    let archive_dir = env.archive_dir();

    // Persisting `verified_at` is a write; take the single-writer lock so it
    // never races an archive run. If unavailable (or the store is fresh),
    // verify still reports but does not persist (W4).
    let lock = if env.is_initialized() {
        WriteLock::acquire(&env.lock_path()).ok()
    } else {
        None
    };

    let mut ok = 0u64;
    let mut failed = Vec::new();
    for row in &rows {
        if verify_stored(
            &archive_dir,
            &row.stored_path,
            &row.stored_sha256,
            &row.content_sha256,
        )? {
            if lock.is_some() {
                cat.mark_verified(row.id)?;
            }
            ok += 1;
        } else {
            failed.push(format!(
                "{} [{}] {}",
                row.session_uuid, row.role, row.stored_path
            ));
        }
    }

    // Scratch has no catalog row, so `verify_rows()` cannot reach it. Its pass is
    // manifest-driven — the manifest is the ledger the delete gate consumes, and
    // attesting to anything else would be attesting to the wrong thing (§5).
    //
    // The lock this command already takes for `verified_at` is also what makes
    // (manifest, store) a consistent snapshot. Without it the pass can confirm
    // but not accuse, so comparative findings downgrade — see `exclusive`.
    let scratch = crate::scratch::verify_stores(
        &archive_dir,
        args.session.as_deref().map(std::ffi::OsStr::new),
        lock.is_some(),
    );

    if json {
        let v = serde_json::json!({
            "verified": ok,
            "failed": failed.len(),
            "failures": failed,
            "scratch": {
                "exclusive": scratch.exclusive,
                "keys": scratch.keys,
                "verified": scratch.verified,
                "violations": findings_json(&scratch.violations),
                "unverifiable": findings_json(&scratch.unverifiable),
                "foreign_matter": findings_json(&scratch.foreign_matter),
                "refused": findings_json(&scratch.refused),
            },
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        println!("Verified {ok} artifacts.");
        if !failed.is_empty() {
            println!("FAILED ({}):", failed.len());
            for f in &failed {
                println!("  {f}");
            }
        }
        println!(
            "Scratch: {} store dirs, {} artifacts verified.",
            scratch.keys, scratch.verified
        );
        if !scratch.exclusive {
            println!(
                "  not exclusive: the write lock was unavailable, so a concurrent \
                 archive may be mid-write. Findings that compare the ledger against \
                 the store are reported as unverifiable rather than as defects."
            );
        }
        // Only violations and refusals are defects; the other two sections say
        // what the ledger cannot prove and what only an operator can clear.
        emit_findings("VIOLATIONS", &scratch.violations);
        emit_findings("refused keys", &scratch.refused);
        emit_findings("unverifiable", &scratch.unverifiable);
        emit_findings("foreign matter", &scratch.foreign_matter);
    }
    Ok(if failed.is_empty() && !scratch.failed() {
        EXIT_OK
    } else {
        EXIT_PARTIAL
    })
}

fn findings_json(v: &[crate::scratch::ScratchFinding]) -> Vec<serde_json::Value> {
    v.iter()
        .map(|f| {
            serde_json::json!({
                "key": f.key, "rel": f.rel, "issue": f.issue.as_str(),
                "class": f.class.as_str(),
            })
        })
        .collect()
}

fn emit_findings(label: &str, v: &[crate::scratch::ScratchFinding]) {
    if v.is_empty() {
        return;
    }
    println!("  {label} ({}):", v.len());
    for f in v {
        if f.rel.is_empty() {
            println!("    {} — {}", f.key, f.issue.as_str());
        } else {
            println!("    {} {} — {}", f.key, f.rel, f.issue.as_str());
        }
    }
}
