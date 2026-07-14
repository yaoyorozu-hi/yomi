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
    /// Verify one session UUID.
    pub session: Option<String>,
    /// Verify every stored artifact.
    #[arg(long)]
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

    if json {
        let v = serde_json::json!({
            "verified": ok,
            "failed": failed.len(),
            "failures": failed,
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
    }
    Ok(if failed.is_empty() {
        EXIT_OK
    } else {
        EXIT_PARTIAL
    })
}
