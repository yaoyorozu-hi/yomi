use crate::archive::incremental::Prior;
use crate::config::Env;
use crate::model::{ArtifactRole, Finding, Severity};
use crate::util::now_iso;
use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;

pub struct Catalog {
    conn: Connection,
}

/// A row to upsert after archiving an artifact.
pub struct ArtifactUpsert<'a> {
    pub session_uuid: &'a str,
    pub role: ArtifactRole,
    pub source_path: &'a str,
    pub source_sha256: &'a str,
    pub source_bytes: u64,
    pub last_src_offset: u64,
    pub stored_path: &'a str,
    pub stored_sha256: &'a str,
    pub stored_bytes: u64,
    pub content_sha256: &'a str,
    pub redacted: bool,
    pub quarantined: bool,
}

pub struct SessionUpsert<'a> {
    pub uuid: &'a str,
    pub project_slug: &'a str,
    pub cwd: Option<&'a str>,
    pub git_branch: Option<&'a str>,
    pub cc_version: Option<&'a str>,
}

/// One artifact's full identity for the GC delete gate, keyed by canonical
/// source path — everything the 5 gates need in a single row.
pub struct GcRow {
    pub id: i64,
    pub session_uuid: String,
    pub source_path: String,
    pub source_sha256: String,
    pub stored_path: String,
    pub stored_sha256: String,
    pub content_sha256: String,
}

/// One artifact's identity for `yomi verify`.
pub struct VerifyRow {
    pub id: i64,
    pub session_uuid: String,
    pub role: String,
    pub stored_path: String,
    pub stored_sha256: String,
    pub content_sha256: String,
}

#[derive(Debug, Default)]
pub struct Counts {
    pub sessions: u64,
    pub artifacts: u64,
    pub redacted: u64,
    pub quarantined: u64,
    pub unverified: u64,
    pub stored_bytes: u64,
}

/// A flagged/allowed finding surfaced by `yomi status --secrets`.
pub struct SecretRow {
    pub session_uuid: String,
    pub source_path: String,
    pub kind: String,
    pub severity: String,
    pub action: String,
    pub secret_sha8: String,
}

impl Catalog {
    pub fn open(path: &Path) -> Result<Self> {
        let conn =
            Connection::open(path).with_context(|| format!("open catalog {}", path.display()))?;
        Self::configure(conn)
    }

    /// Open a fresh in-memory catalog (empty), used by read-side commands and
    /// `--dry-run` when no on-disk catalog exists yet (W1/R8).
    pub fn open_in_memory() -> Result<Self> {
        Self::configure(Connection::open_in_memory()?)
    }

    fn configure(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // Wait rather than fail immediately if another writer holds the db (W4).
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute_batch(include_str!("schema.sql"))
            .context("apply catalog schema")?;
        Ok(Catalog { conn })
    }

    /// Run `f` inside a single transaction, committing on Ok and rolling back
    /// on Err so a crash mid-session leaves the catalog unchanged (B3a).
    pub fn transaction<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        match f() {
            Ok(v) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(v)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    pub fn upsert_session(&self, s: &SessionUpsert) -> Result<()> {
        let now = now_iso();
        self.conn.execute(
            "INSERT INTO sessions (uuid, project_slug, cwd, git_branch, cc_version, first_seen, last_archived)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
             ON CONFLICT(uuid) DO UPDATE SET
                project_slug = excluded.project_slug,
                cwd = COALESCE(excluded.cwd, sessions.cwd),
                git_branch = COALESCE(excluded.git_branch, sessions.git_branch),
                cc_version = COALESCE(excluded.cc_version, sessions.cc_version),
                last_archived = excluded.last_archived",
            rusqlite::params![s.uuid, s.project_slug, s.cwd, s.git_branch, s.cc_version, now],
        )?;
        Ok(())
    }

    /// Prior committed state for an appendable source, if archived before.
    pub fn prior_for_source(&self, source_path: &str) -> Result<Option<Prior>> {
        let row = self
            .conn
            .query_row(
                "SELECT source_sha256, last_src_offset, stored_bytes FROM artifacts WHERE source_path = ?1",
                [source_path],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                },
            )
            .ok();
        Ok(row.map(|(sha, off, sb)| Prior {
            source_sha256: sha,
            last_src_offset: off as u64,
            stored_bytes: sb as u64,
        }))
    }

    /// The full GC row for a canonical source path, if archived. Keyed on the
    /// `UNIQUE` `source_path` column, so at most one row.
    pub fn gc_row_for_source(&self, source_path: &str) -> Result<Option<GcRow>> {
        let row = self
            .conn
            .query_row(
                "SELECT id, session_uuid, source_path, source_sha256, stored_path,
                        stored_sha256, content_sha256
                 FROM artifacts WHERE source_path = ?1",
                [source_path],
                |r| {
                    Ok(GcRow {
                        id: r.get(0)?,
                        session_uuid: r.get(1)?,
                        source_path: r.get(2)?,
                        source_sha256: r.get(3)?,
                        stored_path: r.get(4)?,
                        stored_sha256: r.get(5)?,
                        content_sha256: r.get(6)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Whether the prior capture of this source was ever redacted (sticky).
    pub fn artifact_redacted(&self, source_path: &str) -> Result<bool> {
        let v = self
            .conn
            .query_row(
                "SELECT redacted FROM artifacts WHERE source_path = ?1",
                [source_path],
                |r| r.get::<_, i64>(0),
            )
            .ok();
        Ok(v.map(|n| n != 0).unwrap_or(false))
    }

    pub fn upsert_artifact(&self, a: &ArtifactUpsert) -> Result<i64> {
        let now = now_iso();
        self.conn.execute(
            "INSERT INTO artifacts
                (session_uuid, role, source_path, source_sha256, source_bytes, last_src_offset,
                 stored_path, stored_sha256, stored_bytes, content_sha256, redacted, quarantined, verified_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,NULL,?13)
             ON CONFLICT(source_path) DO UPDATE SET
                session_uuid = excluded.session_uuid,
                role = excluded.role,
                source_sha256 = excluded.source_sha256,
                source_bytes = excluded.source_bytes,
                last_src_offset = excluded.last_src_offset,
                stored_path = excluded.stored_path,
                stored_sha256 = excluded.stored_sha256,
                stored_bytes = excluded.stored_bytes,
                content_sha256 = excluded.content_sha256,
                redacted = excluded.redacted,
                quarantined = excluded.quarantined,
                verified_at = NULL,
                updated_at = excluded.updated_at",
            rusqlite::params![
                a.session_uuid,
                a.role.as_str(),
                a.source_path,
                a.source_sha256,
                a.source_bytes as i64,
                a.last_src_offset as i64,
                a.stored_path,
                a.stored_sha256,
                a.stored_bytes as i64,
                a.content_sha256,
                a.redacted as i64,
                a.quarantined as i64,
                now,
            ],
        )?;
        let id = self.conn.query_row(
            "SELECT id FROM artifacts WHERE source_path = ?1",
            [a.source_path],
            |r| r.get::<_, i64>(0),
        )?;
        Ok(id)
    }

    pub fn replace_findings(&self, artifact_id: i64, findings: &[Finding]) -> Result<()> {
        self.conn
            .execute("DELETE FROM findings WHERE artifact_id = ?1", [artifact_id])?;
        let mut stmt = self.conn.prepare(
            "INSERT INTO findings (artifact_id, kind, severity, secret_sha8, action, span_start, span_len)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
        )?;
        for f in findings {
            stmt.execute(rusqlite::params![
                artifact_id,
                f.kind,
                f.severity.as_str(),
                f.secret_sha8,
                f.action.as_str(),
                f.span_start as i64,
                f.span_len as i64,
            ])?;
        }
        Ok(())
    }

    pub fn counts(&self) -> Result<Counts> {
        let sessions = self
            .conn
            .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get::<_, i64>(0))?;
        let (artifacts, redacted, quarantined, unverified, stored_bytes) = self.conn.query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(redacted),0),
                    COALESCE(SUM(quarantined),0),
                    COALESCE(SUM(CASE WHEN verified_at IS NULL THEN 1 ELSE 0 END),0),
                    COALESCE(SUM(stored_bytes),0)
             FROM artifacts",
            [],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            },
        )?;
        Ok(Counts {
            sessions: sessions as u64,
            artifacts: artifacts as u64,
            redacted: redacted as u64,
            quarantined: quarantined as u64,
            unverified: unverified as u64,
            stored_bytes: stored_bytes as u64,
        })
    }

    pub fn verify_rows(&self) -> Result<Vec<VerifyRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_uuid, role, stored_path, stored_sha256, content_sha256
             FROM artifacts ORDER BY id",
        )?;
        let rows = stmt
            .query_map([], Self::map_verify_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn verify_rows_for_session(&self, uuid: &str) -> Result<Vec<VerifyRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_uuid, role, stored_path, stored_sha256, content_sha256
             FROM artifacts WHERE session_uuid = ?1 ORDER BY id",
        )?;
        let rows = stmt
            .query_map([uuid], Self::map_verify_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn map_verify_row(r: &rusqlite::Row) -> rusqlite::Result<VerifyRow> {
        Ok(VerifyRow {
            id: r.get(0)?,
            session_uuid: r.get(1)?,
            role: r.get(2)?,
            stored_path: r.get(3)?,
            stored_sha256: r.get(4)?,
            content_sha256: r.get(5)?,
        })
    }

    pub fn mark_verified(&self, id: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE artifacts SET verified_at = ?2 WHERE id = ?1",
            rusqlite::params![id, now_iso()],
        )?;
        Ok(())
    }

    /// Findings at or above `min` severity, joined to their artifact source.
    pub fn secret_rows(&self, min: Severity) -> Result<Vec<SecretRow>> {
        let allowed: &[&str] = match min {
            Severity::Low => &["low", "med", "high"],
            Severity::Med => &["med", "high"],
            Severity::High => &["high"],
        };
        let placeholders = allowed
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT a.session_uuid, a.source_path, f.kind, f.severity, f.action, f.secret_sha8
             FROM findings f JOIN artifacts a ON a.id = f.artifact_id
             WHERE f.severity IN ({placeholders})
             ORDER BY f.severity DESC, a.session_uuid"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let params = rusqlite::params_from_iter(allowed.iter());
        let rows = stmt
            .query_map(params, |r| {
                Ok(SecretRow {
                    session_uuid: r.get(0)?,
                    source_path: r.get(1)?,
                    kind: r.get(2)?,
                    severity: r.get(3)?,
                    action: r.get(4)?,
                    secret_sha8: r.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn unverified_sources(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT source_path FROM artifacts WHERE verified_at IS NULL ORDER BY source_path",
        )?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

/// Open the catalog at the env's canonical path, tightening perms to 600.
pub fn open_env(env: &Env) -> Result<Catalog> {
    let path = env.catalog_path();
    let cat = Catalog::open(&path)?;
    Env::chmod_600(&path)?;
    Ok(cat)
}

/// Open the catalog for read-side commands without requiring an initialized
/// store: an existing db is opened as-is; a missing one yields an empty
/// in-memory catalog so `status`/`verify`/`--dry-run` report "nothing archived"
/// instead of erroring on a fresh home (W1/R8).
pub fn open_env_read(env: &Env) -> Result<Catalog> {
    let path = env.catalog_path();
    if path.exists() {
        Catalog::open(&path)
    } else {
        Catalog::open_in_memory()
    }
}
