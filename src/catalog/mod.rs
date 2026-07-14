use crate::archive::incremental::Prior;
use crate::config::Env;
use crate::model::{ArtifactRole, Finding, Severity};
use crate::util::now_iso;
use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, ToSql};
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

/// One artifact to index: identity + session facets (via `sessions` LEFT JOIN).
pub struct IndexCandidate {
    pub artifact_id: i64,
    pub session_uuid: String,
    pub role: String,
    pub source_path: String,
    pub source_sha256: String,
    pub source_bytes: u64,
    pub stored_path: String,
    pub redacted: bool,
    pub project_slug: Option<String>,
    pub cwd: Option<String>,
    pub git_branch: Option<String>,
    pub cc_version: Option<String>,
}

/// The recorded index watermark for one source, consulted by the GC gate.
pub struct IndexStatus {
    pub indexed_source_sha256: String,
    pub indexed_through_offset: u64,
    pub doc_count: u64,
}

/// Roles whose artifacts are index candidates (excludes subagent-meta / scratch).
/// The `quarantined` flag is deliberately NOT a filter here: it is set both for
/// whole-quarantine artifacts (stored = opaque marker) AND for scannable content
/// carrying a HIGH finding that was redacted in place (stored = fully-redacted
/// browsable text — e.g. a transcript with a visible AWS key). Redaction
/// non-exposure is guaranteed structurally by indexing only the decompressed
/// stored bytes (always post-redaction or a marker), never the raw source, so
/// gating on `quarantined` would only make redacted content unsearchable and
/// deny `require_indexed` a watermark for those sources.
const INDEX_ROLES: &str =
    "'transcript','subagent','tool-result','mcp','snapshot','paste','history'";

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

    // ── Index / search (P3) ──────────────────────────────────────────────────

    /// Every index candidate: artifacts of an indexable role (see `INDEX_ROLES`),
    /// with their session facets. `quarantined` is deliberately not a filter —
    /// stored bytes are always post-redaction or an opaque marker, so indexing
    /// them never exposes raw secrets, and gating on it would deny
    /// `require_indexed` a watermark for in-place-redacted sources. Ordered by id
    /// for stable, resumable runs.
    pub fn index_candidates(&self) -> Result<Vec<IndexCandidate>> {
        let sql = format!(
            "SELECT a.id, a.session_uuid, a.role, a.source_path, a.source_sha256, a.source_bytes,
                    a.stored_path, a.redacted, s.project_slug, s.cwd, s.git_branch, s.cc_version
             FROM artifacts a LEFT JOIN sessions s ON s.uuid = a.session_uuid
             WHERE a.role IN ({INDEX_ROLES})
             ORDER BY a.id"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt
            .query_map([], Self::map_candidate)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn index_candidates_for_session(&self, uuid: &str) -> Result<Vec<IndexCandidate>> {
        let sql = format!(
            "SELECT a.id, a.session_uuid, a.role, a.source_path, a.source_sha256, a.source_bytes,
                    a.stored_path, a.redacted, s.project_slug, s.cwd, s.git_branch, s.cc_version
             FROM artifacts a LEFT JOIN sessions s ON s.uuid = a.session_uuid
             WHERE a.role IN ({INDEX_ROLES}) AND a.session_uuid = ?1
             ORDER BY a.id"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt
            .query_map([uuid], Self::map_candidate)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn map_candidate(r: &rusqlite::Row) -> rusqlite::Result<IndexCandidate> {
        Ok(IndexCandidate {
            artifact_id: r.get(0)?,
            session_uuid: r.get(1)?,
            role: r.get(2)?,
            source_path: r.get(3)?,
            source_sha256: r.get(4)?,
            source_bytes: r.get::<_, i64>(5)? as u64,
            stored_path: r.get(6)?,
            redacted: r.get::<_, i64>(7)? != 0,
            project_slug: r.get(8)?,
            cwd: r.get(9)?,
            git_branch: r.get(10)?,
            cc_version: r.get(11)?,
        })
    }

    pub fn insert_entry(&self, d: &crate::index::IndexDoc) -> Result<()> {
        self.conn.execute(
            "INSERT INTO entries
                (entry_uuid, parent_uuid, session_uuid, artifact_id, source_path, role, agent,
                 tool_name, project_slug, cwd, git_branch, cc_version, timestamp, has_redaction,
                 seq, text)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
            rusqlite::params![
                d.entry_uuid,
                d.parent_uuid,
                d.session_uuid,
                d.artifact_id,
                d.source_path,
                d.role,
                d.agent,
                d.tool_name,
                d.project_slug,
                d.cwd,
                d.git_branch,
                d.cc_version,
                d.timestamp,
                d.has_redaction as i64,
                d.seq as i64,
                d.text,
            ],
        )?;
        Ok(())
    }

    pub fn delete_entries_for_artifact(&self, artifact_id: i64) -> Result<usize> {
        Ok(self
            .conn
            .execute("DELETE FROM entries WHERE artifact_id = ?1", [artifact_id])?)
    }

    pub fn delete_entries_for_session(&self, session_uuid: &str) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM entries WHERE session_uuid = ?1",
            [session_uuid],
        )?)
    }

    pub fn delete_all_entries(&self) -> Result<()> {
        self.conn.execute("DELETE FROM entries", [])?;
        Ok(())
    }

    pub fn upsert_index_state(
        &self,
        source_path: &str,
        session_uuid: &str,
        artifact_id: i64,
        indexed_source_sha256: &str,
        through_offset: u64,
        doc_count: u64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO index_state
                (source_path, session_uuid, artifact_id, indexed_source_sha256,
                 indexed_through_offset, doc_count, indexed_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(source_path) DO UPDATE SET
                session_uuid = excluded.session_uuid,
                artifact_id = excluded.artifact_id,
                indexed_source_sha256 = excluded.indexed_source_sha256,
                indexed_through_offset = excluded.indexed_through_offset,
                doc_count = excluded.doc_count,
                indexed_at = excluded.indexed_at",
            rusqlite::params![
                source_path,
                session_uuid,
                artifact_id,
                indexed_source_sha256,
                through_offset as i64,
                doc_count as i64,
                now_iso(),
            ],
        )?;
        Ok(())
    }

    pub fn index_status_for_source(&self, source_path: &str) -> Result<Option<IndexStatus>> {
        let row = self
            .conn
            .query_row(
                "SELECT indexed_source_sha256, indexed_through_offset, doc_count
                 FROM index_state WHERE source_path = ?1",
                [source_path],
                |r| {
                    Ok(IndexStatus {
                        indexed_source_sha256: r.get(0)?,
                        indexed_through_offset: r.get::<_, i64>(1)? as u64,
                        doc_count: r.get::<_, i64>(2)? as u64,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    pub fn delete_index_state_for_session(&self, session_uuid: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM index_state WHERE session_uuid = ?1",
            [session_uuid],
        )?;
        Ok(())
    }

    pub fn delete_all_index_state(&self) -> Result<()> {
        self.conn.execute("DELETE FROM index_state", [])?;
        Ok(())
    }

    /// Run a search. With a non-empty MATCH string, ranks by BM25 and returns a
    /// highlighted snippet; with an empty MATCH (filters only), lists the newest
    /// matching entries. Every facet predicate and the MATCH string are bound
    /// parameters — no query fragment is ever concatenated from user input.
    pub fn query_entries(&self, q: &crate::index::Query) -> Result<Vec<crate::index::Hit>> {
        let f = &q.filters;
        let limit = q.limit as i64;
        let mut params: Vec<(&str, &dyn ToSql)> = vec![
            (":project", &f.project),
            (":session", &f.session),
            (":agent", &f.agent),
            (":role", &f.role),
            (":tool", &f.tool),
            (":branch", &f.branch),
            (":cwd", &f.cwd),
            (":since", &f.since),
            (":until", &f.until),
            (":limit", &limit),
        ];
        const FACETS: &str = "
              AND (:project IS NULL OR e.project_slug = :project)
              AND (:session IS NULL OR e.session_uuid = :session)
              AND (:agent   IS NULL OR e.agent        = :agent)
              AND (:role    IS NULL OR e.role         = :role)
              AND (:tool    IS NULL OR e.tool_name    = :tool)
              AND (:branch  IS NULL OR e.git_branch   = :branch)
              AND (:cwd     IS NULL OR e.cwd          = :cwd)
              AND (:since   IS NULL OR e.timestamp   >= :since)
              AND (:until   IS NULL OR e.timestamp   <  :until)";
        let sql = if q.fts.is_empty() {
            format!(
                "SELECT e.entry_uuid, e.session_uuid, e.project_slug, e.role, e.agent, e.tool_name,
                        e.timestamp, e.has_redaction, substr(e.text, 1, 200), 0.0
                 FROM entries e WHERE 1=1 {FACETS}
                 ORDER BY e.timestamp DESC LIMIT :limit"
            )
        } else {
            params.push((":fts", &q.fts));
            let ctx = q.context_tokens.clamp(1, 64);
            format!(
                "SELECT e.entry_uuid, e.session_uuid, e.project_slug, e.role, e.agent, e.tool_name,
                        e.timestamp, e.has_redaction,
                        snippet(entries_fts, 0, '[', ']', ' … ', {ctx}), bm25(entries_fts)
                 FROM entries_fts JOIN entries e ON e.id = entries_fts.rowid
                 WHERE entries_fts MATCH :fts {FACETS}
                 ORDER BY bm25(entries_fts) LIMIT :limit"
            )
        };
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt
            .query_map(params.as_slice(), Self::map_hit)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn map_hit(r: &rusqlite::Row) -> rusqlite::Result<crate::index::Hit> {
        Ok(crate::index::Hit {
            entry_uuid: r.get(0)?,
            session_uuid: r.get(1)?,
            project_slug: r.get(2)?,
            role: r.get(3)?,
            agent: r.get(4)?,
            tool_name: r.get(5)?,
            timestamp: r.get(6)?,
            has_redaction: r.get::<_, i64>(7)? != 0,
            snippet: r.get(8)?,
            rank: r.get(9)?,
        })
    }

    /// Restore a session's conversational entries in reading order. `agents=false`
    /// keeps only the main transcript; `true` includes subagent transcripts.
    pub fn entries_for_session(
        &self,
        uuid: &str,
        agents: bool,
    ) -> Result<Vec<crate::index::EntryRow>> {
        let agent_clause = if agents { "" } else { "AND agent = 'main'" };
        let sql = format!(
            "SELECT entry_uuid, parent_uuid, role, agent, tool_name, timestamp, has_redaction, text
             FROM entries
             WHERE session_uuid = ?1
               AND role IN ('user','assistant','tool_result','system','summary') {agent_clause}
             ORDER BY COALESCE(timestamp, ''), seq, id"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt
            .query_map([uuid], Self::map_entry_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn entry_by_uuid(
        &self,
        session_uuid: &str,
        entry_uuid: &str,
    ) -> Result<Option<crate::index::EntryRow>> {
        let row = self
            .conn
            .query_row(
                "SELECT entry_uuid, parent_uuid, role, agent, tool_name, timestamp, has_redaction, text
                 FROM entries WHERE session_uuid = ?1 AND entry_uuid = ?2 LIMIT 1",
                [session_uuid, entry_uuid],
                Self::map_entry_row,
            )
            .optional()?;
        Ok(row)
    }

    fn map_entry_row(r: &rusqlite::Row) -> rusqlite::Result<crate::index::EntryRow> {
        Ok(crate::index::EntryRow {
            entry_uuid: r.get(0)?,
            parent_uuid: r.get(1)?,
            role: r.get(2)?,
            agent: r.get(3)?,
            tool_name: r.get(4)?,
            timestamp: r.get(5)?,
            has_redaction: r.get::<_, i64>(6)? != 0,
            text: r.get(7)?,
        })
    }

    pub fn index_meta_get(&self, key: &str) -> Result<Option<String>> {
        let v = self
            .conn
            .query_row("SELECT value FROM index_meta WHERE key = ?1", [key], |r| {
                r.get::<_, String>(0)
            })
            .optional()?;
        Ok(v)
    }

    pub fn index_meta_set(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO index_meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    /// Drop and recreate the FTS vtable with a new tokenizer, then repopulate it
    /// from the current `entries`. Used only on the `--reindex` path. The clause
    /// is a fixed internal string (never user input).
    pub fn rebuild_fts_with_tokenizer(&self, tokenize_clause: &str) -> Result<()> {
        self.conn.execute_batch(&format!(
            "DROP TABLE IF EXISTS entries_fts;
             CREATE VIRTUAL TABLE entries_fts USING fts5(
                 text, content='entries', content_rowid='id', tokenize='{tokenize_clause}');
             INSERT INTO entries_fts(entries_fts) VALUES('rebuild');"
        ))?;
        Ok(())
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
