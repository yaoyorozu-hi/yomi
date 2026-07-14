CREATE TABLE IF NOT EXISTS sessions (
    uuid          TEXT PRIMARY KEY,
    project_slug  TEXT NOT NULL,
    cwd           TEXT,
    git_branch    TEXT,
    cc_version    TEXT,
    first_seen    TEXT NOT NULL,
    last_archived TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id             INTEGER PRIMARY KEY,
    session_uuid   TEXT NOT NULL,
    role           TEXT NOT NULL,
    source_path    TEXT NOT NULL UNIQUE,
    source_sha256  TEXT NOT NULL,
    source_bytes   INTEGER NOT NULL,
    last_src_offset INTEGER NOT NULL,
    stored_path    TEXT NOT NULL,
    stored_sha256  TEXT NOT NULL,
    stored_bytes   INTEGER NOT NULL,
    content_sha256 TEXT NOT NULL DEFAULT '',
    redacted       INTEGER NOT NULL DEFAULT 0,
    quarantined    INTEGER NOT NULL DEFAULT 0,
    verified_at    TEXT,
    updated_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_artifacts_session ON artifacts(session_uuid);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY,
    artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    secret_sha8 TEXT NOT NULL,
    action      TEXT NOT NULL,
    span_start  INTEGER NOT NULL,
    span_len    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_artifact ON findings(artifact_id);

-- ── Index / search (P3) ─────────────────────────────────────────────────────

-- Per-doc index metadata. One row per indexed JSONL entry (transcript/subagent),
-- or one per single-text artifact (mcp/paste/snapshot/history/tool-result). The
-- `text` column derives ONLY from the redacted stored artifact; a raw secret can
-- never reach here (structural invariant, enforced by the indexer reading stored
-- bytes and never source bytes).
CREATE TABLE IF NOT EXISTS entries (
    id             INTEGER PRIMARY KEY,
    entry_uuid     TEXT NOT NULL,
    parent_uuid    TEXT,
    session_uuid   TEXT NOT NULL,
    artifact_id    INTEGER NOT NULL,
    source_path    TEXT NOT NULL,
    role           TEXT NOT NULL,
    agent          TEXT NOT NULL DEFAULT 'main',
    tool_name      TEXT,
    project_slug   TEXT,
    cwd            TEXT,
    git_branch     TEXT,
    cc_version     TEXT,
    timestamp      TEXT,
    has_redaction  INTEGER NOT NULL DEFAULT 0,
    seq            INTEGER NOT NULL DEFAULT 0,
    text           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_session   ON entries(session_uuid);
CREATE INDEX IF NOT EXISTS idx_entries_artifact  ON entries(artifact_id);
CREATE INDEX IF NOT EXISTS idx_entries_entryuuid ON entries(entry_uuid);
CREATE INDEX IF NOT EXISTS idx_entries_ts        ON entries(timestamp);

-- External-content FTS5 over entries.text. The tokenizer here (default
-- unicode61) must match index_meta.tokenizer; changing it requires DROP +
-- recreate + a full reindex, done on the `yomi index --reindex` path.
CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5(
    text,
    content='entries',
    content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);

-- External-content sync triggers (SQLite standard pattern).
CREATE TRIGGER IF NOT EXISTS entries_ai AFTER INSERT ON entries BEGIN
    INSERT INTO entries_fts(rowid, text) VALUES (new.id, new.text);
END;
CREATE TRIGGER IF NOT EXISTS entries_ad AFTER DELETE ON entries BEGIN
    INSERT INTO entries_fts(entries_fts, rowid, text) VALUES('delete', old.id, old.text);
END;
CREATE TRIGGER IF NOT EXISTS entries_au AFTER UPDATE ON entries BEGIN
    INSERT INTO entries_fts(entries_fts, rowid, text) VALUES('delete', old.id, old.text);
    INSERT INTO entries_fts(rowid, text) VALUES (new.id, new.text);
END;

-- Per-source index watermark. The require_indexed GC gate consults this: a
-- source is index-current only if its indexed_source_sha256 equals the artifact's
-- current source_sha256.
CREATE TABLE IF NOT EXISTS index_state (
    source_path            TEXT PRIMARY KEY,
    session_uuid           TEXT NOT NULL,
    artifact_id            INTEGER NOT NULL,
    indexed_source_sha256  TEXT NOT NULL,
    indexed_through_offset INTEGER NOT NULL DEFAULT 0,
    doc_count              INTEGER NOT NULL DEFAULT 0,
    indexed_at             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_index_state_session ON index_state(session_uuid);

-- Index-wide metadata (tokenizer, schema epoch) for reindex-on-change detection.
CREATE TABLE IF NOT EXISTS index_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
