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
