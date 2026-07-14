use serde::{Deserialize, Serialize};

pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const YOMI_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Role of an archived artifact within a session directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactRole {
    Transcript,
    Subagent,
    SubagentMeta,
    ToolResult,
    History,
    Mcp,
    Snapshot,
    Paste,
    ScratchFile,
}

impl ArtifactRole {
    pub fn as_str(self) -> &'static str {
        match self {
            ArtifactRole::Transcript => "transcript",
            ArtifactRole::Subagent => "subagent",
            ArtifactRole::SubagentMeta => "subagent-meta",
            ArtifactRole::ToolResult => "tool-result",
            ArtifactRole::History => "history",
            ArtifactRole::Mcp => "mcp",
            ArtifactRole::Snapshot => "snapshot",
            ArtifactRole::Paste => "paste",
            ArtifactRole::ScratchFile => "scratch-file",
        }
    }

    /// Append-only line-oriented sources are captured incrementally as
    /// newline-aligned zstd frames. Everything else is captured whole.
    pub fn is_appendable(self) -> bool {
        matches!(
            self,
            ArtifactRole::Transcript | ArtifactRole::Subagent | ArtifactRole::History
        )
    }
}

/// One captured zstd frame: the source byte range it compressed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    pub src_offset: u64,
    pub src_len: u64,
    pub captured_at: String,
}

/// Per-artifact secret-scan tally, retained so an incremental run can rebuild
/// the manifest summary by folding every artifact (not just the ones touched).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArtifactScan {
    pub findings: u32,
    pub redacted: u32,
    pub flagged: u32,
    pub quarantined: bool,
}

/// A single stored artifact record inside a manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRecord {
    pub role: ArtifactRole,
    /// Path of the stored artifact, relative to the session archive dir.
    pub path: String,
    /// Absolute source path this was captured from.
    pub source: String,
    /// sha256 of the exact source bytes captured (pre-redaction).
    pub source_sha256: String,
    pub source_bytes: u64,
    /// sha256 of the stored (compressed, possibly-redacted) artifact.
    pub stored_sha256: String,
    pub stored_bytes: u64,
    /// sha256 of the stored artifact's *decompressed* content. `yomi verify`
    /// re-derives this from the store to catch frame-duplication corruption
    /// that a compressed-bytes check would miss.
    pub content_sha256: String,
    pub redacted: bool,
    #[serde(default)]
    pub quarantined: bool,
    #[serde(default)]
    pub scan: ArtifactScan,
    pub frames: Vec<Frame>,
    /// Parsed sidecar (e.g. subagent meta.json), post-redaction — a structured
    /// convenience copy, not a verbatim guarantee.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub parsed_meta: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretScanSummary {
    pub scanned: bool,
    pub findings: u32,
    pub quarantined: bool,
    pub flagged: u32,
    pub redacted: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IncrementalState {
    pub last_src_offset: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prior_capture: Option<String>,
}

/// Per-session archive manifest, written to `manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub session_uuid: String,
    pub project_slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_end: Option<String>,
    pub entry_count: u64,
    pub captured_at: String,
    pub yomi_version: String,
    pub includes: Vec<String>,
    pub artifacts: Vec<ArtifactRecord>,
    pub secret_scan: SecretScanSummary,
    pub incremental: IncrementalState,
}

impl Manifest {
    pub fn new(session_uuid: String, project_slug: String) -> Self {
        Manifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            session_uuid,
            project_slug,
            cwd: None,
            git_branch: None,
            cc_version: None,
            session_start: None,
            session_end: None,
            entry_count: 0,
            captured_at: crate::util::now_iso(),
            yomi_version: YOMI_VERSION.to_string(),
            includes: Vec::new(),
            artifacts: Vec::new(),
            secret_scan: SecretScanSummary::default(),
            incremental: IncrementalState::default(),
        }
    }

    pub fn artifact_by_source(&self, source: &str) -> Option<&ArtifactRecord> {
        self.artifacts.iter().find(|a| a.source == source)
    }
}

/// Severity of a secret-scan detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Med,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Med => "med",
            Severity::High => "high",
        }
    }
}

/// Action taken on a secret-scan finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingAction {
    /// Span replaced with a placeholder in the stored copy.
    Redact,
    /// Redacted in stored copy and unredacted original quarantined.
    Quarantine,
    /// Recorded for human review, not mutated.
    Flag,
    /// Matched an allowlist entry; suppressed entirely.
    Allowed,
}

impl FindingAction {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingAction::Redact => "redact",
            FindingAction::Quarantine => "quarantine",
            FindingAction::Flag => "flag",
            FindingAction::Allowed => "allowed",
        }
    }
}

/// A single secret-scan hit against an artifact's content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub kind: String,
    pub severity: Severity,
    /// First 8 hex chars of sha256(secret) — for dedup/audit, never the secret.
    pub secret_sha8: String,
    pub action: FindingAction,
    pub span_start: usize,
    pub span_len: usize,
}
