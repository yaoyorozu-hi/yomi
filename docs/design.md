# yomi (黄泉) — Claude Code Session-Data Plane — Design

設計: 思兼 (omoikane). 2026-07-12. 対象inventory: `yomi-recon.md` (八咫烏). 吸収対象: `mx codex`.
Status: **DECIDED** — user裁定完 2026-07-12. P1 buildable. Human-facing → natural language.

## 決定事項 (Decisions — user-ratified 2026-07-12)

1. **格納根 = `~/.yomi/`** independent root (override `YOMI_HOME`). §2.
2. **history.jsonl = archive-slice-only, source never wiped.** No live-file compaction. §5.
3. **HIGH secret = redact stored copy + quarantine unredacted original** (recoverable). §4.
4. **scratch = allowlist + size-cap store** (not manifest-only). §3.
5. **codex = frozen read-only vestige — NOT removed.** Freeze writes + import into yomi, but `mx codex read`/`list`/`search` remain available indefinitely for any legacy archives. **No mx subcommand-removal PR.** yomi-side import path unchanged. §7, P5.
6. **quarantine at-rest = mode-700 plaintext (v1);** age/gpg encryption deferred to P6. §4.

黄泉 = the underworld where the dead are preserved and, in time, cleared. Session data descends
to yomi: archived faithfully, then the stale are laid to rest. One static Rust binary. Three
pillars — **archive**, **wipe**, **index/search** — plus **codex absorption**.

---

## 0. Grounding facts (verified on host, not assumed)

- **codex store is empty today.** `mx codex list` → `[]`, `~/.zaibatsu/mx/` empty, no `~/.wonka/vault`.
  → absorption has **near-zero legacy corpus**. Migration is a forward-cutover, not a data conversion. This de-risks P5 dramatically.
- **Real data ≈ 25M** (projects 23M + tmp scratch ~2M ex-clone + MCP logs 2M). Size traps: `versions/` 248M (runtime, never touched), one 134M `/tmp` repo clone (excluded by rule).
- **Transcript = append-only JSONL**, one dir per `projects/<slug>/<uuid>`. Slug = cwd with `/`→`-`.
- Every entry carries `sessionId`, `cwd`, `gitBranch`, `version` (cc), `timestamp`, `userType`, `type`, `uuid`, `parentUuid`. `assistant.message` has `model`, `usage`, content blocks. `subagents/*.meta.json` = `{agentType, description, toolUseId}`.
- Live-session signal: `~/.claude/sessions/<pid>.json` + `~/.local/state/claude/locks/*.lock`.

---

## 1. Component map (what exists, what to build)

| Component | Responsibility |
|---|---|
| `cli` | clap dispatch, global flags, exit codes, `--json` |
| `config` | `YOMI_HOME` resolution, `config.toml`, permission enforcement |
| `blacklist` | compiled-in path denylist (credentials) — checked before any open |
| `source` | discover source artifacts (claude projects, /tmp scratch, history, mcp logs, snapshots) |
| `archive` | manifest + checksum + zstd store + incremental capture |
| `scan` | secret detection → redact / quarantine / flag |
| `catalog` | SQLite registry: sessions, artifacts, checksums, archive+index status, gc audit |
| `index` | search index (SQLite FTS5 v1, `Index` trait, tantivy = future) + query |
| `gc` | archive-verify-then-delete, live-session guard, age policy, /tmp + empty-dir janitor |
| `importer` | ingest codex / wonka archives (idempotent) |
| `lock` | single-writer advisory lock |

---

## 2. Storage — location & layout

### Decision: independent root `~/.yomi/` (override `YOMI_HOME`)

Rejected `~/.zaibatsu/memory/vol/yomi/`. Rationale:
1. Archive corpus grows **unbounded** — must not entangle with curated `vol` artifacts (which may be synced/backed-up; dumping 100s of MB of transcripts there poisons that).
2. yomi is a **secret-aggregation point** → one `chmod 700 ~/.yomi` is a clean, auditable permission boundary at the root.
3. yomi supersedes codex as an **independent plane** — it owns its namespace, not nested under mx's memory tiers.
4. `~/.zaibatsu` is 既管理 (recon). Keeping yomi's large mutable store outside prevents zaibatsu-management tooling from ever touching it.

### Layout

```
~/.yomi/                           # mode 700
  archive/
    <project-slug>/
      <session-uuid>/
        manifest.json              # metadata + checksums + provenance + redaction summary
        transcript.jsonl.zst       # main transcript, zstd (concatenated frames for append)
        subagents/
          <agent-uuid>.jsonl.zst
          <agent-uuid>.meta.json   # {agentType,description,toolUseId} — verbatim
        tool-results/
          <hash>.txt.zst           # content-addressed, dedup by hash
        conversation.md            # derived, human-readable (optional)
        redactions.json            # per-finding: {kind, span, secret_sha8, action}
    _history/<date>.jsonl.zst      # history.jsonl slices (single-file source)
    _mcp/<server>/<date>.jsonl.zst
    _snapshots/<ts>.sh.zst
  quarantine/<session-uuid>/       # mode 700 — unredacted secret-bearing originals; NOT indexed
  index/                           # FTS5 db (or tantivy dir)
  state/
    catalog.db                     # SQLite (mode 600)
    gc.log                         # append-only wipe audit (natural-language lines)
  config.toml                      # mode 600
  yomi.log
```

**Keyed by `session-uuid`, not date.** Date is derived metadata (manifest + index), not a directory
level. A session spanning midnight stays one dir; idempotency and cross-refs use the stable UUID.
Date-based *views* come from the index; age-based *GC* queries the catalog, never a date-partitioned
FS walk. `_history/_mcp/_snapshots` are the only date-partitioned stores (single-file sources with no UUID).

### Fidelity: raw source-of-truth, derived everything else

- **`source_sha256`** = hash of the original `~/.claude` file **as read** (pre-any-transform). Proves "we captured exactly this source." This is the value the wipe layer verifies against.
- **`stored_sha256`** = hash of the compressed stored artifact. Proves archive integrity (`yomi verify`).
- `transcript.jsonl.zst` is byte-faithful to source **except** redaction (§4) — the one transformation, because storing a verbatim secret in the aggregation point defeats the security goal. When redaction fires, the unredacted original goes to `quarantine/` (recoverable); the browsable/indexed copy is redacted.
- `conversation.md`, index docs → all **derived** from the stored artifact, never authoritative.

### Manifest schema

```json
{
  "schema_version": 1,
  "session_uuid": "…", "project_slug": "-home-yhi", "cwd": "/home/yhi",
  "git_branch": "main", "cc_version": "2.1.207",
  "session_start": "ISO", "session_end": "ISO", "entry_count": 1234,
  "captured_at": "ISO", "yomi_version": "0.1.0",
  "includes": ["transcript","subagents","tool-results"],
  "artifacts": [
    { "role": "transcript",
      "path": "transcript.jsonl.zst",
      "source": "/home/yhi/.claude/projects/-home-yhi/<uuid>.jsonl",
      "source_sha256": "…", "source_bytes": 0,
      "stored_sha256": "…", "stored_bytes": 0,
      "redacted": false,
      "frames": [ { "src_offset": 0, "src_len": 0, "captured_at": "ISO" } ] }
  ],
  "secret_scan": { "scanned": true, "findings": 0, "quarantined": false, "flagged": 0 },
  "incremental": { "last_src_offset": 0, "prior_capture": "ISO" }
}
```

### Incremental / idempotent capture

Transcripts append-only → two-level idempotency:
1. **Session-level.** Catalog holds `last_src_offset`, `source_sha256`, `source_bytes` per artifact.
   On re-archive:
   - source `sha` unchanged → **skip** (no-op).
   - source grew, first `last_src_offset` bytes hash-match prior → capture **tail only**, append a
     new **zstd frame** (zstd reads concatenated frames transparently), update offset. O(delta) write.
   - prefix diverged (rewrite/rotation) → re-capture whole, new version, keep prior under `.v<n>`.
2. **Content-addressed.** `tool-results/*.txt` are already hash-named → dedup by hash across increments.

Frame proliferation hurts ratio slightly; **compaction** (rewrite to single frame) runs opportunistically during GC.

---

## 3. Source discovery & size traps

`source` module walks a fixed, config-tunable set. **Never** globs `~/.claude/*` blindly.

| Source | Archive? | Rule |
|---|---|---|
| `projects/<slug>/<uuid>.jsonl` | yes | primary transcript |
| `projects/**/subagents/*.jsonl`+`*.meta.json` | yes | folded ref in manifest |
| `projects/**/tool-results/*.txt` | yes | content-addressed |
| `history.jsonl` | yes | slice → `_history/`; **source never wiped** (live single file) |
| `~/.cache/claude-cli-nodejs/**/mcp-logs-*/*.jsonl` | yes | → `_mcp/`; LOW-MED |
| `shell-snapshots/*.sh` | yes | → `_snapshots/`; **secret scan mandatory** (env dump) |
| `paste-cache/*.txt` | yes | MEDIUM |
| `/tmp/claude-1007/<slug>/<uuid>/scratchpad/**` | **manifest-only default** | see below |
| `/tmp/claude-1007/<slug>/<uuid>/tasks/*.output` | yes | small task output |
| `~/.local/share/claude/versions/` (248M) | **never** | runtime binary — not session data |
| `.credentials.json`, `.claude.json`(+backups), `mcp-needs-auth-cache.json` | **never** | hard blacklist §4 |
| `~/.zaibatsu/**` | **never** | 既管理 |
| `sessions/<pid>.json`, `locks/*.lock` | **never** archive | consumed as live-session signal §5 |

### Scratch (the 134M trap)

Scratch is a working checkout, not "output." Default: **capture a scratch manifest** (file list +
sizes + hashes), **store contents only for an allowlist under a size cap**:

```toml
[scratch]
allow  = ["*.md","*.txt","*.json","*.output","*.log","*.csv","*.sh","*.py"]
deny   = [".git/**","node_modules/**","target/**","**/*.{mp4,zip,tar,iso,bin}"]
file_cap  = "5MB"    # any single file over cap → listed, not stored
total_cap = "20MB"   # whole scratch over cap → manifest-only + flag
```

The 134M cloned repo → excluded by `deny` + `total_cap`, but its existence is recorded in the scratch
manifest. Nothing about it is lost except bytes we deliberately declined to hoard.

---

## 4. Sensitive data (security core)

### Hard blacklist — compiled-in, checked before any `open()`

Path-exact + glob, non-overridable by config (config may **add**, never remove):
- `~/.claude/.credentials.json` (raw OAuth tokens)
- `~/.claude.json`, `~/.claude/backups/*.backup.*` (oauthAccount block)
- `~/.claude/mcp-needs-auth-cache.json`
- `~/.zaibatsu/**`
- `~/.local/share/claude/versions/**`, `~/.local/state/claude/locks/**`

A blacklisted path is never opened for read **or** delete. Test-proven in CI (P1 gate).

### Secret scan pass (on everything archived)

Runs on the **content** of every archived artifact — for JSONL, every string field of every entry
(user content, tool_result text, assistant text blocks, snapshot env lines).

**Detectors** (config-extensible ruleset, severity-tagged):

| Kind | Pattern | Severity |
|---|---|---|
| AWS key | `A(KIA|SIA)[0-9A-Z]{16}` | HIGH |
| Private key block | `-----BEGIN [A-Z ]*PRIVATE KEY-----` … `END` | HIGH |
| GitHub token | `gh[pousr]_[A-Za-z0-9]{36}`, `github_pat_…` | HIGH |
| Slack | `xox[baprs]-…` | HIGH |
| OpenAI/Anthropic | `sk-[A-Za-z0-9]{20,}`, `sk-ant-…` | HIGH |
| Google API | `AIza[0-9A-Za-z_-]{35}` | HIGH |
| JWT | `eyJ[A-Za-z0-9_-]+\.eyJ…\.…` | MED |
| Bearer / generic entropy | `(?i)bearer\s+…`, ≥40-char base64 in key-ish context | LOW |

Recon flagged **2 transcripts** hitting PRIVATE KEY / AKIA patterns — these are the HIGH cases the scan must catch.

**Action model — scan → decide → act → record:**

- **HIGH** finding → redact span in stored copy with `‹REDACTED:kind:sha8›` (sha8 = hash of the secret, for dedup/audit, **never the secret**) **and** move the unredacted original to `quarantine/<uuid>/` (mode 700, index-excluded). Recoverable if false positive.
- **MED** → redact in stored copy, no quarantine.
- **LOW** → **flag only** in `manifest.secret_scan.flagged`, surfaced via `yomi status --secrets` for human review. Not redacted (too FP-prone to auto-mutate on entropy alone).
- **Allowlist** `[scan.allow]` (regexes / secret-sha8s of known-benign, e.g. doc example keys) suppresses a finding entirely.

Raw secrets **never** reach the index or `conversation.md` — those derive from the already-redacted stored artifact.

### Permission model

`~/.yomi` + `quarantine/` = 700; `catalog.db` + `config.toml` = 600; restrictive umask on all writes.
Startup **refuses to run** (exit 3) if `~/.yomi` perms are looser than 700 (`--fix-perms` to correct).

---

## 5. Wipe / GC

### Absolute law: archive-verify-then-delete

No deletion path exists that isn't gated on a verified archive. Per source file:

1. Look up archive artifact by source path + `source_sha256` in catalog.
2. **Recompute live source `sha256`.**
3. Require **all**: catalog artifact with `source_sha256 == live_sha` **AND** `stored_sha256` re-verifies (re-hash stored file) **AND** (if `require_indexed`) index status = indexed.
4. **AND** file age ≥ `min_age` **AND** session not live (§below).
5. Only then delete source. Append to `gc.log`: source, source_sha, archive_id, verified checks, deleted_at.

Any check fails → **skip**, mark `unverified` in status. Never delete on doubt.

### Live-session protection

- Parse `~/.claude/sessions/<pid>.json` → active session UUIDs + cwd; confirm liveness via `/proc/<pid>`.
- Consult `~/.local/state/claude/locks/*.lock`.
- A transcript is **protected** if: its `sessionId` ∈ active set, OR mtime within `active_window` (default 1h), OR age < `min_age`.
- yomi holds its own advisory lock during GC; refuses concurrent runs.

### Policy (config)

```toml
[gc]
min_age          = "7d"    # hard floor — nothing younger is ever touched
transcript_retain = "90d"  # delete source older than, once archived+verified
scratch_retain   = "3d"
mcp_log_retain   = "14d"
paste_retain     = "14d"
snapshot_retain  = "30d"
history_compact  = false   # default: archive history slices, NEVER wipe live file
require_indexed  = true
```

### Special targets

- **history.jsonl** — single live append-only file. Archive **slices** by timestamp watermark; source truncation is OFF by default (`history_compact=false`) — rewriting a file CC may be appending to is unsafe. Archive-only, never wipe, unless user opts in.
- **Empty-dir shells** (`session-env/`, `tasks/` — 65 empty dirs, recon). Pure janitor: `yomi gc --targets empty-dirs` removes empty dirs not owned by a live session. Zero data → no archive needed.
- **`/tmp/claude-1007/**`** scratch — GC removes scratch dirs whose session is not-live AND archived-or-manifested AND older than `scratch_retain`. Reclaims the 134M clone.
- **paste-cache / shell-snapshots** — archive (scan applies) then age-GC.

### Dry-run is the default

`yomi gc` **prints the plan and does nothing.** Requires `--commit` to act. Plan shows, per item:
would-delete / why-safe (checks passed) / bytes reclaimed, and protected items with the reason.

---

## 6. Index / Search

### Engine: SQLite FTS5 (v1), behind an `Index` trait; tantivy = measured-need upgrade

Justification in §9. Catalog is already SQLite → one dependency, one file, no server; FTS5/BM25 is
ample for a 25M→low-GB corpus. `trait Index { fn upsert(docs); fn query(q,filters)->hits; fn delete(session); }`
lets tantivy slot in later without touching callers.

### Document granularity: per-entry (per JSONL message)

One index doc per user/assistant/tool-result entry → precise hits + jump-back. Fields:

| Field | Type | Use |
|---|---|---|
| `session_uuid`, `project_slug`, `cwd`, `git_branch`, `cc_version` | stored/filter | facets |
| `timestamp` | filter | range (`--since/--until/--on`) |
| `role` | filter | user / assistant / tool_result / system |
| `agent` | filter | `main` or subagent `agentType` |
| `tool_name` | filter | Bash / Edit / … (from tool_use/result) |
| `entry_uuid`, `parent_uuid` | stored | threading, `yomi read --entry` |
| `text` | **FTS** | user prompt / assistant text / tool_result text |
| `has_redaction` | filter | bool |

Redacted spans index as the placeholder token — raw secrets never indexed.

### Query CLI

```
yomi search <query> [--project P] [--session U] [--agent A] [--role R] [--tool T]
                    [--branch B] [--cwd C] [--since D] [--until D] [--on D]
                    [--limit N] [--context N] [--json]
```

Inline `field:value` in the query also parses to filters: `project:zaibatsu tool:Bash "cargo build"`.
Output: ranked highlighted snippet + header (`session · timestamp · project · agent`) + jump ref
(`yomi read <uuid> --entry <entry_uuid>`).

### Incremental index

Catalog tracks `indexed_through_offset` per session; `yomi index` (auto post-archive) indexes only
new entries. `--reindex` rebuilds on schema change. Built from the **redacted stored artifact**.

---

## 7. mx codex absorption

### Compatibility

- codex archives derive from the **same** `~/.claude/projects` JSONL yomi reads. Cleanest import =
  **re-ingest from original source**, not convert codex's derived `conversation.md`. Original present
  → normal pipeline (uuid-keyed, idempotent). Original gone but codex archive present → parse codex
  `conversation.md` + `manifest.json` into entries, flagged `degraded` (lossy).
- `yomi import --from-codex [PATH]` / `--from-wonka [PATH]` = the `--backfill` equivalent. Walks codex
  storage / wonka `session-*` snapshots, feeds each through the archive pipeline. Idempotent.
- **Non-overlap with mx memory/kv confirmed.** yomi touches only session transcript / ephemeral data.
  `mx memory` (SurrealDB graph) and `mx kv` (state) are a different data class (curated knowledge) —
  **out of yomi scope, untouched.** Only mx's `codex` subcommand is deprecated; mx keeps memory, kv, git, worktree, sync.

### Migration order (phased coexistence)

1. **Parallel** — yomi archives forward; codex still callable. Both read same source, both idempotent, different stores → no conflict.
2. **Freeze writes** — stop invoking `mx codex archive` (remove from shutdown skill / hooks). codex `read`/`list`/`search` stay for any old archives.
3. **Import** — `yomi import --from-codex` (near-empty today → seconds).
4. **Cutover** — shutdown skill + hooks call `yomi archive`; new search tooling points to `yomi search`.
5. **Frozen vestige (decided §5)** — `mx codex` is **not removed**. Its write path (`archive`) is dormant once hooks stop calling it; `read`/`list`/`search` remain available **indefinitely** as read-only access to any legacy archives. **No mx subcommand-removal PR.** mx decomposition (事業 kv-3HSjJj) may retire it on its own timeline, independent of yomi.

Because the codex store is **empty today**, steps 2–4 collapse into one cutover with negligible import risk. yomi never depends on codex removal; the two coexist permanently, codex passive.

---

## 8. CLI surface

```
yomi archive [--all | --session <uuid> | PATH] [--include transcript,subagents,tool-results,history,mcp,scratch,all]
             [--no-scan] [--quarantine-on-secret] [--dry-run]
yomi gc      [--targets transcripts,scratch,mcp,empty-dirs,paste,snapshots] [--commit] [--min-age D]   # dry-run default
yomi search  <query> [filters…]
yomi index   [--reindex] [--session <uuid>]
yomi read    <session-uuid> [--entry <uuid>] [--agents] [--grep P] [--human|--raw]
yomi list    [--project P] [--since D] [--json]
yomi status  [--secrets] [--unverified] [--storage]
yomi verify  [<uuid> | --all]
yomi import  --from-codex [PATH] | --from-wonka [PATH]
yomi config  [get|set|path]
yomi run     --profile daily          # composite: archive --all && index && gc --commit
```

Global: `--home <dir>` (`YOMI_HOME`), `--config <path>`, `--json`, `-v`.
Exit codes: `0` ok · `1` error · `2` partial (items skipped/unverified) · `3` refused (perm/lock/safety).

### Cron / scheduled

`yomi run --profile daily` is idempotent + lock-guarded → safe hourly/daily. Emits `--json` summary
(counts: archived, indexed, deleted, reclaimed-bytes, secret-flags, unverified) for 千里眼 (senri) monitoring.

---

## 9. Repo: yaoyorozu-hi/yomi

### Crate structure (single binary)

```
yomi/
  Cargo.toml
  src/
    main.rs                 # clap dispatch
    cli/                    # per-subcommand handlers
    config.rs               # YOMI_HOME, config.toml, perm enforcement
    blacklist.rs            # compiled path denylist
    model.rs                # Entry, Session, Manifest, Finding (serde)
    lock.rs                 # advisory single-writer lock
    source/  {mod, claude, tmp, history, mcp, snapshots}.rs
    archive/ {mod, manifest, fidelity, incremental, compress}.rs   # zstd frames
    scan/    {mod, rules, redact, quarantine}.rs
    catalog/ {mod.rs, schema.sql}                                  # rusqlite
    index/   {mod, ftsindex, query}.rs   (trait Index; tantivy.rs future)
    gc/      {mod, safety, policy, live}.rs
    importer/{mod, codex, wonka}.rs
  tests/fixtures/           # sample jsonl, secret-laden fixture, codex archive sample
```

### Dependencies

`clap`(derive) · `serde`+`serde_json`+`toml` · `zstd` · `rusqlite`(bundled, FTS5) · `sha2` ·
`regex`+`aho-corasick` · `walkdir`+`globset` · `chrono` · `anyhow`/`thiserror` · `tracing`(+subscriber) ·
`fs2`/`nix`(lock, /proc) · `rayon`(opt, parallel scan). Future: `tantivy`. Mirror mx crate conventions (follow-up: read mx repo for shared style/lint config).

### CI

`fmt` · `clippy -D warnings` · `test` · `cargo-deny`/`audit` · static musl build · mise integration.
Load-bearing fixtures: secret-scan **must** catch AKIA/PRIVATE KEY; double-archive = no-op; wipe **refuses** on checksum mismatch and on live session.

### Phases (each with a hard done-when)

- **P1 — Archive + blacklist + fidelity** (foundational). Source(claude) + manifest/checksum + zstd store + hard blacklist + incremental(offset/sha) + catalog.
  *Done:* `yomi archive --all` captures transcripts+subagents+tool-results byte-faithfully; re-run no-op; blacklisted paths provably never opened; `yomi verify` passes.
- **P2 — Secret scan + quarantine** (security gate, precedes any wipe). Detectors, redact, quarantine, severity/allowlist, `status --secrets`.
  *Done:* fixture secrets caught+redacted; raw secret never in stored artifact or index (test); FP allowlist works; the 2 known recon-flagged transcripts handled.
- **P3 — Wipe / GC** (gated on P1+P2). archive-verify-then-delete, live detection, age policy, dry-run default, /tmp + empty-dir janitor, `gc.log`.
  *Done:* deletes only verified+aged+non-live; refuses on any mismatch (test); dry-run shows plan; reclaims the 134M scratch clone + 65 empty dirs.
- **P4 — Index + search.** FTS5, per-entry docs, filters, incremental index, `search`/`read`.
  *Done:* ranked filtered results; incremental index no dup; redacted-only content.
- **P5 — Codex absorption + cutover.** importer, freeze codex writes, hook/shutdown rewire. **No mx changes** — codex left as frozen read-only vestige (decided §5).
  *Done:* `import --from-codex` idempotent; `mx codex archive` no longer invoked by hooks; hooks call `yomi archive`; `mx codex read/list/search` still function untouched.
- **P6 — Ops.** `run --profile daily`, `status --storage`, senri JSON hook, documented tantivy upgrade trigger.

---

## 10. Reverse-audit — is Rust + tantivy over-engineering for 25M?

- **Rust: justified independent of scale.** mx ecosystem is Rust; single static binary is the deploy
  model; this tool runs on **cron, unattended, adjacent to credentials, and deletes files** — that is
  precisely where you want a memory-safe compiled binary with no runtime deps, not a shell/python
  janitor. Byte-faithful checksummed archival + safe deletion demand the correctness Rust gives. **Keep.**
- **tantivy: NOT justified at v1 — reduce.** 25M today, 10× growth = 250M; SQLite FTS5/BM25 handles
  that trivially with zero extra infra (catalog is already SQLite). tantivy buys relevance/faceting/fuzzy
  the "grep my own history" use-case doesn't need yet, at the cost of a heavy dep + index lifecycle.
  → **v1 = FTS5 behind `Index` trait; tantivy on measured need** (index >2GB, FTS5 query p95 >200ms, or a real faceting/fuzzy requirement).
- **Growth is real but the design caps it.** Transcripts grow unbounded, but P3 GC caps the *source*
  footprint and zstd (~5–10×) keeps the store small. The dominant value is (1) never losing history and
  (2) safely reclaiming disk — both P1–P3, not search sophistication. yomi is a **safety-critical
  janitor with an archive**, not a search engine. Scope search modestly, invest in the wipe safety proofs.

---

## 11. Open questions

All six resolved — see **決定事項 (Decisions)** at top. No open items requiring user decision. Design is settled for P1 build.
