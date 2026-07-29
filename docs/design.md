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
| `rescan` | retroactive re-redaction of the existing store against the hardened scanner (P3.5) |
| `importer` | ingest codex / wonka archives (idempotent) — **P4, not yet built** |
| `lock` | single-writer advisory lock, dual-anchor (lock file + store directory) — §4 |

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
  .yomi-store                      # marker: proves this dir is a yomi store (guards --fix-perms)
  archive/
    <project-slug>/
      <session-uuid>/
        manifest.json              # metadata + checksums + provenance + redaction summary
        transcript.jsonl.zst       # main transcript, zstd (concatenated frames for append)
        subagents/
          <agent-uuid>.jsonl.zst
          <agent-uuid>.meta.json   # {agentType,description,toolUseId} — redacted-if-needed, else verbatim
        tool-results/
          <name>.txt.zst           # content-addressed, dedup by hash
        conversation.md            # derived, human-readable (P4)
        redactions.json            # per-finding: {kind, span, secret_sha8, action} (P2 sidecar; P1 keeps this in manifest.secret_scan + catalog.findings)
    _history/history.jsonl.zst     # history.jsonl — single incremental store (P1); date-partitioned views come from the index (P4)
    _mcp/<server>/<name>.jsonl.zst # one store per mcp log file (whole-file, idempotent)
    _snapshots/<name>.sh.zst
    _paste/<name>.txt.zst          # paste-cache
    _scratch/<slug--uuid>/         # scratch: manifest.json (every file) + allow-listed stored files
  quarantine/<session-uuid>/<rel>  # mode 700 — unredacted originals, keyed by artifact rel-path; NOT indexed
                                   # (no `index/` directory: the shipped FTS5 index lives
                                   #  inside state/catalog.db — §6. A tantivy upgrade would
                                   #  add index/ here.)
  state/
    catalog.db                     # SQLite (mode 600) — sessions, artifacts, findings
  gc.log                           # append-only wipe audit (P2), mode 600 — at the store root
  config.toml                      # mode 600
  .yomi.lock                       # advisory single-writer lock — first anchor; the store
                                   # directory itself is the second (§4 Single-writer lock)
```

**P1 layout notes (reconciled to implementation):**
- **`_history` is a single incremental store**, not date-sliced: the byte-offset watermark *is* the slice watermark (source is never wiped; §5). Date-partitioned *views* are an index concern (P4).
- **`_paste/` and `_scratch/`** join the date/name-partitioned single-file stores; `_scratch/<key>/` holds a `manifest.json` of every scratch file plus the allow-listed, under-cap files.
- **Quarantine is keyed by the artifact's rel-path** (`quarantine/<uuid>/<rel>`), not basename, so same-named originals from different sources cannot clobber each other.
- **No `.v<n>` rotation in P1.** A prefix-divergence or corruption-triggered recapture overwrites the store in place (atomic temp-write + rename). This avoids untracked orphan versions and eliminates any stale, pre-redaction copy as a leak surface; catalog-tracked versioning is deferred to P3.

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
   - prefix diverged (rewrite/rotation) → re-capture whole, overwriting the store in place
     (atomic temp-write + rename). **No `.v<n>` rotation in P1** — see the P1 layout notes above;
     catalog-tracked versioning is deferred to P3.
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
| `/tmp/claude-1007/<slug>/<uuid>/**` (whole tree) | manifest **+ allowlist-under-cap store** | decision #4; the enumerated set must equal what the deleter removes — see below |
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

**Over-cap is manifest-only, and the manifest says so.** When the tree total exceeds `total_cap`,
nothing is stored and **every** entry is written `stored: false`, with `over_total_cap: true`
recording why. That is what makes the tree reclaimable: a `stored: false` entry takes the GC gate's
size-only path (check 4 — presence and size must still match the manifest), whereas a `stored: true`
entry with no `.zst` and no hashes reads to the gate as a corrupt archive and refuses the whole tree.
The writer used to emit exactly that contradiction, so the 134M clone the cap exists for was
**permanently** unreclaimable — no number of archive/GC cycles helped, because re-archiving
regenerated the identical manifest.

**Consequence, accepted deliberately.** Reclaiming an over-cap tree therefore deletes data that was
never archived: the store holds zero bytes of it, and the only remaining guard is the size match of
check 4. This is decision #4 taken to its conclusion — "whole scratch over cap → manifest-only +
flag", "nothing about it is lost except bytes we deliberately declined to hoard" — so the tree's
*existence and shape* survive in the manifest while its *contents* do not. Second-order effect of the
same rule: an allow-listed file that would have been stored individually is **not** stored, and is
deleted with the rest, once the tree as a whole goes over the cap. The trade is per-tree, not
per-file.

**Scratch path identity is byte-valued, and one module owns it.** `src/scratch.rs` owns `ScratchRel`
— the identity of one scratch file relative to its session dir — and every layer goes through it: the
*writer* (archive), the *reader* (the GC gate), the *deleter*, `yomi read --scratch` and
`yomi verify`. `ScratchRel` is a newtype over the **raw relative path bytes** (`OsStr` bytes, never
`to_string_lossy`), with exactly these operations:

| Operation | Contract |
|---|---|
| `from_live(session_dir: &Path, path: &Path) -> Option<ScratchRel>` | strip `session_dir`; `None` if `path` is not a descendant |
| `as_bytes(&self) -> &[u8]` | the **sole** identity — equality, hashing, map keys, manifest lookup |
| `to_rel_path(&self) -> &Path` | relative path, for joining to a live session dir or a store dir |
| `glob_subpath(&self) -> Cow<'_, str>` | the string the `[scratch]` allow/deny globs match |
| `store_rel(&self) -> PathBuf` | `<rel>.zst`, resolved under `archive/_scratch/<key>/` |
| `manifest_fields(&self) -> (String, Option<String>)` | `(path, path_hex)` — `path` is the lossy display form; `path_hex` is lowercase hex of the raw bytes, emitted **only** when those bytes are not valid UTF-8 |
| `from_manifest(path: &str, path_hex: Option<&str>) -> Option<ScratchRel>` | `path_hex` wins when present, else `path`'s bytes; `None` if neither decodes |

Hex, not base64: `util.rs` already carries a `hex` encoder for `sha256_hex` and needs only a decoder
companion, whereas base64 would add a dependency to `cargo-deny`'s surface for a field that is emitted
only for the pathological name. Hex has one alphabet, no padding and no URL-safe variant to confuse.

`ScratchManifest` / `ScratchEntry` are defined **once**, `Serialize + Deserialize`, in that same
module. The writer and the GC gate previously carried two independent struct definitions — one
serialize-only in `archive`, one deserialize-only in `gc::safety` — which could drift silently. They
cannot now.

`path_hex` is additive: a manifest written before it existed has no such field, `from_manifest` falls
back to `path`, and every ASCII/UTF-8 name (the entire real population) round-trips byte-identically.
Two distinct non-UTF-8 names no longer collapse to one `U+FFFD` key, so their stored `.zst` can no
longer overwrite each other and their trees are no longer refused forever.

**Enumeration is the whole session dir.** The deleter removes `<slug>/<uuid>/` entire, so the writer
must consider `<slug>/<uuid>/` entire. `scratchpad/` and `tasks/` stop being enumeration roots and
become ordinary path prefixes: `ScratchRel` for `<uuid>/scratchpad/a.md` is `scratchpad/a.md`, for
`<uuid>/tasks/a.output` is `tasks/a.output` — byte-identical to what the narrow writer already
emitted, so **existing manifests stay valid with no conversion**. The widening only *adds* keys. A
`tasks/notes.txt`, or anything dropped directly in `<uuid>/`, is now manifested (with `stored` decided
by the allow/deny globs and the caps like any other file) instead of being unmanifested and refusing
the tree forever. This supersedes the `tasks/*.output`-only rule in the source table above: extension
filtering moves entirely into the `[scratch]` allow/deny globs, where it is configurable and where the
same rules already govern `scratchpad/**`. A hardcoded second filter in the enumerator was the reason
the three layers could disagree at all.

Globs continue to match the session-relative path. `build_globs_nested` already registers `**/<p>`
alongside each `<p>`, so the default `allow`/`deny` sets keep matching at every depth; the depth
matrix is a required test, not an assumption.

Consequence, stated because it is visible: `total_bytes` now counts the whole tree, so a tree that sat
just under `total_cap` may go over it and become manifest-only. That is the cap measuring what will
actually be deleted, which is what it was always meant to measure.

**Store law (S) — the store dir and the manifest are one ledger.** For a scratch key `<K>`:

> the set of `*.zst` under `archive/_scratch/<K>/` is **exactly** the set of `store_rel()` of the
> manifest's `stored: true` entries, and each one decompresses to its entry's `content_sha256`.

`archive` establishes S. `yomi verify` checks S. The GC gate's per-entry store re-check is a
*consequence* of S, not an independent claim. Nothing but `archive` writes into a scratch store dir.

**Reconciliation — the one delete authority `archive` holds.** Establishing S means archive removes
`*.zst` under `archive/_scratch/<K>/` that the manifest it just wrote does not claim. The authority is
bounded and enumerable: only `*.zst`, only under that one key's store dir, never `manifest.json`,
never `quarantine/` (a quarantined raw original stays recoverable), never any path outside
`archive/_scratch/`. `--dry-run` reports the removals instead of performing them, and the run report
carries `scratch_orphans_removed` so a config change that discards stored bytes is loud, not silent.

Without reconciliation the store and the manifest drift apart on any policy change, silently and
unrecoverably-in-practice: archive under `total_cap = "1MB"`, lower it to `"1KB"`, re-archive — the
previous run's `.zst` stay on disk while the new manifest declares `over_total_cap: true` and every
entry `stored: false`. The store holds a faithful copy that yomi's own ledger denies. GC then deletes
the live tree on the size-only path. The bytes survive; their **retrievability** does not, and a
ledger that denies its own store is worse than one that stores nothing.

**A vanished file keeps its archive.** Reconciliation applies policy to files that are *still live*.
An entry whose live file is gone since the last run is **retained verbatim** — `stored`, both hashes,
and its `.zst` — and marked `present: false` (`#[serde(default)]` → `true`, so old manifests read
unchanged). Purging it would destroy the only remaining copy, which no cap decision authorizes: the
caps say "do not hoard *this tree*", not "destroy what you already took". A retained entry is not part
of the live tree, so it is excluded from `total_bytes` and from the cap. The GC gate is unaffected —
it walks live files and looks each one up; extra manifest entries match nothing. If a file with the
same `ScratchRel` reappears with different bytes, the size/sha check fails and the tree is refused,
which is correct.

**Over-cap, restated under S.** A tree over `total_cap` writes every *live* entry `stored: false`,
stores no bytes, sets `over_total_cap: true`, and reconciliation removes those live entries' `.zst`.
Retained `present: false` entries are untouched. Decision #4 is honoured for the live tree; no
archive-only copy is destroyed by a cap change.

**Why the scratch manifest does not merge its predecessor — unlike a session manifest.** A session
manifest merges prior records because its sources are append-only and captured *incrementally*: an
artifact untouched this run was genuinely captured in an earlier one and must keep its provenance. A
scratch tree has no incremental capture — it is re-enumerated whole on every run — so a blanket merge
would import stale claims about files whose policy or content has since moved, and would in fact
*mask* the orphan drift above by keeping a `stored: true` entry alive for a `.zst` that no longer
belongs. The asymmetry is deliberate and stays. Retention of vanished-file entries is the one narrow
merge, and it is justified by "do not destroy the last copy", not by provenance.

### Scratch is archived, not disposable: the read and verify paths

GC deletes a scratch tree because the archive covers it. An archive with no retrieval path and no
integrity check is not an archive, so the coverage claim has to be exercisable:

- **`yomi read <session-or-key> --scratch`** — with no `--file`, lists the manifest (rel path, bytes,
  `stored`, `present`, `over_total_cap`, sha8s). With `--file <rel>`, writes that entry's decompressed
  stored bytes to stdout. Detailed in §8.
- **`yomi verify`** — a scratch pass over every `archive/_scratch/*/`, checking law S. Detailed in §5.

**Redaction non-exposure is structural, exactly as it is for the index (§6).** A scratch `.zst` holds
`scan.redacted` as of capture: either in-place-redacted text or the opaque `‹QUARANTINED:…›` marker.
The read path decompresses that `.zst` and emits nothing else — it never reads the live source, never
reads `quarantine/`, and never re-derives content from anything but the stored bytes. Non-exposure
therefore does not depend on the read path making a decision; there is no input from which a raw
secret could reach it.

**Path traversal is structural too.** `--file <rel>` is matched against the manifest's `ScratchRel`
values; the path actually opened is derived from the **matched entry**, never by joining user input to
the store dir. An unmatched value is "not found" — there is no code path that turns
`--file ../../../etc/passwd` into an open.

**Cross-user boundary unchanged.** Neither `read --scratch` nor the verify pass enumerates users,
resolves foreign roots, or accepts a `--discover-all-users`-shaped flag. They operate on
`env.archive_dir()` — the store the invocation already targets — and nothing else.

**Known gap, deliberately out of this scope: scratch is not catalog-registered.** `archive_scratch`
writes no `artifacts` row, so scratch stored bytes are absent from `status --storage`, scratch has no
`verified_at` (the verify pass is stateless, and `status --unverified` does not cover it), and the
secret findings computed for scratch files are tallied into the run report but never persisted — so
`status --secrets` never lists a scratch finding even when a scratch file was quarantined. Closing
this needs rows, and rows need a lossless key that `artifacts.source_path TEXT UNIQUE` cannot give a
non-UTF-8 path. The queued shape is a dedicated table, keyed losslessly and additively (no migration
mechanism required — `schema.sql` is `CREATE TABLE IF NOT EXISTS` applied on every open):

```sql
CREATE TABLE IF NOT EXISTS scratch_entries (
    id             INTEGER PRIMARY KEY,
    scratch_key    TEXT NOT NULL,          -- <slug>--<uuid>
    rel_hex        TEXT NOT NULL,          -- hex(ScratchRel bytes) — lossless, ASCII, collision-free
    rel_display    TEXT NOT NULL,          -- lossy; human-facing only, never a key
    source_sha256  TEXT NOT NULL,
    source_bytes   INTEGER NOT NULL,
    stored_sha256  TEXT NOT NULL,
    stored_bytes   INTEGER NOT NULL,
    content_sha256 TEXT NOT NULL,
    redacted       INTEGER NOT NULL DEFAULT 0,
    quarantined    INTEGER NOT NULL DEFAULT 0,
    verified_at    TEXT,
    updated_at     TEXT NOT NULL,
    UNIQUE(scratch_key, rel_hex)
);
```

No `stored_path` column: the store path is derived from `scratch_key` + `rel_hex`, and a stored
derivation is a value that can drift from its own inputs. A separate table, not `artifacts` rows,
because scratch identity is `(key, rel)` rather than a source path, and because scratch must stay out
of `index_candidates()` and `gc_row_for_source()` by *construction* rather than by a role filter that
a future role addition could quietly widen.

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

**Hardlink defense.** The blacklist matches on a normalized absolute path *and* on the inode
`(dev, ino)` of the credential files, so a hardlink to a credential placed at a non-denied path (e.g.
inside `projects/`) is still refused. The cardinal credential files (`.credentials.json`,
`.claude.json`, `mcp-needs-auth-cache.json`) are **re-stat'd live on every check**, so a hardlink
created *after* the denylist was built is still caught. Rolling `backups/*` use a compile-time inode
snapshot (lower value; mid-run rotation is a narrow, non-cardinal window). Symlinks are already caught
by path normalization.

**Open is fd-pinned (no check→open race).** The reader `open()`s the source **once** and runs the
inode check against that open fd's own `fstat`, then reads from the fd — never re-opening the path. A
path swapped to a credential hardlink between the name check and the read therefore cannot slip
through: what we scan and store is exactly the inode we vetted.

**Out of scope (P1).** Homoglyph/confusable substitution (e.g. Cyrillic `А` U+0410 for Latin `A`) is
*not* folded by NFKC and is a known residual: a structured secret spelled with confusables is
generally rejected by the issuing service, so it is not chased here. A brand-new credential file at an
unknown path with unknown contents — matching neither a denied path nor a denied inode — is likewise
outside the compiled-in denylist by construction.

### Secret scan — the scannable-or-quarantine invariant

**An artifact enters the browsable, searchable store only if it is fully scannable in a *canonical
readable form*.** Anything that is not is **quarantined whole**: the raw bytes go to `quarantine/`,
and only an opaque marker (`‹QUARANTINED:<reason>:<sha8>›`) is stored in the searchable archive. yomi
is a secret-aggregation point, so "only what we could fully read is searchable" is the safe default —
content we cannot fully scan must never sit, unvetted, in the searchable store. Exotic/binary content
becoming quarantine-not-searchable is the accepted trade-off (user/control-plane ratified).

"Scannable" means: the bytes normalize to UTF-8, and in a **canonical readable form** — NFKC-folded,
with zero-width/format/combining characters and non-ASCII spaces stripped — the detectors find no
secret that isn't already visible in the raw text. The gate, in order (any failure ⇒ quarantine whole):

1. **Encoding normalization.** BOMs are honored (UTF-8; UTF-16 LE/BE decoded to UTF-8). BOM-less bytes
   must be valid UTF-8 **and** free of an interleaved-NUL island: an ASCII secret encoded as UTF-16
   (`A\0K\0I\0A\0…`) is valid UTF-8 yet hides from a byte-regex. The NUL check is **windowed** (any
   `NUL_WINDOW`-byte window ≥25 % NUL ⇒ UTF-16-ambiguous), so a small UTF-16 island diluted inside a
   large ASCII body is still caught (a global ratio would be diluted away). Undecodable ⇒ quarantine.
2. **Structural gate (conversation JSONL: transcript/subagent/history).** Every non-blank line must
   parse as JSON. A malformed line ⇒ quarantine whole (a raw multi-line secret — e.g. a PEM block —
   can only appear in a transcript as non-JSON lines, so this closes multi-line/frame-straddle leaks).
   MCP debug logs are treated as plain text (LOW-MED; a stray non-JSON line shouldn't quarantine a log).
   > **Operational note (accepted trade-off).** The quarantine is *whole-artifact*: one malformed or
   > truncated line quarantines the entire transcript, so every clean sibling line becomes
   > quarantine-not-searchable (raw preserved in `quarantine/`, only an opaque marker stored/indexed).
   > This is an availability trade for a fail-closed leak boundary, not an exposure. A transcript that
   > lost searchability this way is recoverable from `quarantine/`; if a source routinely emits
   > malformed lines, fix the producer rather than loosening the gate.
3. **Normalization-gap detection.** For JSON, every **key and value** (recursively); for plain content,
   the whole text. Each is deep-unescaped (`\uXXXX`/`\xXX`, repeatedly) **and** reduced to its canonical
   readable form, then scanned. A HIGH/MED secret that appears only after this normalization — hidden by
   escaping, by invisible-separator token-splitting (zero-width space, word-joiner, NBSP, combining
   marks), or by fullwidth/compatibility forms — ⇒ quarantine whole. Quarantine (not redact): in the raw
   bytes the secret is entangled with invisible characters, so an in-place redaction span is ambiguous —
   whole-artifact isolation is the fail-safe.
4. **Visible secrets** (present literally in the normalized text) are redacted **in place** with
   `‹REDACTED:kind:sha8›`; the artifact stays searchable. HIGH additionally quarantines the raw original.

Canonicalization is **detection-only** — the stored artifact remains the raw (or in-place-redacted)
bytes, so clean content (including non-ASCII conversation text — Japanese, emoji, symbols) is stored
byte-faithfully and is not over-quarantined.

Scanning always runs over the full logical content `[0..end]`, never a single append slice. The store
stays incremental (append a frame) only when appending reproduces the full redacted content exactly;
otherwise the artifact is rewritten whole (temp-write + rename), which also self-heals a
crash-interrupted prior append.

**Cost note (#4).** Because correctness for multi-line/boundary secrets requires the full-content
scan, each append re-scans the whole logical artifact — O(N·K) over K appends of an N-byte transcript.
This is intentional (no leak window); a future optimization may re-scan only an overlap window
(max-secret-length) around the append boundary. The store write itself stays O(delta).

**Threat-model note (#5).** The blacklist gates by path glob and by credential inode (re-stat'd live,
closing the hardlink TOCTOU for the cardinal credential files). A **fresh** credential file at an
unknown path with unknown content — matching neither a denied path nor a denied inode — is outside
both gates by construction; defending against arbitrary future credential locations is out of scope
for P1's compiled-in denylist.

**Detectors** (config-extensible ruleset, severity-tagged):

| Kind | Pattern | Severity |
|---|---|---|
| AWS key | `A(KIA|SIA)[0-9A-Z]{16}` | HIGH |
| Private key block | `-----BEGIN [A-Z ]*PRIVATE KEY-----` … `END` | HIGH |
| GitHub token | `gh[pousr]_[A-Za-z0-9]{36}`, `github_pat_…` | HIGH |
| Slack | `xox[baprs]-…` | HIGH |
| OpenAI/Anthropic | `sk-[A-Za-z0-9]{20,}`, `sk-ant-…` | HIGH |
| Google API | `AIza[0-9A-Za-z_-]{35}` | HIGH |
| npm / PyPI / SendGrid | `npm_[A-Za-z0-9]{36,}`, `pypi-[A-Za-z0-9_-]{16,}`, `SG\.…{22}\.…{43}` | HIGH |
| Connection string | `scheme://user:PASSWORD@host` (password admits `/` and `@`, backtracks to last `@`) | HIGH |
| JWT | `eyJ[A-Za-z0-9_-]+\.eyJ…\.…` | MED |
| Bearer | `(?i)bearer\s+<20+ token>` | MED |
| HTTP Basic | `(?i)authorization:\s*basic\s+<base64>` | MED |
| password= assignment | `(?i)\b(password\|passwd\|pwd)=<value>` | MED |
| Generic entropy | ≥40-char base64 in key-ish context (`secret`/`token`/`api_key`/`password`) | MED |

Recon flagged **2 transcripts** hitting PRIVATE KEY / AKIA patterns — these are the HIGH cases the scan must catch.

**Known residual (uncovered secret classes, deferred to a future "ruleset completeness" pass).**
Each needs false-positive design that the current keyword/prefix-anchored rules do not provide, so
they are documented rather than shipped half-built:

- **Twilio `SK…`** — collides with the `sk`/`rk` key space (Stripe/OpenAI); disambiguation needs a FP-safe design.
- **Azure SAS `sig=…`** — a bare `sig=` query parameter is a high false-positive surface.
- **Keyword-less high-entropy blobs** (bare 64-hex / base64 / SHA-256) — no anchoring keyword or prefix; a regex cannot bound the false-positive rate. Accepted limit of the lexical scanner.

**Action model — scan → decide → act → record:**

- **HIGH** finding → redact span in stored copy with `‹REDACTED:kind:sha8›` (sha8 = hash of the secret, for dedup/audit, **never the secret**) **and** move the unredacted original to `quarantine/<uuid>/` (mode 700, index-excluded). Recoverable if false positive.
- **MED** → redact in stored copy, no quarantine.
- **LOW** → **flag only** in `manifest.secret_scan.flagged`, surfaced via `yomi status --secrets` for human review. Not redacted (too FP-prone to auto-mutate on entropy alone).
- **Allowlist** `[scan.allow]` (regexes / secret-sha8s of known-benign, e.g. doc example keys) suppresses a finding entirely.

Raw secrets **never** reach the index or `conversation.md` — those derive from the already-redacted stored artifact.

### Permission model

`~/.yomi` + `quarantine/` = 700; `catalog.db` + `config.toml` + stored files = 600; restrictive umask on all writes.
A mutating command **refuses to run** (exit 3) if `~/.yomi` perms are looser than 700. `--fix-perms`
corrects it, but only after confirming the directory is actually a yomi store (marker/`archive`/`state`
present, or empty) — it will not chmod an unrelated directory the user pointed `--home` at.
Read-side commands (`status`, `verify`, `archive --dry-run`) never require an initialized store: a
fresh or missing home reports "nothing archived" rather than erroring, and creates nothing.

### Single-writer lock — dual anchor

Every mutating command (`archive`, `gc --commit`, `index`, `rescan --commit`, and `verify`'s
`verified_at` persistence) holds one advisory lock for its whole run. `ensure_layout` (perm/marker
check) runs **before** the lock, so a too-loose or non-yomi home is refused at exit 3 rather than
locked.

**Two anchors are locked, not one.**

| Anchor | Role |
|---|---|
| `~/.yomi/.yomi.lock` | first contention check; the named, inspectable artifact |
| `~/.yomi/` itself (the lock path's parent) | the load-bearing mutex |

Why two. `flock` attaches to an **inode**, never to a name. A lock held only on `.yomi.lock` is
defeated by removing that name: the next acquirer creates a fresh inode, locks it successfully, and
runs concurrently with the first holder. Re-`stat`ing the path after acquisition does **not** close
this — the second acquirer's inode *is* what the path resolves to, so the re-check passes for both
holders. The store directory has no such gap for the unlink case: it cannot be `rmdir`'d while
non-empty, so the first holder's inode stays reachable by name.

Acquisition order is fixed — file, then directory — and **both are non-blocking**, so no deadlock is
possible and a partial acquisition releases on the early return. Mixed old/new binaries stay safe in
either order, because the new binary takes the *file* anchor first and the old binary knows only that
anchor: whichever starts first, the other sees contention on `.yomi.lock`.

**What this lock does and does not defend.** It is an advisory lock: it defends yomi against *yomi* —
a cron run overlapping an interactive one, two shells, a `run --profile daily` firing twice. It is
**not** an adversarial control, and cannot be made into one: a process that simply never calls `flock`
is unaffected, and any principal that can write inside a mode-700 `~/.yomi` can rewrite `catalog.db`
or replace the binary directly. The directory anchor is **unlink-resistant, not rename-resistant** —
`mv ~/.yomi ~/.yomi.bak && mkdir ~/.yomi` admits a second holder exactly as unlinking the lock file
used to. That residual is accepted: it requires the store owner's own UID, which already defeats every
other control in this document. The value delivered is robustness against the *accidental* removal of
`.yomi.lock` (stale-lock-cleanup habits, a partial `rm -rf ~/.yomi/*`, a restore that drops the file).

**Filesystem support.** `flock` on a **file** can fail outright on mounts without support (some NFS,
FUSE, older CIFS); that is reported as a distinct, permanent error, never as contention, so an
operator is not sent hunting for a process that does not exist. `flock` on a **directory** falls back
to the VFS-local implementation on effectively every filesystem (no `.flock` in the directory
`file_operations` of NFS or FUSE), so the directory anchor is node-local on a network filesystem: the
file anchor carries cross-host exclusion, the directory anchor carries same-host exclusion.

**Lock path is never followed.** `.yomi.lock` is opened `O_NOFOLLOW` and never `O_TRUNC`
(`File::create` did both, so a `.yomi.lock` symlinked at `state/catalog.db` wiped the catalog on the
next write command). The lock file carries no content, so a symlink there is never legitimate state:
on `ELOOP` the path is re-confirmed to still be a symlink, the **link node only** is removed (never
its target), a real file is created `O_CREAT|O_EXCL|O_NOFOLLOW`, and a warning is emitted. Self-heal
rather than refusal, because the repair provably destroys zero bytes while a refusal wedges every
write command — including the unattended `run --profile daily` — until a human intervenes.

**`--discover-all-users` takes no lock at all.** It is read-only by construction (§9 P2) and never
opens, let alone locks, a foreign store root.

---

## 5. Wipe / GC

> **Phase:** built as **P2** (the build sequence merges Archive=P1, Wipe/GC=P2). The
> §9 table historically labeled this P3 behind a separate "Secret scan" P2; the secret
> scanner shipped inside P1 (canonical-form scanner, quarantine, 55 tests), so wipe moves
> up to P2. The index layer (P3) now exists; `require_indexed` still defaults **false**, and set
> `true` it consults per-source `index_state` and skips only sources not indexed at their current
> source sha (fail-closed), deleting the rest.

### Absolute law: archive-verify-then-delete

No deletion path exists that isn't gated on a verified archive. Per source file:

1. Look up archive artifact by source path + `source_sha256` in catalog (source path is canonicalized so symlink/`..`/relative forms map to one row).
2. **Recompute live source `sha256`.**
3. Require **all**: catalog artifact with `source_sha256 == live_sha` **AND** the stored artifact **re-verifies** (below) **AND** (if `require_indexed`) index status = indexed. In P3 the gate consults per-source `index_state`: a source is index-current only when `index_state.indexed_source_sha256 == source_sha256`. Un-indexed or stale-indexed (or an SQL error) → skip, never delete (fail-closed).
   > **`require_indexed` guarantee scope.** The gate proves *"the current source sha was processed by the indexer"* — **not** *"this source contributed searchable content"*. A source that produced zero index docs (e.g. a whole-quarantined transcript, whose stored bytes are an opaque marker, or an empty/noise-only file) still satisfies the gate at its current sha: it was seen, its raw is preserved in `quarantine/` (mode 700), and deleting the redundant live copy is safe. `require_indexed` is a *"we have processed this version"* guarantee, not a *"it is findable via search"* guarantee.
4. **AND** file age ≥ `min_age` **AND** session not live (§below).
5. Only then delete source. Append to `gc.log`: source, source_sha, archive_id, verified checks, deleted_at.

Any check fails → **skip**, mark `unverified` in status. Never delete on doubt.

### `gc.log` — every candidate leaves a record

`~/.yomi/gc.log` is append-only JSONL, mode 600, and carries four record kinds: `delete`, `skip`
(a gate refused), `protect` (live/too-young/retain-window), and `delete_failed` (the gates passed but
the physical removal errored). The audit trail is the point of the whole layer, so **one candidate
failing must never truncate it**:

- A failed `unlinkat` (EACCES on the parent, EIO, …) is recorded as `delete_failed` and the run
  **continues**; the run reports exit 2 (partial).
- `ENOENT` (a racer, or Claude Code itself, already removed the entry) and `ENOTEMPTY` (an empty-dir
  candidate refilled) are not failures — the delete either happened or is no longer applicable — and
  are recorded as skips.
- The commit loop aborts only on a **global** doubt: a `catalog.db` failure, which makes every
  subsequent evaluation unreliable, or a failure to write `gc.log` itself, which would mean acting
  without recording. A **per-candidate** doubt — one unreadable source, one corrupt `.zst` — must
  degrade to a `skip` record, never to an abort: aborting leaves every later candidate unevaluated,
  undeleted **and unrecorded**, which is indistinguishable from "looked at and found safe".

> **Known gap (P2 residual).** `evaluate_candidate` still returns `Err` for per-candidate I/O — a
> source read failure, a `.zst` that will not decompress — and the plan and commit loops propagate it,
> so a single unreadable artifact aborts the pass. Only the *physical delete* has been split into the
> two layers above. The gate layer must be split the same way: per-candidate I/O → `Unverified`;
> catalog/SQL → `Err`.

Skips are recorded by reason, so the log distinguishes *why* a candidate survived. The physical-delete
layer currently collapses four distinct outcomes — `ENOENT`, `ENOTEMPTY`, an inode that drifted since
the gate, and a blacklist hit — into one boolean and logs them all as `InodeDriftOrBlacklist`, which
is a false reason for three of the four. The delete primitives should return an explicit outcome
(`Removed` / `AlreadyGone` / `Refilled` / `Drifted` / `Failed(errno)`) so the errno→category mapping
lives once, in the syscall wrapper where the errno is in scope, and the log records the truth.

**Stored re-verification (`yomi verify`, P1) is two-layer, not one:** the compressed bytes must hash
to the catalog's `stored_sha256`, **and** the *decompressed* content must hash to `content_sha256`
(the sha of the intended, post-redaction content, recorded at capture). The content-hash layer is
what catches frame-duplication corruption — e.g. a crash-replayed append — that a
compressed-bytes-only check would pass. For an un-redacted artifact `content_sha256 == source_sha256`;
for a redacted one it is the sha of the redacted stored content (the browsable copy is redacted by
design, so it cannot equal the raw source). The GC gate above therefore trusts `verify`, and `verify`
proves the store is byte-exact to what capture intended.

**Scratch verification is manifest-driven, because the manifest is what the gate trusts.** Scratch
writes no catalog row, so `cat.verify_rows()` cannot reach it — and mirroring scratch into the catalog
purely to give `verify` something to iterate would create a *third* ledger able to drift from both the
manifest and the store. `verify` attests to the ledger the delete gate actually consumes. Its scratch
pass walks `archive/_scratch/*/` (scoped to the matching key when a session uuid is given) and checks
law S (§3) per store dir:

1. `manifest.json` exists and parses. Missing or unparseable ⇒ failure (the gate would refuse this
   tree; `verify` says so out loud rather than leaving it to a GC dry-run to notice).
2. Every `stored: true` entry carries **both** `source_sha256` and `content_sha256`. A stored entry
   without them is unverifiable — the gate already skips such a tree; `verify` reports it.
3. Every `stored: true` entry's `.zst` exists, decompresses, and hashes to its `content_sha256`.
4. Every `stored: false` entry has **no** `.zst` at its `store_rel()`.
5. Every `*.zst` under the store dir is claimed by a `stored: true` entry — the orphan check, and the
   one that catches a store/manifest drift from the outside.

Checks 4 and 5 are the two halves of law S's set equality; 3 is its hash half. A failure in any of
them is a `verify` failure (exit 2), listed by key and rel path. The pass is stateless: it persists no
`verified_at`, because scratch has no catalog row to persist it on (§3, known gap).

**GC gating: unchanged — the scratch gate does not consult law S.** An orphaned `.zst` is a store
hygiene defect, not a coverage defect: it does not make the live tree less archived, and the gate's
question is only ever "does the archive faithfully cover *this live tree*". Refusing on an orphan
would let an unrelated store defect permanently block reclamation — the precise failure mode the
over-cap fix existed to end. The scenario that *would* deserve a halt is "the archive silently failed,
so the source was deleted anyway", and detecting that is exactly what the `verify` pass above is for;
the answer to a ledger defect is a check that reports it, not a gate that wedges on it.

Two conditions of that judgment are worth recording, because the *reason* it is safe changes once §3's
reconciliation lands. Before: an over-cap tree could still have stored bytes sitting in an orphan
`.zst`, so "nothing is lost" leaned on manual `zstd` recovery — which is the defect, not a rationale.
After: an over-cap tree genuinely stores nothing, the orphan class cannot be produced by `archive` at
all, and the position rests on ratified decision #4 alone. No gate change is needed in either state,
and the post-fix rationale is the cleaner one.

### Live-session protection

- Parse `~/.claude/sessions/<pid>.json` → active session UUIDs + cwd; confirm liveness via `/proc/<pid>`.
- Consult `~/.local/state/claude/locks/*.lock`.
- A transcript is **protected** if: its `sessionId` ∈ active set, OR mtime within `active_window` (default 1h), OR age < `min_age`.
- `gc --commit` holds the dual-anchor single-writer lock (§4) for the whole run and refuses (exit 3)
  on contention. `gc` without `--commit` and `gc --discover-all-users` are read-only and take no lock.

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
require_indexed  = false   # P3: true ⇒ GC consults index_state; skips only un-indexed sources
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
ample for a 25M→low-GB corpus. `trait Index { fn upsert(docs); fn query(q); fn delete_session(session); }`
lets tantivy slot in later without touching callers.

**Shipped shape:** external-content FTS5 (`entries` metadata table + `entries_fts` vtable + 3 sync
triggers) inside the same `catalog.db`; per-source `index_state` watermark; `index_meta` records the
tokenizer/epoch. Tokenizer default `unicode61 remove_diacritics 2` (best for English/code, supports
prefix/AND/OR/NEAR), with `[index].tokenizer = "trigram"` opt-in for CJK-heavy corpora (substring
match; requires `yomi index --reindex`, a destructive FTS rebuild). All SQL lives on `Catalog`; the
index reads **only** the redacted stored bytes, never `source_path`.

### Document granularity: per-entry (per JSONL message)

One index doc per user/assistant/tool-result entry → precise hits + jump-back. Single-text roles
(mcp / paste / snapshot / history / tool-result) index as one whole-text doc (`entry_uuid =
art:<id>`); subagent-meta and scratch are not indexed. `agent` is `main` for the session transcript
and the subagent `agentType` (read from the sibling `.meta.json`) for a subagent transcript;
`role=tool_result` derives from the `tool_result` blocks of a `type:"user"` line, inheriting the
tool name from the answered `tool_use`. Fields:

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

Redacted spans index as the placeholder token — raw secrets never indexed. This holds regardless of
the artifact's `quarantined` flag: the flag is set both for whole-quarantine artifacts (stored =
opaque marker) and for scannable content with a redacted-in-place HIGH finding (stored = fully
redacted browsable text), so the indexer does **not** gate on it — non-exposure is guaranteed
structurally by indexing only the decompressed stored bytes.

### Query CLI

```
yomi index [--reindex] [--session U]                       # mutation, WriteLock hard-required
yomi search <query> [--project P] [--session U] [--agent A] [--role R] [--tool T]
                    [--branch B] [--cwd C] [--since D] [--until D] [--on D]
                    [--limit N] [--context N] [--json]      # read-only
yomi read <session> [--entry U] [--agents] [--grep S] [--raw] [--json]   # read-only
```

Inline `field:value` in the query also parses to filters: `project:zaibatsu tool:Bash "cargo build"`
(a CLI flag wins over an inline token; free-text terms are quoted into a safe FTS5 AND-of-terms, so
operators/`"` cannot inject). Output: ranked (BM25) highlighted snippet + header (`session ·
timestamp · project · agent`) + jump ref (`yomi read <session> --entry <entry_uuid>`). Empty free
text with filters → metadata-only listing (newest first). `read --raw` decompresses the stored
transcript and works without an index.

### Incremental index

Per-source watermark: `yomi index` reindexes only artifacts whose `source_sha256` moved off the
recorded `indexed_source_sha256` (sha match, not offset arithmetic — redaction changes byte length),
replacing that artifact's entries. `--reindex` drops and rebuilds all entries (and the FTS vtable on
a tokenizer change). Built from the **redacted stored artifact**. Auto post-archive chaining is
deferred to P5 `run --profile daily`.

### Rescan — retroactive re-redaction (P3.5 remediation)

`yomi rescan` re-redacts the **existing** store against the hardened scanner, remediating raw secrets
that a pre-hardening scanner archived into two faces: the browsable stored `.zst` and the search
index (`entries.text` + FTS). Because a source may already be wiped, the **stored content is the only
input** — sources are never re-read. Dry-run is the default; `--commit` mutates under the WriteLock.

- **Scan scope.** No scanner-rules-version is recorded on artifacts, so the run is a **full sweep** of
  every browsable stored artifact (`index_candidates()` roles). Each is decompressed, re-scanned with
  the hardened scanner, and targeted **iff the re-scan changes the stored bytes** (`scan.redacted !=
  stored`). `--session` narrows the sweep. Scratch and subagent-meta stores are out of v1 scope
  (neither is catalog-registered/indexed — not part of this index exposure surface; a separate
  mechanism is follow-up). This exclusion is unchanged by `read --scratch` (§3), but its consequence
  is now visible rather than latent: a gap-era scratch `.zst` is readable through a first-class
  command while still carrying whatever the pre-hardening scanner left in it. The exposure surface is
  the same as before — owner-only bytes in a mode-700 store, never indexed — but a scratch sweep is
  now a concrete follow-up with a concrete face, not a theoretical one. It needs the catalog rows of
  §3's queued table to record which entries were rescanned.
- **Invariant 1 — both faces cleaned.** A targeted artifact's raw secret is removed from the stored
  copy AND the index; the post-write verify proves no residual on either face.
- **Invariant 2 — `source_sha256` is immutable.** It is the original raw's historical hash and the
  basis of the GC gate-2 (`live_sha == source_sha256`) and require-indexed gate. Rescan updates
  `stored_sha256` / `content_sha256` / `verified_at` (via a dedicated `rescan_update_artifact`) but
  never the source identity.
- **Invariant 3 — forced re-index from in-memory bytes.** Because `source_sha256` is held constant,
  the normal incremental index would *skip* the rescanned artifact (`indexed_source_sha256 ==
  source_sha256`). Rescan therefore rebuilds the index itself, in its own transaction, from the
  **in-memory** re-redacted bytes (`docs_for_stored`) — never from a disk re-read.
- **Invariant 4 — DB-commit before stored-rename (crash-safety core).** Per artifact: in-memory
  fail-closed idempotency gate → temp store write → **DB transaction commit** (index purge + reindex
  from in-mem bytes + `index_state` + catalog + findings) → **atomic stored rename** → manifest. At
  every crash point the index holds no raw secret; the worst case is a stored copy briefly left as
  stale raw (owner-only, flagged by verify), which the next run re-targets and converges. The reverse
  order would let a post-rename crash leave `stored == clean` so the artifact is no longer a target
  while the index still carries the raw secret — a permanent leak.
- **Invariant 5 — require-indexed gate preserved.** The forced re-index writes `index_state.
  indexed_source_sha256 = source_sha256` (the unchanged value), so `require_indexed` GC keeps
  permitting the delete of a rescanned source.
- **scan layer — `trust_existing_tags`.** Re-scanning yomi's own stored output must NOT defang its
  genuine `‹REDACTED:`/`‹QUARANTINED:` tags. `scan_content_with(ScanOpts{trust_existing_tags:true})`
  skips only the forged-tag defang block. Soundness: archive-time scanning already defanged any
  source-forged `‹`-tag, so a `‹`-tag surviving in stored content is necessarily a real redactor tag.
  Archive callers keep the default (defang on).
- **Three transitions.** `InPlaceRedact` (scannable, no HIGH → redact in place), `VisibleQuarantine`
  (scannable + HIGH → redact in place, raw quarantined), `WholeQuarantine` (not fully scannable →
  opaque marker stored, raw quarantined). A raw original is quarantined *before* any store/index
  mutation so a failure there loses no recovery copy (the DB-commit-before-rename invariant is
  unaffected). An already-whole-quarantined artifact is **skipped** — re-scanning a marker under a
  JSONL role would re-quarantine it forever with a fresh tag. The skip requires **both** a strict
  single-token stored shape (`‹QUARANTINED:…›` with no trailing content) **and** catalog provenance
  (`quarantined = 1`, set by yomi, unforgeable by a source); a source-forged leading marker followed by
  a real secret satisfies neither and is rescanned, so the trailing secret cannot shield itself.
- **No secret in the report.** Dry-run / `--commit` / `--json` show only detector `kind × count`,
  transition, sha8, and index-row counts — never placeholder contents, raw bytes, or secret values.

**Known trade-offs.** A mixed-case whole-quarantine copy includes any prior placeholders (the true
original was wiped); the findings row is replaced by the current re-scan's findings (a minor loss of
old audit history — the stored placeholder remains the redaction evidence); a PerEntry role's
whole-quarantine yields zero index docs (marker not separately searchable), identical to archive-time
behavior. The dry-run plan lists an artifact as a target purely by its re-scan outcome; `--commit` may
still skip that artifact at runtime (a residual-gate failure, a quarantine/temp-write/rename error) and
record it under `failed` — so a previewed target is a best-effort forecast, not a guarantee.

**Known limitation — gap-era forged tags.** The `trust_existing_tags` soundness argument (a surviving
`‹`-tag is necessarily yomi's own) holds for P3-era stored content but is formally false for the
gap-era population rescan exists to remediate: that era flagged a source-forged `‹REDACTED:`/
`‹QUARANTINED:` token without defanging it, so such a token can persist un-defanged in gap-era stored
content after rescan. This is **not a secret leak** — the lexical scan still redacts any real secret
in the surrounding text, and the strict-shape + provenance skip guard prevents a forged leading marker
from shielding a trailing secret — but a gap-era forged audit token may remain cosmetically in the
stored copy. Removing it would require re-defanging, which rescan deliberately does not do (it would
also mangle genuine tags).

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
yomi rescan  [--commit] [--session <uuid>] [--fix-perms]                                                # dry-run default; retroactive re-redaction
yomi read    <session-uuid> [--entry <uuid>] [--agents] [--grep P] [--human|--raw]
yomi read    <session-uuid | scratch-key> --scratch [--file <rel>] [--json]                              # archived scratch
yomi status  [--secrets] [--unverified] [--storage]
yomi verify  [<uuid> | --all]                                                                           # incl. scratch store law S (§5)
yomi config  [get|path]
```

**`read --scratch`.** The positional argument is a session uuid or a full `<slug>--<uuid>` store key;
a uuid resolves to the single `archive/_scratch/*--<uuid>/` that carries it (uuids are unique, so at
most one), and an ambiguous or absent key is exit 2 with the reason. Behaviour:

| Form | Output | Exit |
|---|---|---|
| `--scratch` | manifest listing: `rel`, `bytes`, `stored`, `present`, plus `captured_at` / `total_bytes` / `over_total_cap` for the tree. `--json` emits the same fields plus `source_sha256` / `content_sha256` | 0, or 2 if the key resolves to nothing |
| `--scratch --file <rel>` | the entry's decompressed stored bytes, **written raw** to stdout (`write_all`, not a lossy string conversion — a scratch file may be binary). `--json` emits `{rel, bytes, encoding, content}` where `encoding` is `"utf8"` (content verbatim) or `"hex"` (content hex-encoded) — same encoder as `path_hex`, so `--json` adds no dependency and never emits invalid UTF-8 inside a JSON string | 0 |
| `--scratch --file <rel>`, entry `stored: false` | refusal naming *why* it was not stored — over-cap, deny-listed, or over `file_cap` — never a bare "not found" | 2 |
| `--scratch --file <rel>`, no matching entry | not found | 2 |

`<rel>` is compared against `ScratchRel::as_bytes()`; the opened path comes from the matched entry
(§3). Only stored bytes are ever read — never the live source, never `quarantine/`.

**Not yet shipped** (kept here as the designed surface for their phases):
`yomi list` (P5), `yomi import --from-codex|--from-wonka` (P4, §7), `yomi run --profile daily` (P5),
`yomi config set` (only `get`/`path` exist).

Global: `--home <dir>` (`YOMI_HOME`), `--config <path>`, `--json`, `-v`.
Exit codes: `0` ok · `1` error · `2` partial (items skipped/unverified) · `3` refused (perm/lock/safety).

### Cron / scheduled

`yomi run --profile daily` (P5) is idempotent + lock-guarded → safe hourly/daily. Emits `--json` summary
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
    scratch.rs              # ScratchRel + ScratchManifest/Entry — the one owner of scratch identity (§3)
    source/  {mod, claude, single, discover}.rs
    archive/ {mod, manifest, incremental, compress}.rs             # zstd frames
    scan/    {mod, content, rules, redact, quarantine}.rs
    catalog/ {mod.rs, schema.sql}                                  # rusqlite
    index/   {mod, ftsindex, parse, query}.rs   (trait Index; tantivy.rs future)
    gc/      {mod, safety, policy, live}.rs
    rescan/  {mod}.rs                                              # P3.5 re-redaction
    importer/{mod, codex, wonka}.rs                                # P4, not yet built
  tests/  e2e.rs · p4_gc_break.rs · p4_toctou_break.rs · p4_umask_break.rs · p4_unlink_break.rs
          p5_scratch_cap_break.rs · p6_scratch_ledger_break.rs · p6_scratch_read_break.rs
          # fixtures are fabricated in-test under a tmpdir; no committed fixtures/ tree
```

Crate is published as `yhi-yomi`; the binary and lib are both `yomi`. Edition 2024, MSRV 1.89.

### Dependencies

`clap`(derive+env) · `serde`+`serde_json`+`toml` · `zstd` · `rusqlite`(bundled, FTS5) · `sha2` ·
`regex` · `unicode-normalization`+`unicode-properties`(canonical-form scanner, §4) ·
`walkdir`+`globset` · `chrono` · `anyhow`/`thiserror` · `tracing`(+subscriber) ·
`rustix`(fs+process: `unlinkat`/`statat`/`O_NOFOLLOW`, `/proc` liveness). The single-writer lock uses
**std** `File::try_lock` (`flock`), not `fs2`. Dev: `filetime`. Future: `tantivy`. Mirror mx crate
conventions (follow-up: read mx repo for shared style/lint config).

**Platform: Linux only.** `/proc`-based liveness and the `statx`/`unlinkat` paths are not portable,
and `O_NOFOLLOW` on a symlink is `ELOOP` on Linux but `EMLINK`/`EFTYPE` on some BSDs — the lock's
symlink self-heal keys on `ELOOP`.

### CI

`fmt` · `clippy -D warnings` · `test` · `cargo-deny`/`audit` · static musl build · mise integration.
Load-bearing fixtures: secret-scan **must** catch AKIA/PRIVATE KEY; double-archive = no-op; wipe **refuses** on checksum mismatch and on live session.

### Phases (each with a hard done-when)

- **P1 — Archive + blacklist + fidelity + secret scan** (foundational; secret scan/quarantine
  shipped inside P1: canonical-form scanner, quarantine, severity/allowlist, `status --secrets`).
  *Done:* transcripts captured byte-faithfully; re-run no-op; blacklisted paths provably never opened;
  fixture secrets caught+redacted; raw secret never in store/index; `yomi verify` passes. **(merged, #1)**
- **P2 — Wipe / GC** (gated on P1). archive-verify-then-delete, live detection, age policy,
  dry-run default, /tmp + empty-dir janitor, `gc.log`, cross-user READ-ONLY shape discovery.
  *Done:* deletes only verified+aged+non-live; refuses on any mismatch/live/lock (test);
  dry-run shows plan; reclaims the 134M scratch clone + 65 empty dirs; `--discover-all-users`
  inventories all ephemeral shapes without touching foreign data.
  > The "reclaims the 134M scratch clone" criterion was **not** met until the over-cap writer fix: a
  > tree over `total_cap` was manifested with `stored: true` entries but no stored bytes, and the GC
  > gate refuses a stored entry with no hashes, so that tree was never reclaimed — and every existing
  > scratch-reclaim test stayed under the cap, which is why it went unnoticed. Over-cap entries are
  > now written `stored: false` and take the gate's size-only path; `tests/p5_scratch_cap_break.rs`
  > covers the over-cap tree directly, including the permanence claim across three archive/GC cycles.
  > See §3, "Over-cap is manifest-only", for the accepted consequence.
- **P3 — Index + search.** FTS5, per-entry docs, filters, incremental index, `search`/`read`.
  *Done:* ranked filtered results; incremental index no dup; redacted-only content.
- **P4 — Codex absorption + cutover.** importer, freeze codex writes, hook/shutdown rewire. **No mx changes** — codex left as frozen read-only vestige (decided §5).
  *Done:* `import --from-codex` idempotent; `mx codex archive` no longer invoked by hooks; hooks call `yomi archive`; `mx codex read/list/search` still function untouched.
- **P5 — Ops.** `run --profile daily`, `status --storage`, senri JSON hook, documented tantivy upgrade trigger.
- **P6 — Scratch retrieval + integrity** (§3, §5, §8). The archive-then-delete contract holds for
  scratch only in one direction today: `archive/_scratch/` is written and gated on, but no command
  reads it and no command verifies it, so its stored bytes are write-only and a corruption is
  undetectable. Four units, in order:
  1. **`src/scratch.rs`** — `ScratchRel` + the single `ScratchManifest`/`ScratchEntry` definition;
     archive and the GC gate both go through it. Pure refactor: identity becomes lossless (`path_hex`),
     no enumeration change, no store change, no manifest re-keying.
  2. **Enumeration + reconciliation** — the writer walks the whole `<slug>/<uuid>/`; archive
     establishes law S by removing unclaimed `*.zst` under the tree's own store dir; vanished-file
     entries are retained `present: false`; `scratch_orphans_removed` in the run report, previewed
     under `--dry-run`.
  3. **`yomi verify` scratch pass** — law S per store dir, exit 2 on any violation.
  4. **`yomi read --scratch`** — manifest listing and stored-bytes retrieval, stored-only by
     construction. Independent of (3); may land in parallel.

  *Done:* an archived scratch file is retrievable by `yomi read --scratch --file`, byte-identical to
  its stored (post-redaction) content; a corrupted or orphaned scratch store fails `yomi verify`;
  lowering `total_cap` and re-archiving leaves no `.zst` the manifest denies; a file dropped directly
  in `<uuid>/` no longer makes its tree permanently unreclaimable; deleting a live scratch file does
  not destroy its archived copy. Catalog registration of scratch (`scratch_entries`, §3) is
  **not** part of P6 and stays queued.

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
