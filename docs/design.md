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
  quarantine/<archive-rel>         # mode 700 — unredacted originals, mirroring archive/ path-for-path (§4 law Q); NOT indexed
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
- **Quarantine mirrors the archive** — `quarantine/<X>` holds the unredacted original of `archive/<X>.zst` (§4, law Q). An original is named by the identity of the artifact it is the original of, so it inherits the store's uniqueness and same-named originals from different sources cannot clobber each other.
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
longer overwrite each other and their trees are no longer refused forever. A malformed `path_hex`
yields `None` rather than falling back to `path` — the fallback is exactly the lossy value the hex
exists to replace, and silently restoring the collision is worse than refusing.

`from_manifest` also rejects any rel that is not a plain sequence of ordinary components: absolute, or
carrying `..`. A hostile or hand-edited manifest therefore cannot produce a key that escapes the store
dir when `store_rel()` is joined to it. Traversal is refused at the type's constructor, not at each
call site.

#### The store key of a tree, and its two hazards

`store_key(slug: &OsStr, uuid: &OsStr) -> String` names one tree's directory under
`archive/_scratch/`, and is also the discriminator inside its quarantine path. It is `<slug>--<uuid>`
verbatim whenever both directory names are valid UTF-8 — which every real one is — so existing stores
keep their names byte for byte. A name that is not valid UTF-8 takes a hex form beginning `_hex--`;
a UTF-8 pair whose plain form would begin with that marker is pushed into the hex branch too, so the
two output spaces are disjoint and neither can impersonate the other.

**Hazard 1 — the plain form is not injective, and pure ASCII reaches it.**
`store_key("a", "-b") == store_key("a-", "b") == "a---b"`. The string `<slug>--<uuid>` has one
preimage per occurrence of `--` in it, and real slugs contain `--` routinely (any path component
ending in `-`, or beginning one). Two colliding trees share a store directory, a manifest and a `.zst`
namespace, so the later run's live pass claims the earlier tree's identity and overwrites its only
archived copy — the same outcome as the lossy-name collision, reached without any lossy conversion.
Directory names under `/tmp/claude-<uid>/` are creatable by any process of the same uid, so this is
also reachable deliberately.

**Making the key injective is the wrong fix.** Every injective encoding of an arbitrary pair of byte
strings differs from `<slug>--<uuid>` on inputs that exist today, so adopting one renames *every*
store directory: the data is not lost but nothing finds it, and a migration must walk, match and move
directories whose identity is precisely the thing that was ambiguous. Restricting the plain form to
unambiguous strings ("exactly one `--`") is no better — common real slugs fail it and get re-encoded.

**The fix is to record the identity and detect the collision.** The manifest carries the tree's raw
identity, always emitted, as two hex fields:

```json
"slug_hex": "<hex of the slug directory name's bytes>",
"uuid_hex": "<hex of the session directory name's bytes>"
```

Both `#[serde(default)]` (empty), so a manifest from before them parses unchanged. The rule, applied
by archive and by the GC gate alike, immediately after the manifest is read and **before any write,
any reconciliation and any coverage judgment**:

| Recorded identity | Action |
|---|---|
| absent (pre-field manifest) | proceed; archive stamps the real values on its next write, so the store self-upgrades on first contact |
| present and equal | proceed |
| present and **different** | refuse this key — archive writes nothing and removes nothing; the GC gate returns `Unverified { reason: StoreKeyCollision }` |

This is injective *in effect* — two colliding trees can never write through one another, because the
second one to arrive refuses — at zero migration cost, with existing store names untouched and the
guarantee arriving by itself as each store is next archived.

**The refusal is per pair, not per key, and the asymmetry is load-bearing.** The tree whose identity
the ledger records keeps working: it archives, and the GC gate reclaims it, because its coverage is
provably its own — the impostor refused *before writing*, so nothing of the impostor is in that store.
Only the newcomer is refused, and it has no archive to lose. Taking a demonstrably-covered tree out of
service because an unrelated directory happens to collide with it would be the same failure mode §5
rejects for orphans: an unrelated defect permanently blocking reclamation. It would also be worse than
inert — under a symmetric rule, anything able to `mkdir` under `/tmp/claude-<uid>/` could freeze an
arbitrary existing tree's archiving and reclamation by choosing a colliding name. Under the pair-wise
rule the newcomer is the one that stops, so a same-uid actor can only deny itself. (Pre-creating the
store directory to claim the ledger first needs write access inside a mode-700 `~/.yomi`, which §4
already treats as defeating every control.)

The price is that the **newcomer** is neither archived nor reclaimed until an operator renames one of
the two, which is the correct price: the alternative is a silent overwrite of the only archived copy.
Its live tree is never deleted either — the gate refuses it too — so the state is inert, not lossy.

**A ledger outlives its tree, and that is accepted.** Once the first tree is archived and GC has
reclaimed it, the store directory and its manifest remain — that *is* the archive. A colliding tree
arriving afterwards is refused by a ledger whose own tree no longer exists, permanently, until an
operator renames it or deliberately removes the old store. This is the same shape as an
`UnreconcilableKey`: fail-safe, lossless, and a state an operator has to leave rather than one the
tool leaves by itself. No automatic exit is designed, because every candidate is worse — renaming the
surviving store is the migration this whole design refuses, and deriving an alternate key for the
newcomer would make `store_key` depend on what is already on disk, which is the ambiguity class the
unit exists to end. The exit is **reporting**, so the operator can act: see D-S4.

`StoreKeyCollision` is its own reason and not `ForeignStoreDir`, because the operator action differs —
"two session directories map to one store key; rename one" versus "your store path was replaced".

**A recorded identity that does not decode reads as "not recorded", and that must be reported.**
Hand-edited or corrupted hex is not evidence of anything: comparing it to a live identity would either
match by accident or mismatch without meaning, so it decodes to nothing and the verdict is `Proceed` —
the same as a pre-field manifest, which is what keeps one bad byte from permanently refusing a store.
But the two are *not* the same fact, and this design has separated absence from unreadability
everywhere else (`Missing` versus `Unreadable`; `NoManifest` versus `UnreadableManifest`). Conflating
them here is worse than untidy: it means a corrupt field **silently disables the collision guard** for
that key. `verify` must say so — `UndecodableIdentity`, **unverifiable** (§5): the ledger records an
identity that does not decode, so the guard is inactive here. Proceeding is right; proceeding in
silence is not.

**Hazard 2 — `NAME_MAX`.** A key is a single filename component, so it is bounded at 255 bytes on
Linux. Nothing bounds it today: a deep `cwd` yields a long slug, and the `_hex--` form **doubles** the
input, so it exceeds 255 for any pair over ~124 bytes. The failure is not graceful — `create_dir_all`
returns `ENAMETOOLONG`, `archive_scratch` propagates it, and the whole `yomi archive` run aborts (the
same containment defect described under "Per-key failures must not abort the run" below).

The rule: the plain and hex forms are used only while the result is within `KEY_MAX`, which is
**255 bytes — `NAME_MAX` itself, with no margin.** Beyond that, a digest form:

```
_h256--<sha256_hex(hex(slug) ++ "--" ++ hex(uuid))>       # 7 + 64 = 71 bytes, always legal
```

Injective under sha256 collision-resistance, which is not a new assumption: `source_sha256`,
`content_sha256` and the entire GC delete gate already rest on it, and if it fails the archive's
integrity falls before its directory naming does. The inner encoding is hex-then-join precisely
because hex contains no `-`, so the `--` is an unambiguous separator there even though it is not in
the plain form. No existing store is renamed by this rule, because a key that exceeded `NAME_MAX`
never successfully created a directory in the first place — there is nothing to orphan.

**That last sentence is only true because `KEY_MAX` is `NAME_MAX`.** An earlier draft set it to 200
and justified the margin two ways, both of which are now known to be worth nothing:

- *"headroom for the components a quarantine path builds from a key"* — true of the superseded
  `quarantine/_scratch--<K>/…` layout, and false since the mirror rule (§4). `<K>` is now a single
  component in `archive/_scratch/<K>/` and a single component of the same length in
  `quarantine/_scratch/<K>/`, and **no component of either tree is longer than `<K>` itself.** The
  only place the old doubled form is still constructed is Q1's legacy fallback, which `stat`s it and
  never creates it; for a key long enough to overflow there, no legacy original can exist either,
  because the old writer could not have created that component. The `stat` simply fails and the
  fallback finds nothing.
- *"filesystems with tighter limits"* — a margin cannot buy this. On a filesystem bounded near 143
  bytes, a 200-byte key fails to create exactly as a 255-byte one does; the margin only moves the
  failure point to a number that is right nowhere. A key that a filesystem will not accept is a
  **per-key failure**, and it belongs to D-S3's containment — `ENAMETOOLONG` becomes a refusal of that
  key with a reason, not an aborted run — not to a guess baked into the key derivation.

With the margin gone the claim is literal: every plain key a Linux filesystem could ever have created
stays plain, and the digest form fires only where `create_dir_all` would have failed anyway. At 200 it
was false by 55 bytes — a `cwd` past roughly 162 characters produced a key that had been creating its
store directory happily and would now be orphaned beside a fresh digest-form one, doubling the
footprint without losing data. Deep, but reachable, and it is precisely the population a no-migration
guarantee is supposed to protect.

#### `ScratchEntry` — the manifest's per-file record

| Field | Emitted | Meaning |
|---|---|---|
| `path` | always | lossy display form. **Never a key** |
| `path_hex` | only when the name is not valid UTF-8 | lossless identity |
| `bytes` | always | size of the **live** file at enumeration time |
| `stored` | always | an artifact for this entry exists in the store |
| `source_sha256` | stored entries | sha of the live source bytes as captured |
| `content_sha256` | stored entries | sha of the stored, post-redaction content |
| `present` | only when `false` | the live file was not seen by this run's walk |
| `capture_failed` | only when `true` | policy chose to store it and the capture then failed |

`present` and `capture_failed` are both written only in their non-default state, so an ordinary
all-live tree serializes byte-identically to the pre-field schema and no manifest is rewritten merely
by upgrading.

**The manifest must record *why* an entry was not stored, not only that it was not.** It currently
records the outcome alone, so a reader explaining a `stored: false` entry has to reconstruct the cause
from the **current** config — and the config is not the one that produced the entry. Widen `file_cap`
after the fact and an entry rejected at capture for exceeding the old cap is thereafter explained as
"the allow/deny globs did not admit it": a confident, wrong answer, of the same family as reporting a
permission bit as a replaced store path. Retained entries make it worse, since `present: false` records
carry a decision taken under a config that may be several changes old.

The addition is one entry-level field, emitted only when it applies, in the same additive shape as
`present` and `capture_failed`:

```
not_stored: "not_allowed" | "denied" | "file_cap"
```

Exactly the three policy causes `store = allow.is_match && !deny.is_match && size <= file_cap` can
produce, kept apart because "no allow pattern matched" and "a deny pattern matched" are different
configuration edits. The two remaining causes already speak for themselves and take precedence in any
explanation: `over_total_cap` is a property of the tree and lives on the manifest, and `capture_failed`
answers a different question entirely — *nothing was read*, rather than *we decided not to keep it*.
Recording rather than reconstructing also makes a retained entry's explanation stay true forever,
because the field travels with the entry.

**`capture_failed` exists because `stored: false` was carrying two incompatible claims.** One is
*policy declined to hoard these bytes* — a deny glob, an over-cap tree — and there presence + size is
the intended assurance and the tree is reclaimable (decision #4). The other is *nothing was ever
read*: no decision was made at all, so presence and size assure nothing whatsoever about content
nobody has seen. A gate that cannot tell them apart must mishandle one of them; handling the first
correctly (reclaim on size match) is exactly what makes the second a deletion of unarchived data.

**Four paths set the one flag**, because the single fact the ledger records is the one they share:
**not one byte of this file's content was captured.** Three are refusals of the source read — a
blacklisted inode swapped in after the walk, an unreadable file, a file that outgrew the read bound
between stat and read. The fourth is a **failure to quarantine**: nothing of a file may enter the store
while its unredacted original is unpreserved, because the store copy is redacted or an opaque marker,
so writing it and losing the original would leave the secret-bearing bytes only in the live file —
which the gate would then let GC reclaim. The gate maps the flag to a refusal of the whole tree.

**The refusal is transient, and that is what separates it from the `#9` failure mode.** `#9`
regenerated an identical broken manifest on every run, so no number of archive/GC cycles ever helped.
Here the flag is rebuilt from live state each run: the first archive that can read the file stores it,
the flag is simply not written, and the refusal is gone. Measured: three cycles at mode `000` report
`deleted=0`; the run immediately after `chmod 644` reports `deleted=1`.

**Deleting on it was considered and rejected.** The argument for reclaiming was that an unreadable
file is not yomi's problem to hold a whole tree hostage over. The argument against, which carried, is
asymmetry: refusing wrongly is repaired by a later change, deleting wrongly is not — and "delete a
source we could not read" is archive-verify-then-delete run backwards, which no local convenience
outweighs.

#### `StoreDir` — what sits at `archive/_scratch/<K>/`

`classify_store_dir` uses `symlink_metadata`, never `metadata`: the whole point is to see the link
rather than what it points at.

| State | Meaning | Archive | Reconcile | GC gate |
|---|---|---|---|---|
| `Absent` | nothing at the path | create it and proceed | nothing to prune → 0 | manifest read fails → refuse |
| `Own` | a real directory | write | prune | read and judge |
| `Foreign` | a symlink, a regular file, a device, **or a path this run cannot stat** | refuse the key | refuse | `Unverified { ForeignStoreDir }` |

**Three states, not a bool**, because the two predicates that were merged into this function already
disagreed on `Absent` and both were right: archive must proceed (it creates the directory), the
reconciler must not (there is nothing to prune). Collapsing them breaks one or the other.

`Err(NotFound)` is `Absent`; **every other `Err` is `Foreign`**. A path this run cannot even stat is
one it cannot prove it owns, and fail-closed is the only reading of that.

**The guard runs before the manifest is read, in all three layers.** Placed after, the foreign ledger
has already informed the decision — the retention window and the expected artifact set would both be
sourced from outside the archive tree. Measured on a build with only the gate's guard removed, against
a fixture whose store path was symlinked at a *valid* store for that tree: `deleted == 1`. Coverage
looked complete because it was complete — for a directory the run does not own — and the live tree was
destroyed on that evidence. **Foreign evidence authorizes destruction.** The gate's stake is the
largest of the three, because its output is a deletion.

**A symlinked store directory is refused, never repaired** — the opposite of the lock file's symlink
self-heal (§4). That file holds nothing, so removing the link node destroys nothing and a symlink
there is never legitimate state. A store directory holds archived data, and a symlink on it may well
be an operator who deliberately put the store on another volume. Replacing it would orphan that store
and silently begin an empty one. Refusing is reversible by hand; replacing is not.

**Accepted residual: the classification is not atomic with the use.** Between `classify_store_dir` and
the `create_dir_all`/`atomic_write` that follow, the path can be replaced. This is the same
plant-after-scan window `remove_tree_guarded` accepts, bounded the same way — the held `WriteLock` plus
single-user ownership — and it is stated here so no later layer mistakes the guard for a proof. It
raises the bar from "a symlink left lying around" to "a race won against a locked writer"; it does not
eliminate the class.

**Ownership depth is defined.** yomi asserts — and `ensure_layout` re-asserts on every mutating run,
before anything is created or chmod'd through them — that `~/.yomi/`, `archive/`, `quarantine/` and
`state/` are real directories it owns, refusing (exit 3) rather than repairing, for the same reason a
store directory is refused. Read-side commands do not run `ensure_layout`, and for them per-use
classification is the whole guarantee.

**The membership test is §5's global-versus-per-candidate rule, applied to paths.** A path belongs in
the fixed set exactly when a foreign one makes **every** subsequent operation unreliable — which is
what earns an abort. Each of the four qualifies without argument: a foreign `~/.yomi/` puts the whole
store elsewhere, a foreign `archive/` every stored artifact, a foreign `state/` the catalog every gate
depends on, and a foreign `quarantine/` every unredacted original — that last one an exfiltration
channel, not merely a misplacement.

**`archive/_scratch/` fails that test and is *not* in the set.** A foreign `_scratch` leaves transcript
capture, the catalog and the quarantine tree untouched; it is the root of one artifact family, not of
the store. Putting it in the fixed set converted a contained fault into a total outage — `archive`,
`gc`, `index` and `rescan` all refusing at exit 3, so transcripts stopped being captured because a
scratch subtree was wrong.

An earlier draft of this paragraph put it in the set, on the grounds that "without this rule a symlink
on `_scratch` classifies every key beneath it as `Own` and all layers proceed through it." **That
justification has expired.** Every layer that touches a scratch store now classifies the **root** as
well as the key — the writer, the reconciler, the GC gate, `verify` and `read`, five call sites — each
refusing before it opens anything beneath. The layout assertion had become pure duplication of a guard
already made five times per use, and its only remaining effect was the abort. (This is the second
justification in this document to expire the same way, after the `KEY_MAX` margin. A rule whose reason
is "otherwise X is unguarded" must be re-read when X acquires a guard.)

So `_scratch` stays out of the layout assertion entirely — no classify, no create, no chmod there.
**The creator asserts its mode instead**: the scratch writer, which already classifies the root before
`create_dir_all`, sets it 700 explicitly rather than inheriting a umask, for the reason §4 gives about
`Archiver` being a library type whose caller may never have tightened one.

**A key is resolved *through* the root, so the guard has to sit at both levels or it sits at neither.**
Every one of the four layers that touches a scratch store — archive's writer, the reconciler, the GC
gate and `verify` — classifies the root **and** the key. A foreign root makes every key foreign while
each key still classifies `Own` on its own, so a guard at the key level alone is defeated by moving the
level above it.

**Accepted residual: the assertion is not atomic with the writes it guards.** The classification is a
`symlink_metadata` on a path, and the `create_dir_all` and `set_permissions` that follow are path-based
too, so the whole set carries the plant-after-scan window a store directory carries — now at four
levels instead of one. Bounded the same way: the held `WriteLock` plus single-user ownership.

**Both writers descend by directory fd, and that closes less than it appears to.** `archive/` and
`quarantine/` are written through one module (`safefs`), which opens each level from its parent's
descriptor with `O_NOFOLLOW`. That removes the check-then-use window **for a symlink**: there is no
check, so there is nothing to race. It does **not** remove it for a directory swapped in for another
directory. `openat(fd, name, O_NOFOLLOW)` proves the name was not a link; it does not prove the name
still refers to the object this run reached a moment ago, and a `renameat2(RENAME_EXCHANGE)` against a
descent level involves no link at all. Measured against both the path-based writer this replaced and
the fd-descending one: an attacker exchanging a level for a directory of their own captured the
unredacted original in **200 of 200 rounds under each**. The technique is not a fix for that class,
and stating it as one would retire a residual that is still open. Closing it needs
`openat2(RESOLVE_BENEATH)` or an `st_dev`/`st_ino` re-check of the descended descriptor — a separate
design, bounded meanwhile by the same `WriteLock` and single-user ownership as everything else in this
paragraph.

**What the two writers still resolve by path** — a statement about the writers, not an inventory of
the store: `~/.yomi` itself, the outermost boundary `--home` names, above which there is no descriptor
to descend from; the `create_dir_all` of a root, which is where the caller's vouching stops; and
`classify_store_dir`, run per use at the scratch store dirs and at the head of the law-Q pass, where
it classifies the *quarantine root* — the heaviest of the three, since that one's refusal is a
`RefusedKey` that fails the run. That is where the technique goes next if the residual is ever judged
too wide.

**Deliberately not a claim about the rest of the store.** Bookkeeping outside the artifact trees — the
lock file, the catalog, `gc.log`, `shapes.json` — and the removal of stale scratch artifacts are all
still reached by path, some without `O_NOFOLLOW`. None of them holds an unredacted original and none
is what this paragraph is scoped to; taking an inventory of them is its own audit, and an earlier
draft of this sentence tried to state one and got it wrong.

#### `ManifestRead` — absent and unreadable are not the same

| Variant | Meaning |
|---|---|
| `Missing` | no manifest — a store dir never written, or a run that crashed before the ledger landed |
| `Unreadable` | a manifest exists but cannot be read or parsed; its contents are **unknown** |
| `Ok(ScratchManifest)` | parsed |

To a reader that only refuses, these are the same. To a caller that deletes they are opposites: the
first has nothing to contradict, the second says nothing at all about the artifacts beside it —
**including that they are unclaimed**. On `Unreadable`, archive leaves the key exactly as found:
nothing stored, nothing removed, and above all **the unreadable manifest is not overwritten**.
Replacing it with a ledger describing only the live tree would manufacture the confidence that lets
the *next* run delete every archive-only copy this one failed to mention — turning a refusal into a
one-run reprieve.

`ScratchManifest` gives every scalar a `default` so it parses exactly the set of manifests the GC
gate's old deserialize-only struct accepted (that one declared `entries` alone). Tightening it would
turn an old manifest into a permanently refused tree.

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

Globs match the session-relative path. `build_globs_nested` registers `**/<p>` alongside each `<p>`,
so the default `allow`/`deny` sets keep matching at every depth. The lossy `to_string_lossy` that
`globset` forces here is sound precisely because **a glob decision is not an identity**: two names
that collide in the glob string are merely classified alike, and each still carries its own distinct
key, its own manifest record and its own store path.

**The enumerator owns the session dir.** `ScratchDir` carries `session_dir` as a field rather than
letting archive and gc each re-derive it from a member path — two implementations with two failure
behaviours, one of which silently fell back to `tmp_root`. The enumerator is the only layer that knows
it first-hand. It does not follow `file_type`, so a symlinked slug or session directory is skipped
rather than walked out of `tmp_root`, and it sorts its output so a run's manifests, store writes and
GC candidates do not depend on filesystem order.

Consequence, stated because it is visible: `total_bytes` now counts the whole tree, so a tree that sat
just under `total_cap` may go over it and become manifest-only. That is the cap measuring what will
actually be deleted, which is what it was always meant to measure.

**Store law (S) — the store dir and the manifest are one ledger.** For a scratch key `<K>`, S has
**two halves, and they do not hold under the same conditions.** Stating them as one sentence — as an
earlier draft of this section did — is the single most likely way to get `yomi verify` wrong, so they
are separated here:

| Half | Statement | Holds |
|---|---|---|
| **S1 — set equality** | the set of **regular-file** `*.zst` under `archive/_scratch/<K>/` is exactly the set of `store_rel()` of the manifest's `stored: true` entries | **unconditionally.** Checkable for *every* `stored: true` entry, whatever else it carries |
| **S2 — content agreement** | each of those artifacts decompresses to its entry's `content_sha256` | **only for entries that have a `content_sha256`.** An entry without one is not a violation; it is **unverifiable** |

An entry with `stored: true` and no hashes is a real, existing population — every manifest written
before D2/R1 looks like that, and salvage deliberately preserves them — so an implementation that
reads S as one claim reports a violation on every legacy store, on every run. The same applies to an
entry whose identity does not decode: its `store_rel()` is *unknowable*, so it can be tested against
neither half.

**`yomi verify` must therefore report in three vocabularies, not one:** `violation` (S1 broken, or S2
broken where it applies), `unverifiable` (S2 inapplicable — no `content_sha256`; or an identity that
does not decode), and `foreign matter` (below). Only the first is a defect of the store; the second is
a statement about what the ledger can prove. Conflating them makes `verify` cry wolf on exactly the
stores that most need looking at.

S1 is scoped to **regular files** deliberately. A symlink or device named `*.zst` inside a store dir is
not something archive wrote, and reconciliation will not remove it — that would widen the delete
authority past "remove the artifacts we stored". It is therefore neither in S1's left-hand set nor
removable by the tool, and `verify` reports it as its own category, **foreign matter**: an
artifact-shaped object in the store that archive will neither claim nor clean up, and that only an
operator can resolve.

`archive` establishes S. `yomi verify` checks S. The GC gate's per-entry store re-check is a
*consequence* of S, not an independent claim. Nothing but `archive` writes into a scratch store dir.

**Reconciliation — the one delete authority `archive` holds.** Establishing S1 means archive removes
`*.zst` under `archive/_scratch/<K>/` that the manifest it just wrote does not claim. The authority is
bounded so that it cannot grow: **regular files only**, **`.zst` extension only**, **under this one
key's store directory only**. `manifest.json` has the wrong extension; `quarantine/` and every other
key lie outside the walked root, so a quarantined raw original stays recoverable; `WalkDir` does not
follow symlinks, so the walk cannot leave the store dir; and a store dir that is not `Own` is refused
before the walk begins. `--dry-run` reports the removals instead of performing them, and the run
report carries `scratch_orphans_removed` so a config change that discards stored bytes is loud, not
silent.

**Order: manifest first, then reconcile.** A crash between them leaves a store holding *more* than the
ledger claims — which the GC gate ignores and the next run cleans up. The reverse order would leave a
ledger claiming a `.zst` that is already gone, which refuses the tree until someone re-archives.

**Reconciliation refuses outright when any entry's identity fails to decode.** Such an entry names an
artifact whose path cannot be computed — `rel()` is precisely what would compute it — so it cannot be
held out of the orphan set, and every unnamed artifact would then be deleted as unclaimed. An
unreadable record is a reason to refuse, not a licence to destroy what it describes. The check lives
in the reconciler itself as well as in its caller, because a delete primitive must not depend on its
caller's discipline.

Such an entry is carried into the new manifest byte-for-byte with `present` untouched — we cannot tell
whether its file is live, and marking it either way asserts more than the record supports. **The
consequence is permanent and must be stated: that key never reconciles again.** Every subsequent run
re-carries the entry, the ledger stays incomplete, and stale artifacts accumulate with no correction.
This is the safe direction, but it is a state an operator has to leave, not one the tool leaves by
itself. `yomi verify` names such keys, and the repair is manual: correct or delete the offending
entry, or remove `manifest.json` entirely and re-archive.

**Salvage — a capture failure does not forfeit an earlier capture.** When the source read fails for an
entry policy meant to store, archive carries the prior run's capture forward instead of dropping the
claim: the live bytes are unreadable *now*, that `.zst` is the last copy of them, and dropping the
claim would make reconciliation treat it as unclaimed and delete a good archive over a permission bit.
Same law as a vanished file. The predicate is deliberately narrow and deliberately grounded in disk:

> the prior entry says `stored`, **and** `store_dir.join(rel.store_rel())` is a **regular file that
> exists**. Hashes are **not** required.

Grounding the claim in the artifact rather than in the prior ledger's word for it keeps S1 true in the
other direction as well: if that `.zst` vanished by some other route, no claim is made for an artifact
that is not there. And requiring hashes would forfeit exactly the pre-D2/R1 population above — **an
entry that cannot be *verified* is no more a licence to destroy its artifact than one that cannot be
*parsed*.** Absent hashes are carried across as absent: **hashes are never fabricated**, so the gate
keeps treating the artifact as unverifiable rather than gaining a claim it cannot check.

A salvaged entry therefore mixes moments — `bytes` is the live size now, `source_sha256` is the sha of
what was captured earlier. This is internally consistent (`source_sha256` is by definition the hash of
the bytes *as captured*) and unreachable in practice, because `capture_failed` makes the gate refuse
before any hash comparison. It is recorded here because it is the reason `verify` must never try to
reconcile `bytes` against `source_sha256` — see the U3 contract in §5.

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

**"Vanished" is decided by identity, not by a filesystem probe.** The retention pass compares the
prior ledger's identities against the set this run's walk produced — the *same* walk the GC gate
performs — so the two layers agree by construction on what "still here" means. A consequence worth
naming: a file that merely became unreadable or blacklisted during this run is treated as gone, and
its archive is retained. That is the direction that cannot lose data. A file that has come *back* is
not retained, because the live pass has already produced a fresh entry for it under current policy,
and two entries sharing one identity would be a self-contradicting ledger.

**A session directory with no files at all is still enumerated.** A tree whose files have *all*
vanished is the strongest case of the rule above: skipping it would leave the manifest asserting those
files are still present while their `.zst` sit in the store, and nothing would ever correct the
record. The cost is that such a tree also becomes a scratch GC candidate with no age signal — see the
known defects below.

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

### Scratch — known defects and their specified repairs

Recorded here because each is a stated contract that the current code does not yet meet. None is a
data-loss path; three are invariant violations and the rest are diagnosability gaps.

**D-S1 — the GC gate reads a live scratch file without the blacklist gate.** `verify_scratch_tree`
re-hashes each live file with a bare `std::fs::read`. §4 says a blacklisted path is never opened for
read **or** delete, and every other read path in yomi goes through `Blacklist::open_guarded` with the
inode check run against the opened fd. `evaluate_scratch` is not even given a `&Blacklist`. A
credential hardlinked over an archived entry's path, sized to match, is therefore opened and read into
yomi's address space; the hash is compared and discarded, so there is **no exposure**, but the §4
invariant is broken and the fd-pinned gate exists precisely to make this unreachable. Retention makes
the window persistent rather than transient — before it, a blacklisted path had no manifest entry to
match, so the lookup refused *before* the read. **Repair:** pass the blacklist into `evaluate_scratch`
and route the live re-hash through `open_guarded` + `sha256_stream`, treating `Denied` as a refusal of
the tree. Severity MEDIUM (invariant, not exposure).

**D-S2 — a scratch quarantine path is keyed by the lossy name.** The quarantine sub-path is built from
`ScratchEntry.path`, the display form. Two non-UTF-8 names collide there and one quarantined original
overwrites the other — the exact bug class `ScratchRel` exists to eliminate, surviving in the one place
where the lost object is an **unredacted original that exists nowhere else**. **Repair:** derive the
quarantine sub-path from the lossless identity (use `path_hex` as the component whenever it is
present). While there, drop the duplicated key: the path is currently
`quarantine/_scratch--<K>/<K>/<rel>`. Severity MEDIUM (loses a recovery copy, low probability).

**D-S3 — per-key failures abort the whole `archive` run.** `archive_scratch` returns `Err` for
per-key I/O — a failed `create_dir_all` (including `ENAMETOOLONG` from an over-long store key), a
failed `atomic_write`, a `read_to_end` that fails after the file opened — and `cli/archive.rs`
propagates it, so one bad scratch tree ends the run and every later source goes unarchived. This is
the same shape §5 already resolved for the GC commit loop: **a per-candidate doubt degrades to a skip;
only a global doubt aborts.** Note the asymmetry that makes it obvious — three of `read_source`'s four
failure paths are handled as `None` and the fourth is fatal. **Repair:** `archive_scratch` reports a
per-key refusal instead of returning `Err`; only catalog and lock failures remain `Err`. Severity
MEDIUM.

**D-S4 — a refused key is invisible to anything but stderr.** Every refusal path — foreign store dir,
unreadable manifest, undecodable entry, and (once D-S3 lands) a per-key I/O failure — is a
`tracing::warn!` and nothing else. Under cron, stderr is discarded, so "this key is silently skipped
on every run" cannot be seen in `--json`. **Repair:** a `scratch_keys_refused` count plus a
`scratch_refusals` array of `{key, reason}` in the archive report, with one human line per refusal.
The reason set is exactly the refusal paths: `ForeignStoreDir`, `UnreadableManifest`,
`UndecodableEntry`, `StoreKeyCollision`, `StoreWriteFailed`. Severity LOW, but it is what turns every
other refusal in this list from silent into operable.

**U6 raised this from theory to defect.** `StoreKeyCollision` was an unreachable variant in that list
when it was written; it is now constructed by archive, by the GC gate and by `verify`. A refused
collision is a key that will be skipped on **every** run until an operator renames a directory — the
one refusal in the set that never clears itself — and under cron it is announced only to a discarded
stderr. It is also the exit designed for the ledger-outlives-its-tree state (§3), which has no other.

**D-S5 — a blacklisted file makes its tree permanently unreclaimable, invisibly.** A blacklisted
candidate is skipped before it is manifested, so the GC gate's live walk finds an unmanifested file and
refuses the tree forever, reported only as `NoCatalogRow`. Refusing to delete a tree containing a
credential hardlink is correct; doing it without ever saying so is not, and a merely *benign* denylist
hit produces the same permanent, unexplained refusal. **Repair:** record it, as `capture_failed`'s
sibling — `blacklisted: true`, with **`bytes: 0` and no `stat`**, so nothing about the denied inode
(not even its size) is recorded. The gate refuses on the flag with its own reason (`SkipReason::
Blacklisted`, which already exists for the file path), checked immediately after the entry lookup and
before any size or hash comparison. `read --scratch` lists it. Purely diagnostic: `remove_tree_guarded`
already aborts a whole-tree removal on a denylisted inode, so safety is unchanged. Severity MEDIUM
(permanently unreclaimable, with zero diagnosability).

**How it is recorded matters more than that it is.** The obvious implementation — push the candidate
into the live set with `stored: false` — **destroys an archive**, and the mechanism is the salvage
defect wearing new clothes. A live entry is not a retention candidate, so the prior ledger's record for
that identity is dropped; being `stored: false` it is not in the expected set either; so reconciliation
finds its `.zst` unclaimed and removes it. A credential hardlinked over `scratchpad/a.md` would delete
the archive of the file it displaced. `p7_credential_hardlink_swapped_in_after_the_walk_captures_
nothing` catches exactly this.

The two facts are orthogonal and were coupled only by the accident that manifesting an entry meant
entering the live set:

1. this identity has an archived copy from an earlier run — **retain it**, the `.zst` is the last copy;
2. this identity is currently occupied by a denylisted inode — **refuse the tree, and say why**.

So: a denylisted candidate **stays out of the live set** (retention is untouched, and no salvage
extension is needed), and `blacklisted: true` is stamped **after** the prior tail is assembled — onto
the retained entry if one carries that identity, or onto a fresh `bytes: 0` entry appended alongside
the tail if none does. Stamping rather than appending is what keeps this from manufacturing the
duplicate identity §5 reports.

`present` is unchanged by the stamp. §3 already rules that a file which "merely became unreadable or
blacklisted during this run is treated as gone, and its archive is retained" — `present: false` is that
conservative reading, deliberately not a claim about whether the *name* is occupied, and
`blacklisted: true` is what answers that. The existing test expectation therefore stands; it gains an
assertion, it does not change one.

One structural note for the implementer: `entries` and `kept` are two parallel vectors held in
correspondence **by index** (the store pass zips them). Any entry that is manifested but has no
live file to read breaks that alignment, which is why the stamp happens after the tail rather than
inside the candidate loop. If a future change needs to manifest more such entries, make the
correspondence explicit rather than positional.

**D-S6 — an empty session tree is a permanently `Protected` scratch candidate.** With every session
dir enumerated, a tree with no files yields `newest: None`, which falls through to `age = 0` and so is
`Protected { TooYoung }` forever. It is reclaimed instead by the `empty-dirs` target, so nothing leaks
— but `gc` plans the same path twice with contradictory verdicts and writes a misleading `protect`
record. **Repair:** an empty tree has no age signal and should not be described as too young; give it
its own `ProtectReason` (or hand it to `empty-dirs` explicitly). Severity LOW (honesty of the plan and
the audit log).

**D-S7 — `SkipReason::NoCatalogRow` is a three-way misnomer on the scratch path.** Scratch has no
catalog rows at all, and the one reason covers "no manifest", "unreadable manifest" and "a live file
absent from the manifest" — three different operator actions. `OpenFailed` likewise now covers both "we
cannot open it now" and "the archiver could not capture it then". **Repair:** split into `NoManifest`,
`UnreadableManifest`, `UnmanifestedFile` and `CaptureFailed`. Log vocabulary only, no behaviour
change. Severity LOW. See the reason/kind table in §5.

**Accepted, not repaired: `--dry-run` cannot forecast a capture failure.** The store pass does not run
under dry-run, so no source is opened and `capture_failed` is never discovered. Dry-run's contract is
"what the current policy would store", not "what will succeed" — the same standing that §6 gives the
rescan preview: a previewed outcome is a best-effort forecast, not a guarantee.

**Resolved, no action: `StoreDir::Absent` versus `Own` at the read side.** `verify` and
`read --scratch` enumerate `archive/_scratch/*/`, so they only ever see directories that exist and
`Absent` cannot arise. The third state earns its keep on the archive path alone.

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

`read` never opens `quarantine/` at all. `verify` does not either, except under an explicit
`--quarantine`, and the exception is drawn exactly there because the guarantee changes character at
that boundary: over the store it is *structural* (every reachable byte is post-redaction, so a bug
that echoed content could not leak a secret), while over `quarantine/` the bytes **are** the secret
and the same bug would. What the default path keeps is the stronger property — the unattended nightly
command never opens a file containing a raw secret — and law Q is split so that the checks which catch
the defect that actually occurred are the ones that need no reads at all (§4).

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
- **`$YOMI_HOME` and everything under it** — the store this run writes, resolved from `Env`, not the
  `~/.yomi` default (`--home` and `$YOMI_HOME` both move it)

A blacklisted path is never opened for read **or** delete. Test-proven in CI (P1 gate).

**Self-exclusion (no recursive ingestion).** `quarantine/` holds unredacted originals by design, so a
store placed inside a walked source root composes with `archive --include scratch`, which enumerates
`<tmp_root>/<slug>/<uuid>/` **entire**: run N reads run N-1's raw secrets back as ordinary
`*.md`/`*.json` work files, stores them a level deeper, and quarantines them again — monotonic and
unbounded, with every copy keeping the original's name so it never leaves the default allow globs. The
denylist is the only layer that can refuse this, and the default `~/.yomi` was safe only by sitting
outside the three source roots by accident. Registering the store here rather than filtering in the
scratch walk keeps it on the one gate every read and every unlink already passes. Consequence, and the
intended one: a scratch tree containing the store is never reclaimed, because its manifest carries
`blacklisted: true` entries. Measured in `tests/p18_self_ingest_break.rs` (two-pass and six-pass).

**Patterns are anchored through the same normalization as their subjects.** Each entry's leading
metacharacter-free path is resolved with `abs_normalize` at compile time — the function `path_denied`
runs on every subject — and only then escaped, so `$HOME` being a symlink (NFS home, bind mount,
`/home` → `/mnt/home`) cannot leave pattern and subject naming different strings. It could: patterns
were built from an unresolved `$HOME` while every subject was canonicalized, and the three entries with
no inode backstop behind them — `~/.zaibatsu/**`, `versions/**`, `locks/**` — matched nothing and were
archived. Resolving the whole literal prefix rather than only the home also covers a symlink *inside* a
denied path (`~/.zaibatsu` → `/mnt/secrets`), which no per-entry inode snapshot could, and the escape
keeps a metacharacter in a real directory name (`~/a[1]`) a literal instead of a character class that
matches something else. `abs_normalize` resolves the longest **existing** ancestor and appends any
missing tail lexically, so the two sides agree whether or not a subject's leaf is present.

**Hardlink defense.** The blacklist matches on a normalized absolute path *and* on the inode
`(dev, ino)` of the credential files, so a hardlink to a credential placed at a non-denied path (e.g.
inside `projects/`) is still refused. The cardinal credential files (`.credentials.json`,
`.claude.json`, `mcp-needs-auth-cache.json`) are **re-stat'd live on every check**, so a hardlink
created *after* the denylist was built is still caught. Rolling `backups/*` use a compile-time inode
snapshot (lower value; mid-run rotation is a narrow, non-cardinal window). Symlinks are caught by the
normalization above, on both sides of the comparison — the pattern's as well as the subject's.

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

- **HIGH** finding → redact span in stored copy with `‹REDACTED:kind:sha8›` (sha8 = hash of the secret, for dedup/audit, **never the secret**) **and** move the unredacted original to its mirrored quarantine path — `quarantine/<X>` for the artifact stored at `archive/<X>.zst`, per the mirror rule below (mode 700, index-excluded). Recoverable if false positive.
- **MED** → redact in stored copy, no quarantine.
- **LOW** → **flag only** in `manifest.secret_scan.flagged`, surfaced via `yomi status --secrets` for human review. Not redacted (too FP-prone to auto-mutate on entropy alone).
- **Allowlist** `[scan.allow]` (regexes / secret-sha8s of known-benign, e.g. doc example keys) suppresses a finding entirely.

Raw secrets **never** reach the index or `conversation.md` — those derive from the already-redacted stored artifact.

### Quarantine identity, and law Q

Quarantine holds **unredacted originals**, and for a source GC has since deleted it holds the only
copy that exists anywhere. Everything below follows from that one fact.

Until now the tree had **no identity rule at all** — three call sites each built a path their own way,
and because nothing was ever asserted about the result, nothing could be violated and nothing was
checked. That is the failure mode this document has hit three times: **a concept with no owner
accumulates defects.** The consequences it accumulated:

- **A scratch original is keyed by the lossy display name.** The path is built from `ScratchEntry.path`,
  so two non-UTF-8 names collide at `U+FFFD` and **one quarantined original overwrites the other** —
  the exact class `ScratchRel` exists to eliminate, surviving in the one place where the lost object
  has no other copy.
- **The key is doubled**: `quarantine/_scratch--<K>/<K>/<rel>`, once as the synthetic session uuid and
  once as a path component.
- **Archive and rescan disagree about the same artifact.** Archive uses the *session*-relative stored
  rel (`transcript.jsonl`), rescan the *archive*-relative stored path
  (`<slug>/<uuid>/transcript.jsonl`). Both land under `quarantine/<uuid>/`, so nothing is lost — but
  one artifact can have originals at two paths and neither is canonical.

**The rule: quarantine mirrors the archive.**

> `quarantine/<X>` holds the unredacted original of `archive/<X>.zst`.

The quarantine path is the artifact's **archive-relative stored path**, with the compression suffix
removed, and nothing else. One derivation, used by every writer. It needs no naming scheme of its own,
and that is the point: an original is named by the identity of the artifact it is the original of, so
it inherits the store's uniqueness and its losslessness rather than restating them.

| Artifact | Store | Quarantine |
|---|---|---|
| transcript | `archive/<slug>/<uuid>/transcript.jsonl.zst` | `quarantine/<slug>/<uuid>/transcript.jsonl` |
| subagent meta (uncompressed) | `archive/<slug>/<uuid>/subagents/<x>.meta.json` | `quarantine/<slug>/<uuid>/subagents/<x>.meta.json` |
| scratch file | `archive/_scratch/<K>/<rel>.zst` | `quarantine/_scratch/<K>/<rel>` |

Three properties, each load-bearing:

- **Injective.** Store paths are unique by construction, and stripping the suffix does not merge any
  two of them: every *compressed* artifact's store path is its logical path with exactly one `.zst`
  appended, so removing it is that map's inverse; the only *uncompressed* artifacts are subagent metas,
  whose names end `.meta.json` and so are disjoint from the stripped set. Two originals can no longer
  land on one path, which is the whole defect.
- **Lossless.** A scratch store path is derived from raw `ScratchRel` bytes (§3), so the quarantine
  path is too — provided the path is carried as `Path`/`OsStr` end to end. The current sanitizer takes
  `&str`, which is where the bytes are lost; it must take a path.
- **The `<session-uuid>` level disappears.** The archive layout already partitions by session, so
  re-partitioning by uuid was redundant — and it is the source of both the doubled `<K>` and the
  archive/rescan divergence, since the two call sites differed only in how much of the path they had
  already spent on that level.

**Every directory level under `quarantine/` is chmod 700 explicitly.** Today only the first level is,
which was sufficient while the layout was two deep and a mutating command's umask covered the rest. The
mirrored layout is deeper, and `Archiver` is a library type that a caller can use without
`ensure_layout` ever having tightened the umask. Do not rely on inherited modes for a directory tree of
raw secrets.

**The writer replaces the destination name; it never opens it.** An original is staged under a temp
sibling opened `O_EXCL`, moded, and `renameat`-ed into place — the same writer `archive/` uses. The
alternative, opening the destination `O_CREAT|O_TRUNC|O_NOFOLLOW`, was what this design shipped first,
and it is wrong for three separate reasons. **`O_NOFOLLOW` is a statement about symlinks and about
nothing else.** A **hard link** planted at the destination passes it, and `link(2)` needs no
privilege: opening that name in place deposits the unredacted original into an inode the attacker
already holds a second name for, and re-modes their file to 600 on the way. Measured, deterministic,
1/1 — the same-uid threat model this section already adopts for the credential-hardlink defence on the
read side. That is the class §3 calls an exfiltration channel rather than a misplacement. A **FIFO**
planted there passes it too, and a blocking `open(O_WRONLY)` on a FIFO with no reader never returns:
one `mkfifo` stops archiving indefinitely, with no error and no log line. And `O_TRUNC` **manufactures
a state Q1 is structurally blind to** — the old bytes are gone at `openat` time, before the first new
byte, so a crash or an `ENOSPC` mid-write leaves a *truncated original at the claimed path*. Q1 is a
`stat`; a truncated original satisfies it, counts as `present`, and passes nightly `verify` in
silence. Only `verify --quarantine` could ever see it, and that is attended and never in cron. A
rename cannot produce that state: the file at the claimed name is always a complete original of
something.

**What this costs, stated rather than buried.** A symlink at the destination goes from *refused* to
*replaced* — the link node is destroyed and the bytes land in a fresh inode inside a 700 tree, with
the link's target untouched and un-re-moded. That is the right trade in this direction: refusing hands
an attacker a **denial-of-archival** primitive, because every caller treats a quarantine failure as a
refusal to archive the artifact at all. The store side already ruled the same way.

**Crash residual: a temp holding raw secret bytes.** The staging file is unlinked on drop, which
covers every ordinary early return but not `SIGKILL`, OOM or power loss — and nothing removes files
from `quarantine/` by design, so no reconciler sweeps it. The ruling is to **report it, not to mint a
finding for it**: a temp is a file no derivation claims, which is exactly what Q2's `QuarantineStray`
says, at the advisory severity Q2 gives it and `requires_exclusion` already. What it replaces is worse
and invisible — the `O_TRUNC` residual above, a corrupt original at the *claimed* path that the
default pass cannot see. Trading an invisible corruption for a visible stray is the direction to trade
in.

**And that residual carries, narrowly, the same shape this whole ruling argues against.** A staged
write opens its temp `O_EXCL`, and the temp is `<name>.tmp-<pid>-<seq>` with the sequence counter
global to the *process* — so a surviving temp blocks a later write of the same artifact exactly when a
recycled pid reaches the same sequence number, and that collision is an `EEXIST` that refuses the
quarantine, which refuses the archive. It is stated because the argument for replacing the destination
is that *refusing* hands an attacker a denial-of-archival primitive; a residual with the same shape
has to be weighed on the same scale rather than excused by being small. It is small: it is not new
attack surface, since anyone who can write in that directory already holds the cheaper version —
planting a directory at the destination name, which is refused by construction — and it turns on a pid
recycle no attacker can aim. Priced, not dismissed.

**Not addressed either way: durability.** Neither writer `fsync`s, before or after. A rename without
an `fsync` of the file can, on power loss, leave the old file or an empty new one. This is not a
regression — the path-based writer did not fsync either — and it is named here so it is not mistaken
for a property the rename bought. If durability is ever wanted it is `fsync(file)` before the rename
and `fsync(dir)` after, in `safefs`, so `archive/` gets it on the same terms.

**Existing quarantine trees are never renamed, moved or removed.** They may hold the only copy of an
original, and no naming improvement is worth transposing such a tree. The new rule governs **writes**;
the legacy layouts stay exactly where they are. This costs nothing today because **nothing reads
`quarantine/`** — there is no consumer to confuse — and it is the same choice §3 makes for store keys:
record and detect rather than rename.

Recovering an original therefore needs a reader that knows all three layouts (current, `quarantine/
<uuid>/<session-rel>`, and `quarantine/_scratch--<K>/<K>/<lossy-rel>`). That reader is deliberately
**not** part of this work: a command that emits unredacted originals is a new exposure surface and
deserves its own design, not a corner of a path-naming fix.

#### Law Q — what is asserted about the quarantine tree, and who checks it

Q is stated in four parts because they do not cost the same thing to check, and the difference decides
who may check them.

| | Assertion | Cost |
|---|---|---|
| **Q0 — injectivity** | no two artifacts map to one quarantine path | ledger only, opens nothing |
| **Q1 — existence** | every artifact recorded `quarantined` has a file at its quarantine path **or at one a superseded derivation produced** | `stat` only |
| **Q2 — no strays** | every file under `quarantine/` is claimed by some artifact | `readdir` only |
| **Q3 — integrity** | the original hashes to the artifact's `source_sha256` | **opens a raw secret** |

Q3 is checkable with no new field: the bytes handed to quarantine are exactly the bytes
`source_sha256` describes, at every call site, for both session artifacts and scratch.

**Q1's fallback is not a weakening; leaving it out was an inconsistency in this section.** Three
paragraphs above, this design rules that existing quarantine trees are **never** migrated — so every
original written before the mirror rule legitimately sits at a path the current derivation does not
produce. A Q1 that accused on that would report this document's own ratified behaviour as a defect, and
would do it nightly, on exactly the stores with the most history: the outcome §5 refuses when it keeps
a legacy population from failing `verify`. So Q1 asks the current path first, then the superseded ones,
and reports the second case as **legacy layout** — advisory, and the same fact Q2 reports for an
unowned file, named here against the artifact that owns this one. `QuarantineMissing` then means
*present at neither*, which is a stronger and more exact accusation than the one it replaces: the
original is genuinely gone.

Deriving a superseded path and `stat`ing it is not the reader §4 leaves to its own design. Nothing in
law Q can emit an original; the fallback opens nothing.

**The three checks range over three different sets, and collapsing them is wrong in both directions.**

| | Set | Why |
|---|---|---|
| **Q0** | artifacts recorded `quarantined` | a collision destroys an original only when both sides wrote one; reporting a pair where only one did asserts damage that has not happened |
| **Q1** | artifacts recorded `quarantined` | the obligation to have an original is exactly what the flag records |
| **Q2** | **every** artifact | the mirror rule says `quarantine/<X>` belongs to `archive/<X>.zst` — the claim is a property of the artifact, not of any run's finding |

Q2's wider set is what its own assertion says: *claimed by some artifact*, not *by a quarantined
artifact*. It has to be. An artifact quarantined by one run and found clean by a later one has
`quarantined: false` in the current ledger while its original is still on disk — nothing removes it, by
design — so the narrow set would report the design's own behaviour as foreign matter, again in the
store with the most history first.

**Q0 is the one that catches the collision, and it opens nothing.** Q1 does not: when two artifacts
collided onto one path, that path exists, so existence is satisfied for both while one original is
gone. Detecting that damage — past and future — is a pure computation over the ledger: derive every
quarantined artifact's expected path and look for a repeat. The most valuable check here is also the
cheapest and the safest.

**`yomi verify` owns Q0, Q1 and Q2, and does not open `quarantine/`.** This is a narrower guarantee
than the one it makes about the store, deliberately. The store's non-exposure is structural because
every reachable byte is post-redaction, so even a bug that echoed content could not leak a secret. In
`quarantine/` the bytes **are** the secret, so the same bug would. The routine, unattended, nightly
command must therefore keep the property that it never opens a file containing a raw secret — worth
more than nightly bit-rot detection over a small tree, and precisely the property the rest of §4 leans
on. Q0/Q1/Q2 need only the ledger, `stat` and `readdir`, and they cover the defect class that actually
occurred.

**Q3 lives behind an explicit `verify --quarantine`.** Attended, deliberate, never in cron. It hashes
and drops, exactly as §5's store pass does — the finding names a path and a mismatch and never carries
content — but the flag is what keeps that discipline out of the default path, where discipline is the
wrong kind of guarantee.

**Q2 must recognise the legacy layouts.** With no migration, every original written before this rule
sits at a path the current derivation does not produce, and reporting each as a stray would bury the
signal in exactly the stores with the most history. A file matching a known legacy layout is reported
as **legacy layout** — advisory, non-failing, and doubling as the inventory an operator would need to
reconcile the tree by hand. Anything matching neither is a stray, also advisory: like foreign matter in
a store dir (§5), it is something only an operator can resolve.

**Scratch needs one field before Q applies to it.** `ScratchEntry` records no `quarantined` flag, so
for a scratch file the ledger does not say an original was ever written and Q0/Q1 cannot even be
asked. The addition is the same additive shape as `present`, `capture_failed` and `not_stored`
(§3) — default false, emitted only when true. Session artifacts already carry the flag, in both the
manifest and the catalog. Salvage carries it forward with the capture it salvages: the flag describes
the `.zst` that is still there and the original that still backs it, so dropping it would have the
ledger deny an original law Q would then read as a stray.

**The quarantine root is classified like any other store path.** `stat` and `readdir` both follow a
symlink, so a root that is not a directory this run owns would have every check attesting about another
tree — the same reason §5 classifies the scratch store root, applied to the one path law Q is stated
over. An **absent** root does not stop the pass, and the asymmetry is the point: a fresh store has no
claims either, so it reports nothing and creates nothing (W1/R8), while a store whose quarantine tree
was deleted out from under a ledger that still claims originals must not pass in silence — which is
precisely what an early return on absence would buy it. Q0 needs no tree at all, and Q1's stats are
true statements about an empty one.

**Q1 traverses; it does not classify every level.** `symlink_metadata` declines to follow only the
*final* component, so a symlinked directory inside `quarantine/` is followed and a file beneath it can
satisfy Q1 — an existence check answered by a file that may not be ours. This is not made silent: the
link node itself is reported by Q2 as foreign matter, because the sweep does not descend it either.
Classifying every directory level is disproportionate for a tree nothing reads, so the honest statement
of Q1's strength is: *a file is at the path*, and **Q3 is what proves it is the right file**.

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

**Which reason can arise for which candidate kind.** `SkipReason` is shared by all three gate paths,
and nothing in the type says which reasons a given path can produce — so a reader of `gc.log` cannot
tell a scratch refusal from a transcript refusal by the reason alone. The mapping, recorded here until
the type carries it:

| `SkipReason` | `File` | `ScratchTree` | `EmptyDir` |
|---|:--:|:--:|:--:|
| `Blacklisted` | ✓ | — | — |
| `OpenFailed` | ✓ | ✓ | ✓ |
| `NoCatalogRow` | ✓ | ✓ *(misnomer — see below)* | — |
| `ShaMismatch` | ✓ | ✓ | — |
| `EmptyContentSha` | ✓ | — | — |
| `StoreReverifyFailed` | ✓ | ✓ | — |
| `NotIndexed` | ✓ | — | — |
| `ForeignStoreDir` | — | ✓ | — |
| `StoreKeyCollision` *(§3, specified)* | — | ✓ | — |

On the scratch path, `NoCatalogRow` is doubly wrong: scratch has **no catalog rows at all**, and the
one reason covers "no manifest", "a manifest that will not parse" and "a live file the manifest does
not mention" — three different operator actions. `OpenFailed` likewise now covers both "this file
cannot be opened now" and "the archiver could not capture it then". §3 D-S7 specifies the split
(`NoManifest` / `UnreadableManifest` / `UnmanifestedFile` / `CaptureFailed`); it is log vocabulary
only, with no behavioural change.

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
law S (§3) per store dir.

**The contract, in the three vocabularies §3 requires, plus one for a key never examined.** Only
`violation` is a defect of the store; `unverifiable` is a statement about what the ledger can prove;
`foreign matter` is something only an operator can resolve; `refused key` is a key whose ledger could
not be trusted enough to read, or whose reading would have meant trusting something outside the
archive tree. The first and the last fail the run.

| Check | Outcome when it fails |
|---|---|
| the store **root** `archive/_scratch/` classifies `Own` | `ForeignStoreDir` — **refused key**, filed under `_scratch`. Nothing below is attempted; `read_dir` follows a symlink, so without this the whole store could be enumerated from outside the archive tree |
| the store root enumerates | `UnreadableStoreRoot` — **refused key**, filed under `_scratch` |
| the store dir classifies `Own` | `ForeignStoreDir` — **refused key**, not a violation. Nothing below is attempted; a foreign ledger must not be read at all |
| `manifest.json` parses | **violation** — `NoManifest` or `UnreadableManifest`, kept distinct (the gate would refuse this tree either way; `verify` says which) |
| the manifest's recorded identity reproduces the key it sits under, and — when a selector picked this key by name — names the session asked for | `StoreKeyCollision` — **refused key** |
| the recorded identity decodes | `UndecodableIdentity` — **unverifiable**; the collision guard is inactive for this key |
| every entry's identity decodes | `UndecodableEntry` — **unverifiable**, per entry — **and** `UnreconcilableKey` — **refused key**, once per key |
| every `stored: true` entry's `.zst` exists as a regular file — **S1** | `MissingArtifact` — **violation** |
| every `stored: false` entry has no `.zst` at its `store_rel()` — **S1** | `UnclaimedArtifact` — **violation** |
| every regular-file `*.zst` in the store dir is claimed by a `stored: true` entry — **S1** | `OrphanArtifact` — **violation** (the orphan check; catches drift from outside) |
| each claimed artifact decompresses to its `content_sha256` — **S2** | `ContentMismatch` — **violation** *only if* the entry has a `content_sha256`; otherwise `NoContentHash` — **unverifiable**, never a violation |
| every `*.zst` that is **not** a regular file | `ForeignArtifact` — **foreign matter**; archive will neither claim nor remove it |
| no two entries name the same identity | `DuplicateIdentity` — **violation**, once per duplicated identity |

Exit 2 on any `violation`, and on any `refused key`. `unverifiable` and `foreign matter` are reported
and do **not** by themselves fail the run: a legacy store full of pre-D2/R1 entries is not broken, and
a `verify` that fails on it every night is a `verify` that gets ignored.

**Root-level findings are filed under the key `_scratch`, and cannot collide with a real one.** Every
store key contains `--` — the plain form is `<slug>--<uuid>` and the hex form begins `_hex--` — and
`_scratch` does not. So the root reuses the `key` field rather than needing a second shape of finding,
and no store directory can ever impersonate it.

**`UnreadableStoreRoot` is separate from `ForeignStoreDir` because the diagnosis differs.** A root that
will not enumerate is not foreign; it is ours and unreadable. Its reachable cause is narrow — a failing
`stat` already maps to `Foreign` in `classify_store_dir`, so only a root that stats as a directory and
still refuses `read_dir` arrives here (an `x` bit without an `r` bit). Reusing `ForeignStoreDir` would
send an operator looking for a replaced store path instead of a permission bit, which is the same
misdiagnosis §4 refuses when it keeps lock contention apart from an unsupported `flock`.

**`UnreconcilableKey` is a refused key, not a note.** An undecodable entry produces *two* findings
because it is two facts at two scopes: the entry cannot be checked (`unverifiable`), and the key can
never be reconciled again for as long as the entry stands (§3). An earlier draft of this section called
the second one "a key-level note", which is wrong — a note that does not move the exit code is a note
that gets ignored, and §3 says plainly this is "a state an operator has to leave, not one the tool
leaves by itself". A store that will never self-correct must not be reported as fine.

The cry-wolf objection that keeps `NoContentHash` non-failing does not apply here, and the difference
is what decides it: a hash-less entry is a **legacy population** — every pre-D2/R1 manifest is full of
them and nothing is wrong. An undecodable entry is not a population at all. `ScratchEntry::new` builds
from an already-validated `ScratchRel` and `manifest_fields()` round-trips by construction, so archive
**cannot emit one**; it arises only from corruption or hand-editing. There is no nightly noise to fear
and a permanent degradation to surface.

**The rows above are checks, not a partition of objects.** Two rows can hold of the same path, and
whether both are reported depends on whether they are two facts or two names for one:

- **One fact, one name.** A `.zst` sitting at a `stored: false` entry's `store_rel()` satisfies both
  the `UnclaimedArtifact` row and, read literally, the orphan row. It is reported **once**, as
  `UnclaimedArtifact`: the entry *explains* that object, so the orphan sweep must not also claim it is
  unexplained. Implementation follows from that reading — an artifact any entry accounts for, by
  claiming **or** by disclaiming, is removed from the orphan sweep's input. Giving one object two
  names is the misdiagnosis class D-S7 and the `InodeDriftOrBlacklist` collapse already correct.
- **Two facts, two names.** A **symlinked** `.zst` at a `stored: true` entry's path yields *both*
  `MissingArtifact` and `ForeignArtifact`, deliberately. The ledger claims a regular-file artifact that
  is not there (archive can fix that by re-archiving) **and** an artifact-shaped object archive will
  never touch is sitting in the store (only an operator can clear it). Neither implies the other — a
  claimed path with nothing at all at it is only `MissingArtifact`; a stray symlinked `.zst` at an
  unclaimed path is only `ForeignArtifact` — and the two call for different actions.

**The orphan sweep does not run at all on a key with an undecodable entry.** The reasoning §3 gives for
reconciliation refusing there transfers verbatim: that entry's `store_rel()` is *unknowable*, so a
leftover artifact may well be its, and calling it unclaimed would be the same false accusation
reconciliation declines to make. `UnreconcilableKey` says the true thing instead.

**`StoreKeyCollision` is reachable as of U6, and `verify` asks a store-side form of the question.**
The GC gate compares the recorded identity against the *live* tree; `verify` has no live tree — that is
the gate's half — so it makes the two statements it can from the store alone. First, **the recorded
identity must reproduce the key it sits under**: a manifest that fails that describes some other tree,
and every finding below it would be a statement about that one. Second, **when a selector picked this
key by name, the ledger must agree the name meant that session** — the plain form's last residual
(§5, resolver), closed here at no extra open because the manifest is already in hand. Both were added
by the implementation and both are adopted; the first is a check the design did not ask for and should
have.

**Symlinked *directories* inside a store dir are not descended**, by the reconciler or by `verify`
(`WalkDir` does not follow them). Entries resolving through one therefore read as `MissingArtifact`
and their contents are never opened. That is the safe direction, and one more thing only an operator
can clear.

**`DuplicateIdentity` is a violation, not a refused key.** `read --scratch` already detects two rows
naming one identity, serves the row the store corroborates, and tells the operator to run
`yomi verify` — which until now could not see the defect at all, so the referral went nowhere.

A refused key means *the key was not examined*: its ledger could not be trusted to be read, or reading
it would have meant trusting something foreign. A duplicate prevents none of that. Both rows decode,
both are checkable against S1 and S2, and — because they name one identity they name one artifact path
— the orphan sweep stays sound (the path is accounted once) and reconciliation stays enabled (it
refuses only on an identity that will not decode, and these do). Everything remains examinable, so what
is broken is the ledger, and a broken ledger with an intact store is a **violation**.

Like `UndecodableEntry`, this is not a population: the live pass yields one entry per walked path and
the tail skips identities already live, so `archive` cannot produce one. Unlike `UndecodableEntry`, it
also does not self-correct — two prior rows sharing an identity are both carried forward as vanished
on every subsequent run. **`prior_tail` should collapse retained entries by identity**, so archive
cannot propagate a duplicate any more than it can create one; the manual repair remains the remedy for
one already on disk.

**It does not require exclusion.** It is a property of the manifest alone, which is read atomically
(temp-write + rename), and it compares nothing against the store — the same category as
`UndecodableEntry`, `UnreadableManifest` and `NoContentHash`. A concurrent `archive` cannot produce one
transiently, because it cannot produce one at all.

Report it **once per duplicated identity**, and account the artifact once: two rows on one path must
not double-count `verified`, nor draw both a `verified` and a `ContentMismatch`.

#### The quarantine pass — law Q

`verify` also attests to the quarantine tree, under the split §4 defines: **Q0** (no two artifacts map
to one quarantine path — ledger only), **Q1** (every artifact recorded `quarantined` has a file at its
path — `stat` only), **Q2** (every file under `quarantine/` is claimed by an artifact — `readdir`
only). None of them opens a file, which is the property that lets them run in cron over a tree of raw
secrets.

| Finding | Class | Needs exclusion |
|---|---|---|
| `QuarantineForeignRoot` — `quarantine/` is not a directory this run owns | **refused key** | no |
| `QuarantineCollision` — two artifacts derive one quarantine path (**Q0**) | **violation** — one original has overwritten another | no |
| `QuarantineMissing` — an artifact recorded `quarantined` has a file at neither its path nor any superseded one (**Q1**) | **violation** | no |
| `QuarantineLegacyLayout` — a file at a path a superseded derivation produced, whether found for a claim (**Q1**) or unowned (**Q2**) | **foreign matter** — advisory; also the inventory for a by-hand reconciliation | no |
| `QuarantineStray` — a file matching no derivation, current or legacy (**Q2**) | **foreign matter** — advisory | **yes** |
| `QuarantineMismatch` — the original does not hash to `source_sha256` (**Q3**) | **violation** | **yes** |
| `QuarantineNoSourceHash` — Q3 was asked and the ledger records no `source_sha256` | **unverifiable** | no |

Q0 is the check that catches the collision, and Q1 is not: when two originals collided onto one path
that path exists, so existence holds for both while one original is gone. Q0 also finds the damage
retrospectively, from the ledger alone.

**The exclusion column follows from the write order, which is the same at every writer: the original is
quarantined *before* the store write and before the ledger update.** So a concurrent `archive` can
transiently produce a file no row yet claims — the Q2 direction, hence `QuarantineStray` downgrades —
but never a claim whose file is missing, hence Q1 stands. Nothing ever removes a file from
`quarantine/`, which closes the other direction. `QuarantineMismatch` downgrades because re-quarantining
an artifact whose source changed rewrites the original in place, so mid-run the file and the ledger's
`source_sha256` legitimately disagree. Q0 is ledger-only, and a legacy-layout path is one no current
writer produces at all.

**Q3 — the original hashes to the artifact's `source_sha256` — runs only under `verify --quarantine`.**
It hashes and drops, exactly as the store pass does, so no finding carries content; the flag exists so
that opening raw secrets is an attended decision rather than a nightly habit (§4).

**When Q3 is asked and cannot be answered, it must say so.** A claim carrying no `source_sha256` is not
currently produced by any writer — `quarantined` is set immediately before the hash is recorded — but a
hand-edited or corrupted ledger reaches it, the same population that produces `UndecodableEntry` and
`DuplicateIdentity`, and salvage carries both fields forward together so a future change to its shape
could reach it too. Silently skipping is the one behaviour the three vocabularies exist to prevent:
`NoContentHash` is exactly this shape in S2. `QuarantineNoSourceHash` is emitted **only when Q3 was
requested** — in the default path nothing is checked, and the silence there is correct.

**Q2 does not run under a session selector.** "Every file under `quarantine/` is claimed" is a statement
about the whole tree, and a selector narrows the ledger — so every other session's originals would read
as strays. A partial ledger cannot support a whole-tree accusation, which is the same rule that stops
the orphan sweep on a key it cannot fully name. The report says `swept: false` rather than reporting
zero strays, because "not asked" and "asked and clean" are not the same answer.

**A subtree whose ledger was refused is not judged.** When the scratch pass refuses a key — a foreign
store dir, a missing or unreadable manifest, an undecodable entry — it hands law Q that key's
quarantine subtree as *unexamined*, and the sweep passes over everything beneath it. Nothing there can
be called a stray, because nothing there can be shown to be unclaimed: an unreadable record is a reason
to refuse, not a licence to accuse what it describes.

**The same must hold when a whole ledger is gone, and two cases currently do not.**

- **`archive/_scratch/` absent.** The scratch pass returns early without marking anything unexamined,
  so if that directory was *deleted* while `quarantine/_scratch/…` still holds originals, every one of
  them reads as a stray. Advisory, so nothing fails — but the label is false, and a false reason is
  worse than a coarse one (D-S7). Mark `_scratch` unexamined on absence too: on a store that never
  archived scratch the mark covers an empty subtree and costs nothing, and on a store that lost the
  directory it says the true thing.
- **`catalog.db` absent.** `open_env_read` substitutes an empty in-memory catalog, so a store that
  lost its catalog beside a populated `archive/` is indistinguishable from a fresh one — and law Q
  then reports **every** session original as a stray. This is the manifest's `Missing`-versus-
  `Unreadable` distinction, unmade one layer down, and it is the same store state §5's `NotAttempted`
  identifies for the lock gate. Both belong to the store-shape work in §9 P6.7: `open_env_read` should
  tell a fresh store from one whose catalog is missing, and `verify` should withhold Q2 — saying why —
  in the second case rather than accusing a tree it has no ledger for.

**B2 has made the lock-gate defect more expensive.** A store that lost its marker and its catalog never
attempts the lock, so `exclusive` is permanently false — and that now permanently downgrades
`QuarantineStray` and `QuarantineMismatch` as well as the scratch comparatives. On such a store law Q
can confirm and can never accuse. The repair is unchanged (§5, `NotAttempted`), but it has moved from
*a defect in one pass* to *a precondition for two*, and should be sequenced ahead of the rest of P6.7 if
that unit is scheduled late.

Scope: session artifacts come from the catalog (`quarantined`, `stored_path`, `source_sha256`); scratch
comes from its manifest and needs the `quarantined` flag §4 specifies before Q applies to it at all.

**Three checks `verify` must *not* attempt.** Each looks reasonable and each is wrong:

- **`bytes` against `source_sha256`.** `bytes` is a live-tree fact; the store facts are the hashes.
  `verify` has no live tree — GC may have deleted it, which is the whole point — and cannot re-derive
  `source_sha256`. A salvaged entry legitimately carries a current `bytes` beside an earlier capture's
  hash (§3), so this check would flag correct ledgers.
- **`source_sha256` at all.** It describes bytes that no longer exist anywhere `verify` can look.
  Only `content_sha256` is checkable from the store.
- **anything requiring the live tree.** `verify` is a store-side command by construction; the live-tree
  half of coverage belongs to the GC gate, which runs it at delete time on a tree that is still there.

**Refused keys are reported by both commands, and the division matters.** `verify` sees the store, so
it reports store-side refusals — foreign store dir, unreadable manifest, undecodable entry, key
collision. `archive` sees the live tree, so it is the only one that can report a key whose *tree*
exists and was skipped (§3, D-S4). Neither report subsumes the other; a key silently skipped by
`archive` need not appear anywhere in `verify`'s output, because its store may look perfectly clean.

The pass is stateless: it persists no `verified_at`, because scratch has no catalog row to persist it
on (§3, known gap).

#### Exclusion: `verify` can confirm without the lock, but it cannot accuse

`verify` already takes the write lock for its `verified_at` persistence and **continues without it**
when it is unavailable (§4, W4) — the lock is held across the scratch pass too, when it was acquired
at all. So the pass runs in one of two conditions, and they are not equivalent.

**Held.** No other yomi writer can run, so the manifest and the store are one consistent snapshot and
every finding above stands as classified.

**Not held.** An `archive` may be running, and the store passes through states that look exactly like
defects — by the design's own instruction. §3 fixes the order **manifest, then reconcile** for crash
safety, so between them the store legitimately holds `.zst` the new ledger does not claim. That is not
the only window, and the widest one is elsewhere: artifacts are written *before* the manifest, so for
the whole store pass a new `.zst` sits under a manifest that predates it, and a rewritten `.zst` sits
under an entry whose `content_sha256` describes the previous content.

The rule is not a list of racy checks; it is one principle: **without exclusion the pair (manifest,
store) is not a consistent snapshot, so no finding that compares one against the other may stand.**

| Without exclusion | Findings |
|---|---|
| **stand** — each depends on a single atomically-replaced object, or on the store path's classification, and `archive` never transiently produces it | `ForeignStoreDir`, `UnreadableManifest` (the manifest is temp-write + rename, so a reader sees old or new, never torn), `UndecodableEntry`, `UnreconcilableKey`, `NoContentHash`, `ForeignArtifact`, `StoreKeyCollision` |
| **downgraded to `unverifiable`** — each compares the ledger against the store, or is a state `archive` deliberately passes through | `NoManifest` (the store dir is created before the ledger lands), `MissingArtifact`, `UnclaimedArtifact`, `OrphanArtifact`, `ContentMismatch` |

The issue name is unchanged by the downgrade — only the class moves — so a downgraded `OrphanArtifact`
still reads as `{"issue":"OrphanArtifact","class":"unverifiable"}`, and the report carries
`"exclusive": false` with a line saying why. That is the three-vocabulary discipline applied one level
up: `unverifiable` already means "a statement about what the ledger can prove", and under a concurrent
writer it genuinely cannot be proven.

**Positives survive the downgrade; negatives do not.** An artifact that hashes to its entry's
`content_sha256` is a true statement about that (manifest, artifact) pair even if both change a moment
later, so `verified` is sound in either condition. Only the accusations are unsafe. `verify` without
exclusion can confirm; it cannot accuse.

**Two rejected alternatives.** *Requiring* the lock for the scratch pass turns a false-alarm problem
into a no-coverage one: §4 lists `verify` among the lock's users only for its persistence, read-side
commands are explicitly not lock-gated, and a nightly `verify` that refuses (exit 3) whenever archive
overruns is a nightly `verify` that checks nothing — a worse outcome than the one being fixed.
Gating *only* the orphan check covers one of the five affected findings and leaves `ContentMismatch`,
the loudest false alarm, in place.

**The downgrade happens at one point, and adding a check cannot bypass it.** The checks themselves know
nothing about exclusion; they push an issue and the report decides where it lands, with
`requires_exclusion()` as the single predicate. That predicate is an exhaustive `match`, so a new issue
that fails to declare itself does not silently stand — it fails to compile. "Someone adds a comparative
check and forgets the downgrade" is designed out rather than remembered. Both passes share one
`FindingClass`, so *which class fails the run* stays a single decision rather than one per tree; the
emitted strings are unchanged.

> This paragraph was, for one round, false about the code — the predicate was a `matches!`, which
> answers `false` for an undeclared issue in silence. A claim of the form *"X is impossible by
> construction"* is worth exactly the construction behind it, and this document has now made that
> mistake twice (the other: the store-root classification, stated for three layers and implemented at
> one). Such a claim is to be verified against the code, not asserted about it.

**Exclusion is store-wide and cannot be per-key.** While `archive` writes key A, comparative findings
for keys B…Z are downgraded too. The lock is the only exclusion signal that exists, and per-key locking
would change §4's single-writer model — multiplying the lock surface and its deadlock analysis for a
pass that is cheap and re-runnable. Accepted as a property, not a defect: over-downgrading costs a
re-run, under-downgrading costs a false accusation.

**Why exclusion was unavailable must be reported, not guessed.** There are three causes and they call
for three different operator actions, so collapsing them into "a concurrent archive may be mid-write"
is a false explanation in two of the three cases — the same error §4 refuses when it insists lock
contention and an unsupported `flock` be reported apart, because naming the wrong one "sends the
operator hunting for a competing process that does not exist":

| Cause | Meaning | Action |
|---|---|---|
| `Contended` | another yomi holds the lock | re-run later |
| `Unsupported` | `flock` failed permanently (some NFS/FUSE/CIFS) | move the store (`--home` / `YOMI_HOME`) |
| `NotAttempted` | the lock was never sought | see below — usually, restore the store's marker. Once the store-shape predicate is in use this means *there is no store here*, and a home that has run one mutating command never returns to it: `ensure_layout` creates `state/`, so the store is present from then on whatever else is lost |

`NotAttempted` is the one that matters, because it is **permanent and silent**. `verify` gates its lock
on `is_initialized()`, which is `marker || catalog.db` — so a store that has lost both, while
`archive/_scratch/` and every artifact in it survive intact, never attempts the lock at all.
`exclusive` is then false on every run forever, and `verify` can confirm but can never accuse, about a
store that is entirely present. The monitoring rule below ("never exclusive" is the alert) does catch
it, but only after the operator has ruled out a concurrent archive that was never running.

The gate asks the wrong question. It exists so a read-side command does not **create** a store on a
fresh home (§4; `w1_fresh_home_read_commands_do_not_error` pins it), and for that the question is
whether a store is *there* — `marker || archive/ || state/` — not whether it still has its bookkeeping.
Taking the lock inside an existing store directory creates only `.yomi.lock`, which every other command
already does. **Introduce a distinct predicate rather than widening `is_initialized()`**: its other
caller (`gc`'s "persist `shapes.json` if a store exists") is not a lock gate and must not change
meaning. With the predicate corrected, `NotAttempted` arises only when there is nothing to verify — at
which point the pass has no findings and exclusion is moot.

**Why the pair had to be fixed together.** A store that lost `state/` produced *both* halves of the
same wrong picture: the lock was never attempted, so every comparative finding was permanently
downgraded, **and** the catalog read back as empty, so every session original became a false stray.
Repairing one alone would have left the other making the store look broken; repaired together, the run
reports `exclusion: held`, no downgrades, no strays — and `claims` stays non-zero, because scratch's
ledger lives in its manifests and survived. **The output says which ledger was lost**, which is the
whole point of separating the two.

**The reason exclusion was unavailable is reported, not the fact alone.** `Unavailable` still folds
`Contended` and `Unsupported` together, pending a typed error from the lock layer; that split is worth
little beside `NotAttempted`, which was the permanent and silent one. Two fields now describe the same
thing — `exclusive` is exactly "`exclusion` is `Held`" — and only one carries the reason. The derived
one is redundant, and a redundant field is a second place for the truth to be written: **`exclusion` is
authoritative, and `exclusive` should go once its consumers move.**

**A downgraded finding does not fail the run.** `unverifiable` is uniformly non-failing, and splitting
it into failing and non-failing halves would give one vocabulary two exit behaviours — which is the
confusion the three vocabularies exist to prevent. An overlapping cron would otherwise exit 2 nightly
with no defect present, and that is the same ignored-alarm failure by another route. Visibility comes
from `exclusive: false`, which a monitor can alert on directly: a scheduled `verify` that **never**
gets exclusion is a `verify` that has never checked S1 or S2, and that is the condition worth paging
on, not any individual downgraded finding.

**Operational consequence for §8's cron path, stated rather than assumed.** Nothing here forbids
running `archive` and `verify` concurrently — the point of the rule is that concurrency degrades
honestly instead of lying. But for a nightly integrity check to *mean* anything it must obtain
exclusion, so the scheduled `verify` belongs **inside** `run --profile daily` (P5), sequenced after
archive within the single process that already holds the lock, rather than as an independently
scheduled job that overlaps it.

#### Resolving a session to a store key

`verify <uuid>` and `read --scratch <uuid>` must resolve a session to its store directory, and a
suffix test on the key does not do it. A key is `<slug>--<uuid>` only in the **plain** form; a session
whose directory name is not valid UTF-8 is encoded `_hex--<hex(slug)>--<hex(uuid)>` (§3), which no
`ends_with("--<uuid>")` can ever match. The failure mode is the worst kind for a verification tool:
**zero keys matched, exit 0** — indistinguishable, by exit code alone, from "checked it, all clean".

One resolver in `src/scratch.rs`, used by both commands:

```rust
pub fn store_key_matches_session(key: &str, uuid: &OsStr) -> bool
```

It handles both forms. The hex form parses unambiguously — hex contains no `-`, so after stripping the
`_hex--` marker the remainder splits on `--` into exactly two fields — which is precisely the property
the plain form lacks and the reason the two namespaces were made disjoint in the first place.

**It dispatches on the form; it does not try both.** For the key `_hex--ff--3131` the real session name
is `unhex("3131")`, and also attempting the plain suffix test would match a *different* session whose
directory is literally named `3131` — turning the false negative into a false positive, which is
strictly worse for a command whose job is to not miss anything. Because the two namespaces are
disjoint, the form is known from the key alone and there is never a reason to guess.

**One residual, which U6 closes for free.** The plain branch is a suffix test, and `<slug>--<uuid>` is
not injective (§3) — so a session directory literally named `bbbb--cccc` matches the key of slug
`-a--bbbb` and session `cccc`. This is N14 resurfacing in the resolver, reachable in pure ASCII and not
naturally produced by Claude Code's uuids.

**Under U6 the resolver still matches on the key name; the manifest only confirms** — and confirms on
the *chosen* key alone, which was measured: resolving one session opens exactly one `manifest.json`,
and no other key's ledger is touched. Reading
`uuid_hex` out of every manifest to resolve one session would make resolution cost one open per store
and would put the identity's authority in a place the name already carries it — the plain and hex forms
both encode `(slug, uuid)` recoverably. So: match by name as now, then read **the matched key's**
manifest and compare `uuid_hex`. One manifest open, not N. A disagreement is not a miss but a
`StoreKeyCollision`, which is exactly the condition U6 defines and which the resolver is otherwise the
most likely place to encounter. The **digest form** `_h256--<sha256>` is the one exception: it encodes
nothing recoverable and cannot be resolved from a uuid alone, so those keys — produced only by a store
key over `KEY_MAX`, and correspondingly rare — do require reading their manifest. The cost is bounded
by the number of digest-form keys, not by the size of the store.

A digest key whose manifest is missing or unreadable is therefore **unresolvable from a session
name** — its key encodes nothing to match on and its ledger is the only other source. It stays
reachable by naming the key directly, and `verify` still enumerates it and reports the missing ledger
as a violation, so the state is visible and has an exit. Accepted: there is no third place the mapping
could come from that is not a fourth ledger.

An index over the keys was considered and rejected: it would be a **fourth ledger** beside the
manifest, the store and the queued catalog table, with its own drift to detect. This design has
declined that twice already.

The resolver belongs to whichever unit lands first and is **reused**, not reimplemented, by the other:
U3 ships before U4, so U3 carries it. Shipping U3 with the suffix test and repairing it in U4 would
release a known false-negative in the one command whose entire job is to not have any.

#### A scratch-pass failure must not discard the catalog pass

`verify` runs the catalog pass first and the scratch pass second, and an `Err` from the second
propagates before anything is printed — so an unreadable `archive/_scratch/` throws away a completed
catalog verification and reports only the error. The two passes attest to different ledgers and neither
is a precondition of the other. A failure to enumerate the scratch root is a refusal of *that* pass:
it should be reported as such, with the catalog results still emitted, under the same rule §5 already
applies to the GC commit loop — a per-pass doubt degrades, only a global doubt aborts.

**GC gating: unchanged — the scratch gate does not consult law S.** An orphaned `.zst` is a store
hygiene defect, not a coverage defect: it does not make the live tree less archived, and the gate's
question is only ever "does the archive faithfully cover *this live tree*". Refusing on an orphan
would let an unrelated store defect permanently block reclamation — the precise failure mode the
over-cap fix existed to end. The scenario that *would* deserve a halt is "the archive silently failed,
so the source was deleted anyway", and detecting that is exactly what the `verify` pass above is for;
the answer to a ledger defect is a check that reports it, not a gate that wedges on it.

Two conditions of that judgment are worth recording, because the *reason* it is safe changed once §3's
reconciliation landed. Before: an over-cap tree could still have stored bytes sitting in an orphan
`.zst`, so "nothing is lost" leaned on manual `zstd` recovery — which is the defect, not a rationale.
After: an over-cap tree genuinely stores nothing and the position rests on ratified decision #4 alone.
No gate change is needed in either state, and the post-fix rationale is the cleaner one.

**Precisely: the gate ignores S1 (orphans), and it is *not* true that orphans became impossible.** Two
states still produce them — a key whose ledger holds an undecodable entry never reconciles again
(§3), and a non-regular `*.zst` is foreign matter archive will not touch. Both are store-side defects
that leave the live tree's coverage intact, so the reasoning above is unchanged; they are named here
so the claim is "the gate does not care about orphans", not the stronger and false "orphans cannot
exist".

**What the scratch gate *did* gain is not law S but two refusals about its own evidence**, and both
are coverage questions, not hygiene:

- **`ForeignStoreDir`**, checked before the manifest is read. Every fact the gate would draw from a
  store path it does not own — the ledger, the artifacts — is foreign evidence for a decision that
  deletes live data. Measured on a build with only this guard removed, against a fixture whose store
  path was symlinked at a valid store for that tree: `deleted == 1`. The tree was destroyed because
  coverage looked complete, and it *was* complete, for a directory the run does not own.
- **`capture_failed`**, checked before the size and hash comparisons. Presence + size is the intended
  assurance for a file policy declined to hoard; it assures nothing about a file nobody read (§3).

Both are the same principle the rest of this section runs on, applied to the gate's inputs rather than
its outputs: **an unreadable ledger is a reason to refuse, never a licence to destroy what it
describes.**

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
yomi verify  [<uuid> | --all] [--quarantine]                                                            # scratch law S + quarantine law Q (§5)
yomi config  [get|path]
```

**`read --scratch`.** The positional argument is a session uuid or a full `<slug>--<uuid>` store key;
a uuid resolves to the single `archive/_scratch/*--<uuid>/` that carries it (uuids are unique, so at
most one), and an ambiguous or absent key is exit 2 with the reason. Behaviour:

| Form | Output | Exit |
|---|---|---|
| `--scratch` | manifest listing: `rel`, `rel_hex`, `bytes`, `stored`, `present`, `capture_failed`, plus `captured_at` / `total_bytes` / `over_total_cap` for the tree. `--json` adds `source_sha256` / `content_sha256` | 0, or 2 if the key resolves to nothing |
| `--scratch --file <rel>` | the entry's decompressed stored bytes, **written raw** to stdout (`write_all`, not a lossy string conversion — a scratch file may be binary). `--json` emits `{rel, rel_hex, content_bytes, encoding, content}` where `encoding` is `"utf8"` (content verbatim) or `"hex"` (content hex-encoded) — same encoder as `path_hex`, so `--json` adds no dependency and never emits invalid UTF-8 inside a JSON string | 0 |
| `--scratch --file <rel>`, entry `stored: false` | refusal naming *why* it was not stored — over-cap, deny-listed, over `file_cap`, or `capture_failed` (nothing was ever read) — never a bare "not found" | 2 |
| `--scratch --file <rel>`, no matching entry | not found | 2 |

`<rel>` is compared against `ScratchRel::as_bytes()`; the opened path comes from the matched entry
(§3). Only stored bytes are ever read — never the live source, never `quarantine/`. The store dir is
classified before anything under it is opened, exactly as the other layers do: a `Foreign` store is
exit 2 with its own reason, never read through.

**Non-exposure and traversal are unrepresentable, not defended.** The one type that names a scratch
store has a single constructor, which classifies the root and then the key **before** it opens
anything beneath either — so holding the value *is* the proof that the classification happened. The
entry handle it hands out has no public constructor of its own and its read method takes **no
arguments**: there is no function anywhere that turns a path or a string into stored bytes. A `--file`
value is compared against each entry's `ScratchRel::as_bytes()` and discarded; what is opened is the
*matched entry's* identity, and a `ScratchRel` cannot hold `..` or an absolute path (§3). The
guarantees §3 states for the read path are therefore properties of the type, not of the caller's care.

**Every output field a user is expected to pass back carries the lossless form.** `rel` is the lossy
display value and can never be handed to `--file`; `rel_hex` accompanies it whenever the name is not
valid UTF-8. Without it a non-UTF-8 entry can be *listed but not fetched* — a hole in retrieval for the
exact population `path_hex` exists to serve. Two gaps remain and are queued (§9 P6.5): the human
listing shows no hint that an entry's `rel` is undisplayable, and there is no `--file-hex <HEX>` to
pass the identity back without shell byte-escaping.

**`bytes` means one thing in this command.** The listing's `bytes` is the manifest's value — the live
source size at capture, **before** redaction. The retrieved payload's length is therefore a *different
quantity* whenever an entry was redacted, and it is emitted under a different name, `content_bytes`.
Reusing `bytes` for both would put two claims behind one name in two outputs of one command, which is
the defect `capture_failed` split out of `stored: false`, and the defect `NoCatalogRow` still carries
on the scratch path. If the manifest value is ever wanted alongside the payload, it goes as
`source_bytes` — the name §2 already uses for exactly that quantity.

**The positional accepts hyphen-leading values, and must.** Every real store key begins with `-`: a
key is `<slug>--<uuid>` and a slug is a cwd with its separators replaced, so it starts `-home-…`.
Without `allow_hyphen_values` the documented "or a full store key" form is unusable for **every key
that exists** — the argument parser reads it as an unknown flag. The `--` end-of-options escape
remains available and equivalent; this only removes the requirement to know it. `--scratch` is not
swallowed as the positional's value when the positional is omitted (that is a required-argument
error), and a mistyped flag becomes a selector that resolves to nothing rather than a silent success.

**`--scratch` conflicts with `--entry`, `--agents`, `--grep` and `--raw`; `--file` requires
`--scratch`.** They read a different ledger, and accepting one alongside the other while silently
honouring only one is the failure mode `--all` had. Same standard as `verify --all`.

**Refusals carry a stable code beside the prose.** `--json` emits `{"error": "<code>", "reason":
"<prose>"}` so a caller branches on the code and never parses the sentence — the same two-layer shape
`gc.log` uses for its skip reasons. Codes: `NoScratchStore`, `ForeignStoreRoot`, `UnreadableStoreRoot`,
`NotFound`, `Ambiguous`, `ForeignStoreDir`, `NoManifest`, `UnreadableManifest`, `NotStored`. `NotFound`
(no such entry) and `NotStored` (the entry exists, its bytes do not) are deliberately distinct: the
questions differ and so do the remedies. An `Ambiguous` selector is never guessed between.

**`ForeignStoreRoot` and `ForeignStoreDir` are distinct, and `verify` must adopt the same split.**
§8's rule for `archive` — a root refusal and a key refusal do not share a field, because one skips
every tree and the other skips one — is a rule about *names* for the same reason it is a rule about
fields. `verify` currently reports both as `ForeignStoreDir`, distinguished only by filing the root's
finding under the key `_scratch`. The `_scratch` filing convention is right and stays; the shared issue
name is not, and splitting it makes the two commands describe one condition one way (§9 P6.5).

**One selector grammar, one implementation.** `read --scratch` accepts a session uuid **or** a full
store key; `verify` accepts only a uuid, and its positional does not allow hyphen-leading values — so
`yomi verify <full-key>` cannot even be typed, and if escaped it matches nothing and reports "0 store
dirs, exit 0". That is the same false-negative shape as the hex-key resolver defect (§5), in the same
command, one round later. Both halves of the question — "is this key named by this selector?" — belong
in a single `store_key_selected_by(key, selector)` in `src/scratch.rs`, used by both commands, with
`verify`'s positional taking `allow_hyphen_values` too. A selector that matches no store must be an
explicit outcome in `verify`, not silence (§9 P6.5).

The listing shows `present: false` and `capture_failed: true` explicitly rather than folding them into
`stored`, because those are the two states where a reader's natural question ("why can I not get these
bytes?") has a different answer and a different remedy: an archive-only copy that is still there, and
a file that was never captured at all.

**A missing artifact is exit 2, not exit 1.** `archive` writes artifacts *before* the manifest (§3), so
a concurrent run leaves a window in which the ledger claims an artifact the store does not yet hold.
Reading it currently propagates an I/O error and exits 1, which §8 reserves for the tool failing — but
nothing failed: the bytes are not there *yet*. This is the read-side face of §5's non-snapshot
condition, and read's correct response differs from verify's because **read does not accuse**: it
cannot downgrade a finding, it can only state the fact. So it reports a coded exit-2 refusal that says
the ledger claims these bytes and the store does not have them, **without asserting a cause** — a race
and a genuine S1 violation are indistinguishable from here, and `yomi verify` run exclusively is the
thing that can tell them apart. The same applies to an artifact that will not decompress: a store
defect is exit 2 with a code, not a tool error (§9 P6.5).

**A field the ledger does not carry must not be rendered as a value it does.** `ScratchManifest` gives
every scalar `#[serde(default)]` so that a manifest predating a field still parses (§3) — and the
listing then prints those defaults as data: `captured_at: ""` reads as an empty capture time,
`total_bytes: 0` as an empty tree, neither distinguishable from the real thing. `verify` never looks at
them so it was harmless there; `read` shows them to a person. The scalars a reader is shown become
`Option`, written as `Some` by archive on every manifest (so serialized output is unchanged) and
rendered as *unknown* when absent — the same "absent means something" the `present` and
`capture_failed` flags already rely on (§9 P6.5).

**`archive` report fields for scratch.** `--json` and the human summary both carry:

| Field | Meaning |
|---|---|
| `scratch_orphans_removed` | stored artifacts the new ledger no longer claims, removed to hold S1. Counted, not performed, under `--dry-run` |
| `scratch_keys_refused` | keys archive touched nothing for (§3, D-S4) |
| `scratch_refusals` | `[{key, reason}]` — `ForeignStoreDir`, `UnreadableManifest`, `UndecodableEntry`, `StoreKeyCollision`, `StoreWriteFailed` |
| `scratch_root_refused` | the store **root** was refused, so **no** scratch was archived at all |

A root refusal gets its own field rather than a row in `scratch_refusals`, because the blast radius is
categorically different: a key refusal skips one tree, a root refusal skips every tree. Reporting it as
"1 key refused" when the truth is "nothing was archived" is the same misreport as `NoCatalogRow` on the
scratch path. The root check also belongs **outside** the per-key loop — it is a property of the run,
not of the key — otherwise one root problem emits one warning per session directory on disk.

A refusal is not an error: the run continues and reports exit 2 (partial), matching how §5 treats a
per-candidate GC doubt. What it must never be is invisible, which is what it is today.

**`verify` output.** Alongside the catalog counts, a `scratch` section carrying `keys`, `verified`,
`exclusive`, and the four finding lists (`violations`, `unverifiable`, `foreign_matter`, `refused`),
each finding a `{key, rel, issue, class}`. `rel` is the lossy display path and is empty for key-level
findings; it is never an identity (§3). The human form prints the same, one labelled block per class,
so a reader can see the class of every finding without consulting this document.

A `quarantine` section reports law Q (§5) beside the `scratch` section, with the same four finding
lists plus `claims`, `present`, `legacy`, `swept`, `files`, `unexamined`, `opened_originals` and
`verified`. Three of those are there so a reader can tell *not asked* from *asked and clean*, which is
the distinction the whole vocabulary rests on: `swept: false` says the stray sweep did not run (a
session selector narrows the ledger, and a partial ledger cannot support a whole-tree accusation),
`opened_originals: false` says no original was hashed, and `unexamined` counts files under a ledger
this run refused. `--quarantine` adds **Q3**, the only check that opens a file under `quarantine/` — a
flag rather than a default precisely so that reading raw secrets stays an attended decision (§4).

`--all` is an explicit alias for "no session", not an independent mode: the two are mutually exclusive
and omitting both is the same as `--all`. The flag is currently never read — the positional alone
decides — so the surface documented here (`[<uuid> | --all]`) is a claim the binary does not honour.
Enforce it with clap (`conflicts_with`) rather than deleting the flag; a documented alternative that
silently does nothing is worse than either.

**Not yet shipped** (kept here as the designed surface for their phases):
`yomi list` (P5), `yomi import --from-codex|--from-wonka` (P4, §7), `yomi run --profile daily` (P5),
`yomi config set` (only `get`/`path` exist).

Global: `--home <dir>` (`YOMI_HOME`), `--config <path>`, `--json`, `-v`.
Exit codes: `0` ok · `1` error · `2` partial (items skipped/unverified) · `3` refused (perm/lock/safety).

### Cron / scheduled

`yomi run --profile daily` (P5) is idempotent + lock-guarded → safe hourly/daily. Emits `--json` summary
(counts: archived, indexed, deleted, reclaimed-bytes, secret-flags, unverified) for 千里眼 (senri) monitoring.

**`verify` belongs inside the profile, not beside it.** The scratch pass's S1/S2 findings are only
conclusive under the write lock (§5, "Exclusion"), and the profile already holds it for the whole run —
so a `verify` sequenced there is exclusive by construction. An independently scheduled `verify` that
overlaps an `archive` is not wrong and is not an error, but it downgrades its comparative findings to
`unverifiable` and reports `exclusive: false`. The monitoring signal to watch is therefore not any
individual finding but **`exclusive` being false every time**: a scheduled `verify` that never obtains
exclusion has never actually checked the scratch store.

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
    safefs.rs               # fd-pinned writes — the one writer for archive/ and quarantine/ (§3, §4)
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
          p5_scratch_cap_break.rs · p6_scratch_ledger_break.rs · p7_scratch_ledger_break.rs
          p8_scratch_capture_break.rs
          p9_scratch_verify_break.rs · p10_scratch_verify_break.rs · p11_scratch_read_break.rs
          p12_scratch_read_break.rs · p13_quarantine_identity_break.rs · p14_law_q_break.rs
          p15_store_key_identity_break.rs · p16_store_ownership_break.rs · p17_safefs_break.rs
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
- **P6 — Scratch retrieval + integrity** (§3, §5, §8). The archive-then-delete contract held for
  scratch in one direction only: `archive/_scratch/` was written and gated on, but no command read it
  and no command verified it, so its stored bytes were write-only and a corruption was undetectable.
  1. **`src/scratch.rs`** — `ScratchRel` + `store_key` + the single `ScratchManifest`/`ScratchEntry`
     definition; archive and the GC gate both go through it. Identity became lossless (`path_hex`);
     no enumeration change, no store change, no manifest re-keying. **(merged, #10)**
  2. **Enumeration + reconciliation** — the writer walks the whole `<slug>/<uuid>/`; archive
     establishes S1 by removing unclaimed `*.zst` under the tree's own store dir; vanished-file
     entries are retained `present: false`; `scratch_orphans_removed` in the run report, previewed
     under `--dry-run`. **(merged)**

     Adversarial testing during U2 added five constructs the unit was not designed with, each now a
     contract in §3: `capture_failed` (a capture that never happened is not a policy decision not to
     hoard), **salvage** (a capture failure does not forfeit an earlier capture; grounded in the
     artifact on disk, hashes neither required nor fabricated), the **split of law S into S1/S2**,
     `StoreDir`/`classify_store_dir` with a single classification shared by all three layers and
     `SkipReason::ForeignStoreDir`, and **refuse-not-repair** for a symlinked store directory.
     `tests/p6_scratch_ledger_break.rs`, `tests/p7_scratch_ledger_break.rs` and
     `tests/p8_scratch_capture_break.rs` pin them.

     One principle produced all five and is the unit's real result: **an unreadable ledger is a reason
     to refuse, never a licence to destroy what it describes** — reached independently through a
     manifest that will not parse, an entry whose identity will not decode, an artifact that cannot be
     salvaged, and a store directory that is not ours.
  3. **`yomi verify` scratch pass** — S1 and S2 per store dir, in the three vocabularies of §5
     (`violation` / `unverifiable` / `foreign matter`), plus refused keys. Manifest-driven; no catalog
     schema change and no migration. **(merged)**

     The three checks §5 forbids are not merely omitted but structurally absent — `verify_stores`
     contains no reference to `source_sha256` or `entry.bytes` at all. Four additions the unit made to
     the design, all adopted: `UnreconcilableKey` as a **refused key** (an undecodable entry is two
     facts at two scopes, and the key-level one is a permanent degradation that must move the exit
     code); the rule that an artifact any entry *explains* — by claiming or by disclaiming it — is
     withheld from the orphan sweep, so one object never draws two names; `UnreadableStoreRoot` as its
     own issue, because a root that is ours and unreadable is a different diagnosis from a root that is
     foreign; and the convention that root-level findings are filed under the key `_scratch`, which no
     real key can collide with because every key contains `--`.

     The **exclusion rule** (§5), the shared **session→key resolver** and scratch-pass error
     containment all landed here too. Two structural properties worth keeping: the downgrade happens at
     the single point where a finding is filed, behind an exhaustive `requires_exclusion()` — a new
     comparative check that forgets to declare itself fails to compile rather than silently standing;
     and the root/key classification is applied by **all four** layers (writer, reconciler, GC gate,
     `verify`), because a key resolved through a foreign root is foreign even when the key directory
     itself classifies `Own`. `tests/p9_scratch_verify_break.rs` and
     `tests/p10_scratch_verify_break.rs` pin the vocabulary and attack its boundary.
  4. **`yomi read --scratch`** — manifest listing and stored-bytes retrieval, stored-only by
     construction. Reuses (3)'s session→key resolver. **(implemented; in review)**

     The unit's result is that §3's read-path guarantees stopped being promises about caller discipline
     and became properties of a type: one constructor that classifies root then key before opening
     anything beneath either, an entry handle with no public constructor, and a read method that
     **takes no arguments** — so no function exists anywhere that turns a path or a string into stored
     bytes. Traversal is not defended against; it is unrepresentable (§8). This is the fifth layer to
     go through `classify_store_dir`.

     Five deviations from §8, all adopted and now written there: `allow_hyphen_values` on the positional
     (**the documented "full store key" form was unusable for every key that exists**, since every slug
     begins `-`), `rel_hex` in the listing and in `--file --json` (without it a non-UTF-8 entry can be
     listed but not fetched), `conflicts_with` against the transcript flags and `requires` on `--file`
     (the `--all` standard), and stable `{error, reason}` codes with `NotFound` and `NotStored` kept
     apart. The fifth was referred for a ruling and **partly overturned**: the retrieved payload's
     length is the right quantity to emit, but not under the name `bytes`, which the listing already
     uses for the manifest's pre-redaction source size — it is `content_bytes` (§8).
  5. **Defect sweep.** D-S1 (the GC gate reads a live scratch file outside the blacklist gate) and
     D-S2 (a scratch quarantine path keyed by the lossy name) are invariant repairs and should not wait
     on (3)/(4); D-S3/D-S4 (per-key failure containment and refusal reporting) are prerequisites for
     anything unattended; D-S5/D-S6/D-S7 are diagnosability. Joined by what (3) and (4) surfaced,
     grouped by the change each needs:

     - **`ScratchEntry` schema** — one edit adding D-S5's `blacklisted` (which joins `capture_failed`
       on the refusing side) and `not_stored` (§3): the manifest must record *why* an entry was not
       stored, because reconstructing the cause from the current config answers confidently and wrongly
       once a cap has been widened.
     - **Manifest scalars a reader is shown become `Option`** (§8), so a field the ledger does not carry
       is rendered *unknown* rather than as `""` or `0`.
     - **Exit-code correctness in `read --scratch`** (§8): a claimed artifact the store does not hold —
       or one that will not decompress — is a coded exit 2, not the exit 1 that means the tool failed.
     - **One selector grammar** (§8): `store_key_selected_by(key, selector)` shared by `verify` and
       `read`, `allow_hyphen_values` on `verify`'s positional, and a selector matching no store reported
       explicitly by `verify` rather than as "0 store dirs, exit 0".
     - **`ForeignStoreRoot` split out of `ForeignStoreDir` in `verify`** (§8), keeping the `_scratch`
       filing convention: a refusal covering every tree and one covering a single tree do not share a
       name, for the same reason §8 already says they do not share a report field.
     - **`--file-hex <HEX>`, and a marker in the human listing** for an entry whose `rel` is
       undisplayable (§8) — the last step of making the non-UTF-8 population addressable rather than
       merely visible.

     **U5-B1 — quarantine identity** (§4). One derivation owning the quarantine path, taken by all
     three writers (session capture, meta capture, rescan) from the artifact's archive-relative stored
     path: `quarantine/<X>` is the original of `archive/<X>.zst`. Carried as `Path`/`OsStr` end to end
     so scratch's raw bytes survive the sanitizer, which currently takes `&str`. The redundant
     `<session-uuid>` level goes, taking the doubled `<K>` and the archive/rescan divergence with it.
     Adds `ScratchEntry.quarantined` (the ledger has to say an original exists before anything can
     check that it does) and chmods **every** created directory level 700 rather than only the first.
     No migration: existing trees may hold the only copy of an original and are never renamed, moved or
     removed. D-S5's `blacklisted` write belongs here too, in the stamping form §3 specifies — the
     obvious form deletes an archive.

     **U5-B2 — law Q in `verify`** (§4, §5). Q0/Q1/Q2 by default, opening nothing; Q3 under
     `--quarantine`. Depends on B1 for the derivation and the flag. Same shape as U2→U3: one unit stops
     producing the defect, the next detects it, including retrospectively.
     **(implemented; in review)**

     Q3's isolation is carried by a **type**, not by discipline: the permission token has a private
     field, one constructor that takes the flag, and the only code in the crate that opens a file under
     `quarantine/` is a private method on it. Forgetting the flag is a compile error rather than a leak
     — which is what §4 asked for and better than what it specified.

     Three adjustments, all adopted and now written into §4/§5: **Q1's legacy fallback** (leaving it
     out was an inconsistency in §4, which three paragraphs earlier rules that legacy trees are never
     migrated — a strict Q1 would have accused this document's own behaviour, nightly, on the oldest
     stores); **`QuarantineForeignRoot`** (the store-path classification rule applied to the one path
     law Q is stated over, with absence deliberately *not* an early return); and the exhaustive
     `requires_exclusion` **match**, which corrected the code to a claim §5 had already made and the
     code did not meet.

     Outstanding, small: mark `_scratch` unexamined when the scratch root is *absent* (a deleted store
     dir currently turns every scratch original into a false stray), and add `QuarantineNoSourceHash`
     so a Q3 that was asked and cannot be answered says so instead of skipping in silence. The
     `open_env_read` fresh-versus-missing distinction belongs to P6.7 with the lock gate.

     **`DuplicateIdentity` in `verify`** (§5) — a violation, and `prior_tail` collapsing retained
     entries by identity so archive cannot propagate one. Closes the referral `read --scratch` already
     makes to a check that did not exist.
  6. **Store-key hardening** (§3, "The store key of a tree"): `slug_hex`/`uuid_hex` identity fields
     with collision refusal, and the `KEY_MAX`/`_h256--` digest form for over-long keys. No migration
     and no renaming — that is the point of choosing detection over an injective encoding.
     **(implemented; in review)**

     The resolver was measured to open exactly one `manifest.json` per resolution, and `verify` added a
     store-side form of the identity check the design had only specified against a live tree. One
     correction went the other way: `KEY_MAX` was 200, and the 55 bytes between that and `NAME_MAX`
     were a **hole in this document's own no-migration guarantee** — plain keys of 201–255 bytes had
     been creating their store directories successfully and would have been orphaned beside fresh
     digest-form ones. Both justifications for the margin had expired (§3); it is `NAME_MAX`, and the
     guarantee is now literal. A filesystem with a tighter limit is a per-key failure for D-S3's
     containment, not a number to guess at in the key derivation. `verify`'s
     `StoreKeyCollision` variant is already defined and deliberately unreachable until this lands, so
     populating it changes no output schema; it is not dead code to be swept. Once `uuid_hex` exists,
     **session→key resolution should read it instead of parsing the key** (§5), closing the last place
     the non-injective plain form is still consulted.
  7. **Store-root ownership** (§3, "Ownership depth"). `ensure_layout` asserts that `~/.yomi/`,
     `archive/`, `quarantine/` and `state/` are real directories — refusing (exit 3), not repairing.
     **(implemented; in review)**

     `store_exists()` landed as a **distinct** predicate with `is_initialized()` untouched, and
     `open_env_read` now returns `Present`/`Fresh`/`Lost` so `verify` can withhold Q2 *and say which
     reason* (`SessionScoped` versus `CatalogMissing`) — "not asked" and "asked with no ledger to
     answer from" being different answers, which is the discipline the whole vocabulary rests on. Both
     halves of the lost-`state/` picture close together (§5).

     One correction: **`archive/_scratch/` must come back out of the fixed set.** It was put there on a
     justification that has since expired, and its presence turns a foreign scratch subtree into an
     exit-3 abort of `archive`, `gc`, `index` and `rescan` alike — transcripts stop being captured
     because a scratch directory is wrong. §3 now states the membership test (a foreign member must
     make *every* subsequent operation unreliable) and why `_scratch` fails it. Its mode assertion
     moves to the writer that creates it. Today only `archive/_scratch/` is guarded, and at use rather than at
     layout, so an `archive/` that is a symlink still resolves the whole store elsewhere with every key
     beneath it classifying `Own`. Independent of scratch and reaching every command, hence its own
     unit rather than a line in the defect sweep. Carries the corrected lock-gate predicate with it
     (§5, `NotAttempted`): a distinct store-shape test, not a widening of `is_initialized()`, whose
     other caller is not a lock gate. Also `open_env_read` telling a fresh store from one whose
     `catalog.db` is missing beside a populated `archive/` — the same question, one layer down, and
     without it law Q reports every session original as a stray on such a store (§5). B2 raised the
     cost of the lock gate specifically: `exclusive: false` now permanently disarms two law-Q checks as
     well as the scratch comparatives, so this predicate should lead the unit.

  *Done:* an archived scratch file is retrievable by `yomi read --scratch --file`, byte-identical to
  its stored (post-redaction) content; a corrupted or orphaned scratch store fails `yomi verify` while
  a legacy hash-less one does not; lowering `total_cap` and re-archiving leaves no `.zst` the manifest
  denies; a file dropped directly in `<uuid>/` no longer makes its tree permanently unreclaimable;
  deleting a live scratch file does not destroy its archived copy; a file yomi meant to archive and
  could not read holds its tree back until it can be read, and no longer. Catalog registration of
  scratch (`scratch_entries`, §3) is **not** part of P6 and stays queued.

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
