//! The one owner of scratch path identity (design §3).
//!
//! A scratch manifest is the sole authority for a whole-tree delete (§5), so the
//! writer, the GC gate, the deleter and the read path must agree byte-for-byte on
//! what an entry names. They did not: the writer keyed by `to_string_lossy()` and
//! carried its own serialize-only manifest structs, while the GC gate carried an
//! independent deserialize-only pair. Both the key and the schema could drift
//! silently. One key type and one schema live here; nothing else defines either.

use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

/// Identity of one scratch file, relative to its session directory
/// (`<tmp_root>/<slug>/<uuid>`), held as raw `OsStr` bytes.
///
/// The bytes are the identity — equality, hashing, map keys and manifest lookup
/// all go through [`ScratchRel::as_bytes`]. A lossy string is never an identity:
/// `note-\xff.md` and `note-\xfe.md` both decode to the same `U+FFFD` name, which
/// let an unarchived file inherit an archived sibling's manifest entry and let
/// their stored `.zst` overwrite each other.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScratchRel(OsString);

impl ScratchRel {
    /// The identity of `path` within `session_dir`. `None` when `path` is not a
    /// descendant of `session_dir`, or when the relative form is not a plain
    /// sequence of ordinary components — an absolute path, or one carrying `..`,
    /// is not an identity and must never be joined to a store dir.
    pub fn from_live(session_dir: &Path, path: &Path) -> Option<Self> {
        let rel = path.strip_prefix(session_dir).ok()?;
        Self::from_raw(rel.as_os_str())
    }

    /// Rebuild from a manifest entry's two fields. `path_hex` wins whenever it is
    /// present; a malformed `path_hex` yields `None` rather than falling back to
    /// `path`, because the fallback is exactly the lossy value the hex exists to
    /// replace and would silently restore the collision.
    pub fn from_manifest(path: &str, path_hex: Option<&str>) -> Option<Self> {
        let raw = match path_hex {
            Some(h) => OsString::from_vec(crate::util::unhex(h)?),
            None => OsString::from(path),
        };
        Self::from_raw(&raw)
    }

    fn from_raw(raw: &OsStr) -> Option<Self> {
        if raw.is_empty() {
            return None;
        }
        if !Path::new(raw)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
        {
            return None;
        }
        Some(ScratchRel(raw.to_os_string()))
    }

    /// The sole identity. Everything that compares, hashes or looks up a scratch
    /// entry uses this.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Relative path form, for joining to a live session dir or a store dir.
    pub fn to_rel_path(&self) -> &Path {
        Path::new(&self.0)
    }

    /// The string the `[scratch]` allow/deny globs match. Lossy by necessity —
    /// `globset` matches `str` — which is sound because a glob decision is not an
    /// identity: two names that collide here are merely classified alike, and
    /// each still carries its own distinct key.
    pub fn glob_subpath(&self) -> Cow<'_, str> {
        self.0.to_string_lossy()
    }

    /// Path of this entry's stored artifact, relative to
    /// `archive/_scratch/<key>/`. Derived from the raw bytes, so two names that
    /// share a lossy form no longer share a store path.
    pub fn store_rel(&self) -> PathBuf {
        let mut bytes = self.0.clone().into_vec();
        bytes.extend_from_slice(b".zst");
        PathBuf::from(OsString::from_vec(bytes))
    }

    /// The `(path, path_hex)` pair a manifest entry records. `path` is the lossy
    /// display form, kept because a manifest is a human-facing artifact;
    /// `path_hex` is emitted **only** when the raw bytes are not valid UTF-8, so
    /// a manifest whose names are all UTF-8 — the entire real population — is
    /// byte-identical to one written before this field existed.
    pub fn manifest_fields(&self) -> (String, Option<String>) {
        match self.0.to_str() {
            Some(s) => (s.to_owned(), None),
            None => (
                self.0.to_string_lossy().into_owned(),
                Some(crate::util::hex(self.as_bytes())),
            ),
        }
    }
}

/// Marker on a store key that had to be encoded. Chosen so the key forms occupy
/// disjoint namespaces — see [`store_key`].
const HEX_KEY_PREFIX: &str = "_hex--";

/// Marker on a store key too long to carry its inputs at all.
const DIGEST_KEY_PREFIX: &str = "_h256--";

/// The longest key any form may produce, in bytes.
///
/// A key is a single filename component, so Linux bounds it at `NAME_MAX` = 255
/// and nothing in this module bounded it before: a deep `cwd` yields a long slug,
/// and the `_hex--` form **doubles** its input, so any pair over ~124 bytes
/// exceeded the limit. The failure was not graceful — `create_dir_all` returns
/// `ENAMETOOLONG` and `archive_scratch` propagates it, ending the whole run.
///
/// **`NAME_MAX` exactly, with no margin below it, and the two reasons a margin
/// was considered for are both worth less than what it costs.** What it costs is
/// concrete: a plain key of 201..255 bytes was a legal directory name, so stores
/// at those names exist, and a lower bound moves them to the digest form —
/// orphaning a store that this whole approach exists to avoid renaming.
///
/// * *Headroom for what a quarantine path builds from a key* — there is nothing
///   to leave room for. Since the mirror rule (§4) a key is a standalone
///   component in `quarantine/_scratch/<K>/` exactly as it is in
///   `archive/_scratch/<K>/`, and no component of either tree is longer. The one
///   place the superseded `_scratch--<K>` form is still constructed is law Q's
///   legacy fallback, which only `stat`s it — and a key of this length can have
///   no legacy original anyway, because the writer that used that form could not
///   create the component either.
/// * *Filesystems with tighter limits* — a margin cannot buy this. Where the
///   limit is 143, a 200-byte key fails exactly as a 255-byte one does; the
///   margin only moves the failure to a different wrong number. On such a
///   filesystem `create_dir_all` returns `ENAMETOOLONG`, which is a per-key
///   failure and belongs to the run-containment rule (D-S3) — not to a guess
///   baked into the key derivation.
const KEY_MAX: usize = 255;

/// The store key of one scratch tree: the name of its directory under
/// `archive/_scratch/`, and the discriminator inside its quarantine path.
///
/// `<slug>--<uuid>` verbatim whenever both directory names are valid UTF-8 —
/// which every real one is — so existing stores keep their names byte for byte.
///
/// A name that is *not* valid UTF-8 must not go through `to_string_lossy`: two
/// sessions differing only in invalid bytes collapse to one key, share one store
/// directory and one manifest, and the later run's live pass then claims the
/// earlier one's identity and overwrites its only archived copy. Such keys are
/// hex, which is injective on bytes.
///
/// No two forms can be confused. Each encoded form has its own marker prefix, and
/// a plain form that would begin with either marker is pushed into the encoded
/// branch, so the three output spaces are disjoint and none can impersonate
/// another. Hex carries no `-`, so the `--` inside an encoded form is an
/// unambiguous separator even though the one in the plain form is not (a real
/// slug contains `--`, which is why nothing parses a key — it only has to be
/// unique).
///
/// **The plain form is not injective, and that is not fixed here.**
/// `store_key("a", "-b") == store_key("a-", "b") == "a---b"`: the string
/// `<slug>--<uuid>` has one preimage per `--` in it, and real slugs contain `--`
/// routinely. Every injective encoding of an arbitrary byte pair differs from
/// `<slug>--<uuid>` on inputs that exist today, so adopting one renames *every*
/// store directory and the migration would have to walk and match directories by
/// the very identity that was ambiguous. The fix is instead to **record the
/// identity and detect the collision** — [`ScratchManifest::slug_hex`] and
/// [`ScratchManifest::uuid_hex`], checked by [`identity_verdict`] before any
/// write. That is injective *in effect*: two colliding trees can never write
/// through one another, because the second to arrive refuses.
///
/// **A key over [`KEY_MAX`] takes a digest form**, `_h256--<sha256_hex(hex(slug)
/// ++ "--" ++ hex(uuid))>` — 71 bytes, always legal. Injective under sha256
/// collision-resistance, which is not a new assumption: `source_sha256`,
/// `content_sha256` and the whole GC delete gate already rest on it, and if it
/// fails the archive's integrity falls before its directory naming does. The
/// inner encoding is hex-then-join precisely because hex contains no `-`. No
/// existing store is renamed by this rule: a key that exceeded `NAME_MAX` never
/// successfully created a directory, so there is nothing to orphan.
///
/// The result is ASCII in the encoded cases and a pair of existing directory
/// names in the plain case, so it is a legal filename either way: no `/`, no
/// NUL, never `.` or `..`, and never longer than `KEY_MAX`.
pub fn store_key(slug: &OsStr, uuid: &OsStr) -> String {
    if let (Some(s), Some(u)) = (slug.to_str(), uuid.to_str()) {
        let plain = format!("{s}--{u}");
        if !plain.starts_with(HEX_KEY_PREFIX)
            && !plain.starts_with(DIGEST_KEY_PREFIX)
            && plain.len() <= KEY_MAX
        {
            return plain;
        }
    }
    let inner = hex_pair(slug, uuid);
    let hex = format!("{HEX_KEY_PREFIX}{inner}");
    if hex.len() <= KEY_MAX {
        return hex;
    }
    format!(
        "{DIGEST_KEY_PREFIX}{}",
        crate::util::sha256_hex(inner.as_bytes())
    )
}

/// `hex(slug) ++ "--" ++ hex(uuid)` — the inner encoding both encoded key forms
/// are built from, and injective because hex contains no `-`.
fn hex_pair(slug: &OsStr, uuid: &OsStr) -> String {
    format!(
        "{}--{}",
        crate::util::hex(slug.as_bytes()),
        crate::util::hex(uuid.as_bytes())
    )
}

/// The scratch store root's name under `archive/`. Also the `key` a root-level
/// finding is filed under — no store key can collide with it, since every key
/// contains `--`.
pub const SCRATCH_ROOT: &str = "_scratch";

/// `archive/_scratch/` — the directory every scratch store key sits in.
pub fn store_root(archive_dir: &Path) -> PathBuf {
    archive_dir.join(SCRATCH_ROOT)
}

/// Whether `key` is the store key of the session directory named `uuid`.
///
/// A suffix test does not do this. A key is `<slug>--<uuid>` only in the *plain*
/// form; a session whose directory name is not valid UTF-8 is encoded
/// `_hex--<hex(slug)>--<hex(uuid)>`, which no `ends_with("--<uuid>")` can ever
/// match. For a verification tool the resulting failure is the worst kind —
/// **zero keys matched, exit 0**, indistinguishable by exit code from "checked
/// it, all clean".
///
/// The two forms are dispatched on, never both tried: hex output is `[0-9a-f]`
/// and carries no `-`, so stripping the marker leaves a remainder that splits on
/// `--` into exactly two fields. That unambiguity is the property the plain form
/// lacks, and the reason the two namespaces were made disjoint.
pub fn store_key_matches_session(key: &str, uuid: &OsStr) -> bool {
    if let Some(rest) = key.strip_prefix(HEX_KEY_PREFIX) {
        let fields: Vec<&str> = rest.split("--").collect();
        return fields.len() == 2
            && crate::util::unhex(fields[1]).is_some_and(|raw| raw == uuid.as_bytes());
    }
    // Plain form: both halves are verbatim, so the uuid must be UTF-8 to appear.
    uuid.to_str()
        .is_some_and(|u| key.ends_with(&format!("--{u}")))
}

/// Whether the store directory named `key` is the one `selector` asks for —
/// `selector` being either a full store key or a session directory's name.
///
/// **Matched by name; the ledger only confirms, and confirms later.** Reading
/// `uuid_hex` out of every manifest to resolve one session would cost one open
/// per store and would move the identity's authority away from the name, which
/// already carries it recoverably in both the plain and the hex form. So the
/// filter stays a name test, and [`confirm_selector`] runs on the *chosen* key's
/// manifest, where the caller has already read it — one manifest open, not N. An
/// index over the keys was considered and rejected as a fourth ledger beside the
/// manifest, the store and the queued catalog table, with its own drift to
/// detect.
///
/// The **digest form** is the one exception: `_h256--<sha256>` encodes nothing
/// recoverable and cannot be resolved from a session name alone, so those keys do
/// require their manifest here. They are produced only by a key over [`KEY_MAX`]
/// and are correspondingly rare, so the cost is bounded by their number and not
/// by the size of the store.
pub fn select_key(root: &Path, key: &str, selector: &OsStr) -> KeySelection {
    // A full key names its own directory.
    if OsStr::new(key) == selector {
        return KeySelection::Match;
    }
    if key.starts_with(DIGEST_KEY_PREFIX) {
        // Nothing to match on but the ledger. No manifest at all is a miss —
        // `NoManifest` is the vocabulary for that, and `verify` reports it — but
        // a manifest whose identity cannot be read is not a miss: the one bridge
        // this key has exists and is illegible.
        return match read_manifest_at(&root.join(key).join("manifest.json")) {
            ManifestRead::Ok(mf) => match mf.recorded_identity() {
                RecordedIdentity::Recorded(_, uuid) if uuid == selector => KeySelection::Match,
                RecordedIdentity::Corrupt => KeySelection::Unreadable,
                _ => KeySelection::Miss,
            },
            _ => KeySelection::Miss,
        };
    }
    match store_key_matches_session(key, selector) {
        true => KeySelection::Match,
        false => KeySelection::Miss,
    }
}

/// What a key's name test yielded, before its ledger has been consulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySelection {
    Match,
    Miss,
    /// Only reachable for the digest form, whose name resolves nothing on its
    /// own: the ledger that would answer is present and illegible.
    Unreadable,
}

/// What the chosen key's ledger says about the selector that reached it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorConfirmation {
    /// Recorded and agreeing, or nothing recorded — the name stands, exactly as
    /// it did before the fields existed.
    Confirmed,
    /// Recorded, and naming a different session. The plain form's last residual:
    /// a suffix test cannot tell a session directory literally named
    /// `bbbb--cccc` from the key of slug `-a--bbbb` and session `cccc`, and the
    /// resolver is the place most likely to meet it.
    Collision,
    /// Recorded and illegible.
    ///
    /// **Refused, like every other layer refuses it.** Reading destroys nothing,
    /// which is why this looked like the one place a damaged identity could be
    /// waved through — but the failure here is not destruction, it is *answering
    /// the wrong question*: measured, one corrupted byte turns a correctly
    /// refused `read --scratch <other session>` into a silent exit 0 serving the
    /// other session's archived bytes. `archive`, the GC gate and `verify` all
    /// read this state as "a claim this run cannot read"; the resolver reading it
    /// as "no claim" gave one value two meanings across four layers.
    Unreadable,
}

/// Whether the ledger of the key `selector` resolved to agrees that this store is
/// that session's.
pub fn confirm_selector(mf: &ScratchManifest, key: &str, selector: &OsStr) -> SelectorConfirmation {
    // A full key makes no claim about a session, so there is nothing to confirm.
    if OsStr::new(key) == selector {
        return SelectorConfirmation::Confirmed;
    }
    match mf.recorded_identity() {
        RecordedIdentity::Unrecorded => SelectorConfirmation::Confirmed,
        RecordedIdentity::Corrupt => SelectorConfirmation::Unreadable,
        RecordedIdentity::Recorded(_, uuid) if uuid == selector => SelectorConfirmation::Confirmed,
        RecordedIdentity::Recorded(..) => SelectorConfirmation::Collision,
    }
}

/// One file in a scratch tree, as recorded in `manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScratchEntry {
    /// Lossy display form of the entry's [`ScratchRel`]. **Never a key** — call
    /// [`ScratchEntry::rel`].
    pub path: String,
    /// Lowercase hex of the raw identity bytes, present only for a name that is
    /// not valid UTF-8. Absent from every manifest written before this field
    /// existed, hence `default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_hex: Option<String>,
    pub bytes: u64,
    pub stored: bool,
    /// sha256 of the live source bytes at archive time. Present only for stored
    /// entries; GC re-hashes the live file against this to prove it is unchanged
    /// before deleting the tree. Absent for non-stored (deny-listed) junk, which
    /// GC verifies by presence + size only, and absent in manifests written
    /// before D2/R1 shipped — a stored entry without it is unverifiable, so the
    /// tree is skipped (safe side).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_sha256: Option<String>,
    /// sha256 of the stored (post-scan, possibly-redacted) bytes. GC decompresses
    /// the stored `.zst` and checks its content hash against this, so a valid-zstd
    /// frame of the *wrong* content can never pass the scratch delete gate (D2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,
    /// False once this entry's live file has vanished. Archive then retains the
    /// entry and its `.zst` verbatim instead of reconciling them away: that
    /// artifact is the only remaining copy, and the caps say "do not hoard *this
    /// tree*", never "destroy what was already taken". A retained entry belongs
    /// to no live tree, so it counts toward neither `total_bytes` nor the cap.
    /// Defaults to `true` and is written only when false, so a manifest from
    /// before this field reads unchanged and an all-live tree serializes exactly
    /// as it did.
    #[serde(default = "present_default", skip_serializing_if = "is_present")]
    pub present: bool,
    /// Set when policy decided to store this file and the capture then failed:
    /// a blacklisted inode swapped in after the walk, an I/O or permission
    /// error, or a file that outgrew the read bound between stat and read.
    ///
    /// It is **not** the same statement as a bare `stored: false`. That one says
    /// policy declined to hoard the bytes, and presence + size is then the
    /// intended assurance (design §3, decision #4). This one says nothing about
    /// the content was ever captured — no decision was made at all — so
    /// presence + size assures nothing and the GC gate must refuse the tree.
    /// Deleting on it would break archive-verify-then-delete for a file yomi
    /// *intended* to archive and could not.
    ///
    /// Self-clearing: every run rebuilds live entries from scratch, so the first
    /// run that can read the file stores it and the flag is simply not written.
    /// Defaults to false and is emitted only when true, so a manifest from
    /// before this field reads unchanged and an ordinary tree serializes exactly
    /// as it did.
    #[serde(default, skip_serializing_if = "is_false")]
    pub capture_failed: bool,
    /// Which policy rule declined to store this file, recorded rather than
    /// reconstructed.
    ///
    /// The manifest used to record only the outcome, so a reader explaining a
    /// `stored: false` entry had to infer the cause from the config in force
    /// *now* — which is not the one that produced the entry. Widen `file_cap`
    /// after the fact and an entry rejected at capture for exceeding the old cap
    /// is thereafter explained as "the globs did not admit it": a confident,
    /// wrong answer. A retained entry makes it worse still, since it carries a
    /// decision taken under a config several changes old. Recorded here, the
    /// explanation travels with the entry and stays true.
    ///
    /// `over_total_cap` and `capture_failed` are deliberately **not** in this
    /// set: the first is a property of the tree and lives on the manifest, and
    /// the second answers a different question — *nothing was read*, rather than
    /// *we decided not to keep it*.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_stored: Option<NotStored>,
    /// The candidate's inode was on the denylist, so it was never opened —
    /// §4 forbids opening a blacklisted path for read or delete.
    ///
    /// Manifested (with `bytes: 0` and no `stat`, so nothing about the denied
    /// inode is recorded) purely so the tree's refusal is diagnosable: an
    /// unmanifested file made the GC gate refuse forever, reported only as
    /// `NoCatalogRow`. Safety is unchanged — `remove_tree_guarded` already
    /// aborts a whole-tree removal on a denylisted inode.
    ///
    /// It belongs beside `capture_failed`, not inside `not_stored`: both say
    /// *nothing was read*, where `not_stored` says *we decided not to keep it*.
    #[serde(default, skip_serializing_if = "is_false")]
    pub blacklisted: bool,
    /// This entry's unredacted original was written to `quarantine/`, at the
    /// mirror of its store path.
    ///
    /// Session artifacts record this in both the manifest and the catalog;
    /// scratch recorded it nowhere, so the ledger could not even be *asked*
    /// whether an original exists — which is what law Q's existence and stray
    /// checks are stated over.
    #[serde(default, skip_serializing_if = "is_false")]
    pub quarantined: bool,
}

/// The policy rule that declined to store a file — exactly the three causes
/// `store = allow.is_match && !deny.is_match && size <= file_cap` can produce.
///
/// `NotAllowed` and `Denied` are kept apart because they call for different
/// configuration edits: adding an allow pattern versus removing a deny one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotStored {
    /// No `[scratch] allow` glob matched.
    NotAllowed,
    /// A `[scratch] deny` glob matched.
    Denied,
    /// Larger than `[scratch] file_cap` as it stood at capture.
    FileCap,
}

impl NotStored {
    /// The token as it appears in the manifest.
    pub fn as_str(self) -> &'static str {
        match self {
            NotStored::NotAllowed => "not_allowed",
            NotStored::Denied => "denied",
            NotStored::FileCap => "file_cap",
        }
    }

    /// Phrased so every variant names the rule set an operator would edit, and
    /// the parenthetical names which half of it decided.
    pub fn reason(self) -> &'static str {
        match self {
            NotStored::NotAllowed => {
                "the [scratch] allow/deny globs did not admit it (no allow glob matched)"
            }
            NotStored::Denied => {
                "the [scratch] allow/deny globs did not admit it (a deny glob matched)"
            }
            // Deliberately without the cap's value: that would come from the
            // config in force now, and the whole point of recording the cause is
            // that the explanation does not move when the config does.
            NotStored::FileCap => {
                "it was over the [scratch] file_cap in force when it was captured"
            }
        }
    }
}

fn present_default() -> bool {
    true
}

fn is_present(present: &bool) -> bool {
    *present
}

fn is_false(flag: &bool) -> bool {
    !*flag
}

impl ScratchEntry {
    /// A fresh entry for `rel`, with no hashes yet — the writer fills those in
    /// only after the bytes are actually stored.
    ///
    /// `stored` is derived from `not_stored` rather than passed alongside it, so
    /// the two cannot be written into contradiction. (The tree cap flips
    /// `stored` afterwards without a policy cause; `stored: true` still implies
    /// `not_stored: None`.)
    pub fn new(rel: &ScratchRel, bytes: u64, not_stored: Option<NotStored>) -> Self {
        let (path, path_hex) = rel.manifest_fields();
        ScratchEntry {
            path,
            path_hex,
            bytes,
            stored: not_stored.is_none(),
            source_sha256: None,
            content_sha256: None,
            present: true,
            capture_failed: false,
            not_stored,
            blacklisted: false,
            quarantined: false,
        }
    }

    /// A denylisted candidate, manifested so its tree's refusal is diagnosable.
    ///
    /// `bytes: 0` and never stat'd: nothing about the denied inode is recorded,
    /// not even its size. §4 forbids opening a blacklisted path for read or
    /// delete, and this records that it was refused without learning anything
    /// from it.
    pub fn blacklisted(rel: &ScratchRel) -> Self {
        let mut e = ScratchEntry::new(rel, 0, None);
        e.stored = false;
        e.blacklisted = true;
        e
    }

    /// This entry's identity. `None` for an entry whose recorded fields do not
    /// decode — such an entry matches no live file, which refuses the tree.
    pub fn rel(&self) -> Option<ScratchRel> {
        ScratchRel::from_manifest(&self.path, self.path_hex.as_deref())
    }
}

/// `archive/_scratch/<key>/manifest.json`.
///
/// Every scalar carries `default` so this type parses exactly the set of
/// manifests the GC gate's old deserialize-only struct did — that one declared
/// `entries` alone and ignored the rest, and tightening it would turn an old
/// manifest into a refused tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScratchManifest {
    #[serde(default)]
    pub key: String,
    /// Hex of the raw bytes of the slug directory's name, and of the session
    /// directory's name — the tree's identity, recorded because its *key* cannot
    /// carry it unambiguously (see [`store_key`]).
    ///
    /// Always emitted, so a store self-upgrades on first contact with a writer
    /// that knows them; `default` (empty) so a manifest from before them parses
    /// unchanged and reads as "not recorded" rather than as a mismatch.
    ///
    /// Hex, not the names: they are `OsStr` bytes and need not be UTF-8, and the
    /// lossy form is exactly the thing this field exists to stop being used as an
    /// identity.
    #[serde(default)]
    pub slug_hex: String,
    #[serde(default)]
    pub uuid_hex: String,
    #[serde(default)]
    pub captured_at: String,
    #[serde(default)]
    pub total_bytes: u64,
    #[serde(default)]
    pub over_total_cap: bool,
    /// The `[scratch]` caps were lifted for the run that wrote this ledger
    /// (`archive --full`).
    ///
    /// Without it, `over_total_cap: false` and the absence of any
    /// `not_stored: "file_cap"` are ambiguous: they mean either "no cap declined
    /// anything" or "no cap was applied". The two look identical in a manifest and
    /// differ in exactly the case that loses data — a `--full` run stores N
    /// artifacts, a later plain `--include scratch` run finds them unclaimed under
    /// the caps it does apply, and reconciliation removes them. That removal is
    /// correct (store law S: the store holds what current policy stores), but a
    /// removal with no nameable cause reads as a defect, and the operator who
    /// wanted those bytes has nothing to act on. This field is the name.
    ///
    /// `serde(default)` and emitted only when true, so a manifest written before
    /// it parses unchanged and a capped run's manifest is byte-identical to one
    /// from before the field existed.
    #[serde(default, skip_serializing_if = "is_false")]
    pub caps_lifted: bool,
    pub entries: Vec<ScratchEntry>,
}

/// What a ledger says about the identity of the tree it describes.
///
/// **Three states, because two collapse a distinction that decides whether an
/// archive is overwritten.** "Records nothing" and "records something this run
/// cannot read" are different facts: the first ledger makes no claim, the second
/// makes a claim nobody can check. Folding them together made a single corrupted
/// byte reopen exactly the overwrite U6 exists to prevent — and, from the other
/// side, made a half-written record read as a *different* session and lock a tree
/// out of its own store, permanently, since a refused archive can never restamp
/// the field that would repair it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedIdentity {
    /// Nothing recorded — a manifest written before the fields existed.
    Unrecorded,
    /// Recorded and readable.
    Recorded(OsString, OsString),
    /// Recorded and unreadable: hex that does not decode, or only one of the two
    /// halves. Both are claims this run cannot read, not absent claims.
    Corrupt,
}

impl ScratchManifest {
    /// The identity this ledger records, in the three states that matter.
    pub fn recorded_identity(&self) -> RecordedIdentity {
        match (self.slug_hex.is_empty(), self.uuid_hex.is_empty()) {
            (true, true) => RecordedIdentity::Unrecorded,
            // Half a record is a damaged one, not a different session and not an
            // absent claim.
            (true, false) | (false, true) => RecordedIdentity::Corrupt,
            (false, false) => {
                match (
                    crate::util::unhex(&self.slug_hex),
                    crate::util::unhex(&self.uuid_hex),
                ) {
                    (Some(slug), Some(uuid)) => RecordedIdentity::Recorded(
                        OsString::from_vec(slug),
                        OsString::from_vec(uuid),
                    ),
                    _ => RecordedIdentity::Corrupt,
                }
            }
        }
    }
}

/// What the recorded identity says about the tree in front of the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityVerdict {
    /// Recorded and equal, or **not recorded at all** — a manifest written
    /// before the fields existed has nothing to contradict, and refusing it
    /// would turn every pre-U6 store into a refused tree. Archive stamps the
    /// real values on its next write, so the store self-upgrades on first
    /// contact.
    Proceed,
    /// Recorded and different. Two session directories map to one store key and
    /// this manifest belongs to the other one. Refuse: archive writes nothing and
    /// removes nothing, the GC gate returns `StoreKeyCollision`. What stops is
    /// the newcomer — the tree the ledger names goes on being archived and
    /// reclaimed, which is deliberate: a symmetric rule would let anyone who can
    /// `mkdir` under `/tmp/claude-<uid>/` freeze any existing tree's archive by
    /// choosing a colliding name, where pair-wise refusal lets an actor at that
    /// uid only refuse itself.
    Collision,
    /// Recorded and unreadable. **Not a licence to proceed**: an identity this
    /// run cannot decode is exactly the state a corrupted or hand-edited byte
    /// produces, and proceeding through it authorizes the overwrite the recorded
    /// identity exists to stop. The third time this series takes the same rule —
    /// an entry the reader cannot parse is not a licence to destroy its artifact,
    /// a prior capture that cannot be salvaged is not a licence to delete its
    /// `.zst`, and an identity that cannot be read is not a licence to overwrite
    /// what it names.
    Refuse,
}

/// The rule §3 states over a recorded identity, applied by **archive and the GC
/// gate alike, immediately after the manifest is read and before any write, any
/// reconciliation and any coverage judgment.** Placed after, the foreign ledger
/// has already informed the decision. `verify` reads the same three states,
/// naming the third as `UndecodableIdentity` rather than acting on it.
///
/// `session_dir` is the live tree's own directory: its name is the uuid and its
/// parent's name is the slug, which is exactly the pair [`store_key`] was built
/// from. Comparing the *identity* rather than the recomputed key is the whole
/// point — two colliding trees produce the same key by definition, so a key
/// comparison could never tell them apart.
pub fn identity_verdict(mf: &ScratchManifest, session_dir: &Path) -> IdentityVerdict {
    match mf.recorded_identity() {
        RecordedIdentity::Unrecorded => IdentityVerdict::Proceed,
        RecordedIdentity::Corrupt => IdentityVerdict::Refuse,
        RecordedIdentity::Recorded(slug, uuid) => match tree_identity(session_dir) {
            // A tree with no derivable identity cannot be compared, and a
            // comparison that cannot be made is not a mismatch.
            None => IdentityVerdict::Proceed,
            Some(live) if live == (slug, uuid) => IdentityVerdict::Proceed,
            Some(_) => IdentityVerdict::Collision,
        },
    }
}

/// The `(slug, uuid)` directory names of a live scratch tree, raw.
pub fn tree_identity(session_dir: &Path) -> Option<(OsString, OsString)> {
    let uuid = session_dir.file_name()?.to_os_string();
    let slug = session_dir.parent()?.file_name()?.to_os_string();
    Some((slug, uuid))
}

/// The same identity as the two hex fields a manifest records. Empty strings
/// when the tree has no derivable identity, which reads back as "not recorded"
/// rather than as a false one.
pub fn identity_hex(session_dir: &Path) -> (String, String) {
    match tree_identity(session_dir) {
        Some((slug, uuid)) => (
            crate::util::hex(slug.as_bytes()),
            crate::util::hex(uuid.as_bytes()),
        ),
        None => (String::new(), String::new()),
    }
}

/// What sits at `archive/_scratch/<K>/`, as every layer that touches a scratch
/// store must classify it.
///
/// Three states rather than a bool, for the same reason [`ManifestRead`] splits
/// `Missing` from `Unreadable`: "there is nothing here" and "there is something
/// here that is not ours" call for opposite handling, and collapsing them would
/// either make a first archive impossible or make a foreign directory writable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreDir {
    /// Nothing at this path. `archive` creates it; nobody else has work to do.
    Absent,
    /// A real directory — this key's store, yomi's to write, walk and prune.
    Own,
    /// Something else: a symlink, a regular file, a device, or a path this run
    /// cannot even stat. Not a directory yomi created, and acting through it
    /// leaves the archive tree — writes land outside it, a walk escapes it, and
    /// a manifest read through it is *foreign evidence for a decision that
    /// deletes live data*. Every layer refuses.
    Foreign,
}

/// Classify `archive/_scratch/<K>/`. `symlink_metadata`, never `metadata`: the
/// whole point is to see the link rather than whatever it points at.
///
/// One function so the writer, the reconciler and the GC gate cannot drift on
/// what a store directory *is* — the drift this module exists to end.
pub fn classify_store_dir(path: &Path) -> StoreDir {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => StoreDir::Absent,
        // Un-stattable is not "ours" — a store we cannot even classify is one we
        // must not write into, walk, or take evidence from.
        Err(_) => StoreDir::Foreign,
        Ok(md) if md.is_dir() => StoreDir::Own,
        Ok(_) => StoreDir::Foreign,
    }
}

/// What `archive/_scratch/<K>/manifest.json` yielded.
///
/// "There is no ledger" and "there is a ledger this run cannot read" are the
/// same thing to a reader that only refuses, and opposite things to a caller
/// that deletes: the first has nothing to contradict, the second says nothing at
/// all about the artifacts beside it — including that they are unclaimed.
pub enum ManifestRead {
    /// No manifest: a store dir never written, or written by a run that crashed
    /// before the ledger landed.
    Missing,
    /// A manifest exists but could not be read or parsed, so its contents are
    /// unknown. Nothing may be concluded from the absence of a claim in it.
    Unreadable,
    Ok(ScratchManifest),
}

/// Read `manifest.json`, keeping "absent" and "unreadable" apart.
pub fn read_manifest_at(path: &Path) -> ManifestRead {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ManifestRead::Missing,
        Err(_) => return ManifestRead::Unreadable,
    };
    match serde_json::from_str(&text) {
        Ok(mf) => ManifestRead::Ok(mf),
        Err(_) => ManifestRead::Unreadable,
    }
}

/// Read `manifest.json`. `None` for absent, unreadable or unparseable — every
/// one of which means the GC gate cannot prove coverage and must refuse.
pub fn read_manifest(path: &Path) -> Option<ScratchManifest> {
    match read_manifest_at(path) {
        ManifestRead::Ok(mf) => Some(mf),
        ManifestRead::Missing | ManifestRead::Unreadable => None,
    }
}

// ---------------------------------------------------------------------------
// Retrieval — what `yomi read --scratch` opens (design §3, §8).
// ---------------------------------------------------------------------------

/// Why a store could not be opened for reading. Each is exit 2 with its own
/// reason: "not found" is never reported for a store that exists but was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreOpenError {
    /// `archive/_scratch/` does not exist — nothing has ever been archived.
    NoRoot,
    /// The store root is not a directory yomi owns, or could not be enumerated.
    /// Every key resolves *through* the root, so this refuses all of them.
    ForeignRoot,
    UnreadableRoot,
    /// No store key answers to this selector.
    NotFound,
    /// More than one does. Never guess between stores.
    Ambiguous(Vec<String>),
    /// The key resolved by name, and its ledger names a different session. The
    /// plain key form is not injective, so a name can be ambiguous; the recorded
    /// identity is what says so.
    KeyCollision(String),
    /// The key resolved, and the identity its ledger records cannot be read, so
    /// nothing can say whether the name meant this session. Its own error and not
    /// `KeyCollision`, for the reason the GC gate keeps the two reasons apart:
    /// the operator action differs — repair a manifest versus rename a directory.
    UndecodableIdentity(String),
    /// The key resolved, but its store directory is not one yomi owns.
    ForeignStoreDir(String),
    NoManifest(String),
    UnreadableManifest(String),
}

impl StoreOpenError {
    /// A stable token for `--json`, so a caller can branch without parsing prose.
    pub fn code(&self) -> &'static str {
        match self {
            StoreOpenError::NoRoot => "NoScratchStore",
            StoreOpenError::ForeignRoot => "ForeignStoreRoot",
            StoreOpenError::UnreadableRoot => "UnreadableStoreRoot",
            StoreOpenError::NotFound => "NotFound",
            StoreOpenError::Ambiguous(_) => "Ambiguous",
            StoreOpenError::KeyCollision(_) => "StoreKeyCollision",
            StoreOpenError::UndecodableIdentity(_) => "UndecodableIdentity",
            StoreOpenError::ForeignStoreDir(_) => "ForeignStoreDir",
            StoreOpenError::NoManifest(_) => "NoManifest",
            StoreOpenError::UnreadableManifest(_) => "UnreadableManifest",
        }
    }

    pub fn reason(&self) -> String {
        match self {
            StoreOpenError::NoRoot => "no scratch has ever been archived into this store".into(),
            StoreOpenError::ForeignRoot => {
                "the scratch store root is not a directory this run owns; refusing to read \
                 through it"
                    .into()
            }
            StoreOpenError::UnreadableRoot => "the scratch store root could not be read".into(),
            StoreOpenError::NotFound => {
                "no archived scratch tree answers to that session or key".into()
            }
            StoreOpenError::Ambiguous(keys) => format!(
                "that selector matches {} store keys ({}); name one exactly",
                keys.len(),
                keys.join(", ")
            ),
            StoreOpenError::KeyCollision(k) => format!(
                "{k} names this session while its ledger records a different one; two \
                 session directories map to one store key, so rename one"
            ),
            StoreOpenError::UndecodableIdentity(k) => format!(
                "{k}'s recorded tree identity cannot be read, so nothing can say \
                 whether it is this session's store; repair or remove its manifest"
            ),
            StoreOpenError::ForeignStoreDir(k) => format!(
                "the store directory for {k} is not one this run owns; refusing to read through it"
            ),
            StoreOpenError::NoManifest(k) => format!("{k} has no manifest.json"),
            StoreOpenError::UnreadableManifest(k) => {
                format!("{k}'s manifest.json could not be read")
            }
        }
    }
}

/// A scratch store directory that **has been classified as ours**, with the
/// ledger inside it.
///
/// The only constructor is [`ScratchStore::open`], which classifies the root and
/// the key before it reads anything under either — so holding one of these *is*
/// the proof that the classification happened. Nothing can read a scratch store
/// without first passing through it.
pub struct ScratchStore {
    key: String,
    dir: PathBuf,
    manifest: ScratchManifest,
}

impl ScratchStore {
    /// Resolve `selector` — a session uuid or a full store key — to its store,
    /// classifying every path level before opening anything under it.
    ///
    /// The root is classified as well as the key, because a key is resolved
    /// *through* the root: a foreign root makes every key foreign while each one
    /// still classifies `Own` on its own. This is the fifth layer to go through
    /// [`classify_store_dir`], after the writer, the reconciler, the GC gate and
    /// `verify`.
    pub fn open(archive_dir: &Path, selector: &OsStr) -> Result<Self, StoreOpenError> {
        let root = store_root(archive_dir);
        match classify_store_dir(&root) {
            StoreDir::Absent => return Err(StoreOpenError::NoRoot),
            StoreDir::Foreign => return Err(StoreOpenError::ForeignRoot),
            StoreDir::Own => {}
        }
        let Ok(dir) = std::fs::read_dir(&root) else {
            return Err(StoreOpenError::UnreadableRoot);
        };

        let mut matched: Vec<String> = Vec::new();
        let mut illegible: Vec<String> = Vec::new();
        for e in dir.flatten() {
            let key = e.file_name().to_string_lossy().into_owned();
            // `select_key` is the shared resolver — a suffix test cannot address
            // a hex key, and this must not be reimplemented here.
            match select_key(&root, &key, selector) {
                KeySelection::Match => matched.push(key),
                KeySelection::Unreadable => illegible.push(key),
                KeySelection::Miss => {}
            }
        }
        matched.sort();
        matched.dedup();
        // A full key names one *directory*, not a session, so it asks nothing of
        // any ledger — and the escape hatch has to stay open exactly when
        // something nearby is damaged. Nothing about another store bears on it.
        if let Some(k) = matched.iter().find(|k| OsStr::new(k) == selector).cloned() {
            matched = vec![k];
        }
        // Otherwise a key whose ledger cannot be read **might be the one asked
        // for**, and that holds whether or not something else also matched.
        // Guarding this on `matched.is_empty()` let a legible key hide an
        // illegible one: with both ledgers readable the resolver refuses to
        // choose between two stores, and one damaged byte made it answer from
        // the survivor instead — the same downgrade the ledger check itself
        // closes, one step along. `Ambiguous` would be the wrong refusal here:
        // it asserts that the listed keys *do* answer to this selector, which is
        // precisely what an unreadable identity cannot say, and it sends the
        // operator to pick one rather than to repair the ledger that would
        // decide it.
        else if let Some(k) = illegible.into_iter().min() {
            return Err(StoreOpenError::UndecodableIdentity(k));
        }
        let key = match matched.len() {
            0 => return Err(StoreOpenError::NotFound),
            1 => matched.remove(0),
            _ => return Err(StoreOpenError::Ambiguous(matched)),
        };

        let dir = root.join(&key);
        if classify_store_dir(&dir) != StoreDir::Own {
            return Err(StoreOpenError::ForeignStoreDir(key));
        }
        let manifest = match read_manifest_at(&dir.join("manifest.json")) {
            ManifestRead::Ok(mf) => mf,
            ManifestRead::Missing => return Err(StoreOpenError::NoManifest(key)),
            ManifestRead::Unreadable => return Err(StoreOpenError::UnreadableManifest(key)),
        };
        // The ledger confirms what the name matched, on the manifest just read —
        // so the identity costs no extra open. A key whose name claims this
        // session while its ledger names another is an ambiguity, not a
        // near-miss, and serving it would answer a question the operator did not
        // ask.
        match confirm_selector(&manifest, &key, selector) {
            SelectorConfirmation::Confirmed => {}
            SelectorConfirmation::Collision => return Err(StoreOpenError::KeyCollision(key)),
            SelectorConfirmation::Unreadable => {
                return Err(StoreOpenError::UndecodableIdentity(key));
            }
        }
        Ok(ScratchStore { key, dir, manifest })
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn manifest(&self) -> &ScratchManifest {
        &self.manifest
    }

    /// The entry whose identity is exactly `wanted`.
    ///
    /// A **byte comparison against the ledger**, never a path construction: the
    /// caller's value is compared to each entry's [`ScratchRel::as_bytes`] and
    /// discarded. What comes back carries the *matched entry's* identity, so the
    /// path that is eventually opened is derived from the manifest and never from
    /// user input.
    pub fn find(&self, wanted: &OsStr) -> Option<StoredEntry<'_>> {
        let matched: Vec<(&ScratchEntry, ScratchRel)> = self
            .manifest
            .entries
            .iter()
            .filter_map(|entry| {
                let rel = entry.rel()?;
                if rel.as_bytes() != wanted.as_bytes() {
                    return None;
                }
                Some((entry, rel))
            })
            .collect();
        if matched.len() > 1 {
            // A damaged ledger, and the one moment retrieval matters most. Every
            // row here names the same identity and therefore the same artifact
            // path, so choosing between them cannot answer about the wrong file
            // — unlike an ambiguous *key*, where guessing would read a different
            // session. Refusing would deny bytes that are demonstrably on disk
            // and add nothing to safety, since reading destroys nothing: "a
            // ledger yomi cannot read is a reason to refuse to *destroy*", not a
            // reason to withhold. Prefer the row the store corroborates, and say
            // the ledger is damaged rather than resolve it silently.
            tracing::warn!(
                key = %self.key,
                rel = %String::from_utf8_lossy(wanted.as_bytes()),
                rows = matched.len(),
                "the ledger holds more than one entry for this identity; serving the \
                 one the store corroborates. Run `yomi verify` and repair the manifest."
            );
        }
        let (entry, rel) = matched
            .iter()
            .find(|(e, _)| e.stored)
            .or_else(|| matched.first())?;
        Some(StoredEntry {
            store: self,
            entry,
            rel: rel.clone(),
        })
    }
}

/// Whether `path` holds an artifact yomi stored: a **regular file**, judged
/// without following a symlink.
///
/// One predicate for every layer that asks the question. S1's left side is
/// regular files only because reconciliation will not remove anything else —
/// that would widen the delete authority past "the artifacts we stored" — so
/// anything else is foreign matter only an operator can clear. `verify` and the
/// read path must not be able to answer differently about one object.
pub fn is_stored_artifact(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|md| md.is_file())
}

/// Why an entry's stored bytes could not be produced.
///
/// Every one is a statement about the **store**, not a failure of the tool, so
/// each is a coded refusal rather than an error: `read` can serve or not serve,
/// it never accuses. Distinguishing a transient window from a real defect needs
/// the write lock, which is `yomi verify`'s job, so the messages point there
/// instead of guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactError {
    /// The ledger claims this artifact and the store does not hold it.
    Missing,
    /// Something is at the path, but it is not a regular file.
    Foreign,
    /// A regular file that could not be read.
    Unreadable,
    /// Read, but it did not decompress.
    Corrupt,
}

impl ArtifactError {
    /// A stable token for `--json`. `MissingArtifact` and `ForeignArtifact` are
    /// deliberately the names `verify` already uses for the same conditions.
    pub fn code(self) -> &'static str {
        match self {
            ArtifactError::Missing => "MissingArtifact",
            ArtifactError::Foreign => "ForeignArtifact",
            ArtifactError::Unreadable => "UnreadableArtifact",
            ArtifactError::Corrupt => "CorruptArtifact",
        }
    }

    /// States the fact and names where the cause can be settled. It does **not**
    /// assert a cause: a concurrent `archive` and a real store defect are
    /// indistinguishable from here.
    pub fn reason(self) -> &'static str {
        match self {
            ArtifactError::Missing => {
                "the ledger claims this artifact and the store does not hold it. A \
                 concurrent `yomi archive` passes through this state; only `yomi verify` \
                 under the write lock can tell that apart from a store defect"
            }
            ArtifactError::Foreign => {
                "the object at this artifact's path is not a regular file, so it is not \
                 something yomi stored. `yomi verify` reports it as foreign matter; only \
                 an operator can resolve it"
            }
            ArtifactError::Unreadable => {
                "this artifact is present but could not be read; run `yomi verify` for the \
                 store's condition"
            }
            ArtifactError::Corrupt => {
                "this artifact did not decompress; run `yomi verify` for the store's \
                 condition"
            }
        }
    }
}

/// One manifest entry, bound to the classified store it came from.
///
/// It has no public constructor: [`ScratchStore::find`] is the only way to obtain
/// one. [`StoredEntry::read`] therefore takes **no arguments** — there is no
/// function anywhere that turns a path or a string into stored bytes, so
/// traversal is not defended against, it is unrepresentable. `ScratchRel` cannot
/// hold `..` or an absolute path either (its components are all `Normal`), so the
/// join below cannot leave the store directory even in principle.
pub struct StoredEntry<'a> {
    store: &'a ScratchStore,
    entry: &'a ScratchEntry,
    rel: ScratchRel,
}

impl StoredEntry<'_> {
    pub fn entry(&self) -> &ScratchEntry {
        self.entry
    }

    pub fn rel(&self) -> &ScratchRel {
        &self.rel
    }

    /// The entry's decompressed stored bytes — `scan.redacted` as of capture,
    /// which is either in-place-redacted text or the opaque `‹QUARANTINED:…›`
    /// marker.
    ///
    /// The one and only path this opens is `<store dir>/<rel>.zst`, and the
    /// **object** at that path is classified before it is read: a path being
    /// beyond reproach says nothing about what sits at the end of it. Anything
    /// that is not a regular file is [`ArtifactError::Foreign`] — the same
    /// judgment and the same name `verify` gives it, so the two layers cannot
    /// answer differently about one object.
    ///
    /// The live source and `quarantine/` are never opened, so there is no input
    /// from which an un-redacted byte could reach a caller.
    pub fn read(&self) -> Result<Vec<u8>, ArtifactError> {
        let path = self.store.dir.join(self.rel.store_rel());
        if !is_stored_artifact(&path) {
            return Err(if path.symlink_metadata().is_ok() {
                ArtifactError::Foreign
            } else {
                ArtifactError::Missing
            });
        }
        let raw = std::fs::read(&path).map_err(|_| ArtifactError::Unreadable)?;
        crate::archive::compress::decompress_all(&raw).map_err(|_| ArtifactError::Corrupt)
    }
}

// ---------------------------------------------------------------------------
// Store law S — what `yomi verify`'s scratch pass checks (design §3, §5).
// ---------------------------------------------------------------------------

/// Which of the three vocabularies a finding speaks in. Only [`Violation`] and
/// [`RefusedKey`] fail the run.
///
/// Shared by the scratch pass and the quarantine pass (law Q, §4): the classes
/// are a discipline about *what a finding claims*, not about which tree it came
/// from, and one enum keeps "which class fails the run" a single decision.
///
/// [`Violation`]: FindingClass::Violation
/// [`RefusedKey`]: FindingClass::RefusedKey
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingClass {
    /// S1 broken, or S2 broken where S2 applies — a defect of the store.
    Violation,
    /// S2 inapplicable (the entry carries no `content_sha256`), or an identity
    /// that does not decode. A statement about what the ledger *can prove*, not
    /// a defect: every manifest written before D2/R1 is full of these, and a
    /// verify that fails on them nightly is a verify that gets ignored.
    Unverifiable,
    /// An artifact-shaped object archive will neither claim nor remove — S1's
    /// left side is regular files only, and reconciliation deliberately does not
    /// widen past "the artifacts we stored". Only an operator can resolve it.
    ForeignMatter,
    /// The key was not examined: its ledger could not be trusted to be read, or
    /// reading it would have meant trusting something outside the archive tree.
    RefusedKey,
}

impl FindingClass {
    /// Whether a finding of this class makes the run exit non-zero.
    pub fn fails_the_run(self) -> bool {
        matches!(self, FindingClass::Violation | FindingClass::RefusedKey)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FindingClass::Violation => "violation",
            FindingClass::Unverifiable => "unverifiable",
            FindingClass::ForeignMatter => "foreign matter",
            FindingClass::RefusedKey => "refused key",
        }
    }
}

/// What `verify` found. One variant per row of the §5 contract table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScratchIssue {
    /// The store path is not a directory yomi owns. Nothing below is attempted:
    /// a foreign ledger must not be read at all. Also reported against the key
    /// `_scratch` when the store *root* itself is foreign — the rule applies to
    /// the root as much as to a key, and `read_dir` follows a symlink there.
    ForeignStoreDir,
    /// `archive/_scratch/` exists and could not be enumerated. A refusal of this
    /// pass, not of the command: the catalog pass attests to a different ledger
    /// and neither is a precondition of the other.
    UnreadableStoreRoot,
    /// The manifest's recorded identity does not match the tree this key names.
    /// **Not reachable yet** — it needs the `slug_hex`/`uuid_hex` fields, which
    /// are queued separately. Defined so the reported vocabulary is already the
    /// one the design specifies and populating it changes no output schema.
    StoreKeyCollision,
    /// A store directory with no `manifest.json` at all.
    NoManifest,
    /// A `manifest.json` that exists but does not parse.
    UnreadableManifest,
    /// An entry whose identity does not decode. Its `store_rel()` is
    /// *unknowable*, so it can be tested against neither half of S — which is a
    /// statement about what the ledger can prove, not a defect of the store.
    UndecodableEntry,
    /// The key-level consequence of the above: reconciliation refuses here on
    /// every future run, so the ledger stays incomplete and stale artifacts
    /// accumulate with no correction. This is a state an operator has to leave,
    /// not one the tool leaves by itself (§3), so it is named at key level and
    /// fails the run.
    UnreconcilableKey,
    /// S1: a `stored: true` entry with no regular-file `.zst` at its `store_rel()`.
    MissingArtifact,
    /// S1: a `stored: false` entry that nonetheless has a `.zst` at its
    /// `store_rel()` — the ledger disclaims bytes the store holds.
    UnclaimedArtifact,
    /// S1: a regular-file `*.zst` no `stored: true` entry claims. Catches drift
    /// introduced from outside the tool.
    OrphanArtifact,
    /// S2: the artifact does not decompress to its entry's `content_sha256`.
    ContentMismatch,
    /// S2 does not apply: the entry carries no `content_sha256`. Every manifest
    /// written before D2/R1 looks like this, and salvage preserves them.
    NoContentHash,
    /// A `*.zst` that is not a regular file.
    ForeignArtifact,
    /// The tree identity a ledger records cannot be read: hex that does not
    /// decode, or only one of the two halves.
    ///
    /// **Unverifiable, not a violation** — the store may be perfectly intact;
    /// what cannot be proven is which tree this ledger belongs to. The same
    /// shape as `NoContentHash`, and named for the same reason: archive and the
    /// GC gate *refuse* on this state, and a refusal nothing reports is a store
    /// that silently stops being archived. Reporting and refusing are not
    /// alternatives here — they are the two halves of one response.
    UndecodableIdentity,
    /// Two entries name one identity. `read --scratch` already detects this,
    /// serves the row the store corroborates, and refers the operator to
    /// `yomi verify` — which until now could not see the defect at all, so the
    /// referral went nowhere.
    ///
    /// A **violation**, not a refused key: a refused key means the key was not
    /// examined, and a duplicate prevents nothing. Both rows decode, both are
    /// checkable against S1 and S2, and because they name one identity they name
    /// one artifact path, so the orphan sweep stays sound and reconciliation
    /// stays enabled. Everything remains examinable — what is broken is the
    /// ledger, and a broken ledger over an intact store is a violation.
    DuplicateIdentity,
}

impl ScratchIssue {
    pub fn class(self) -> FindingClass {
        match self {
            ScratchIssue::ForeignStoreDir
            | ScratchIssue::UnreadableStoreRoot
            | ScratchIssue::StoreKeyCollision
            | ScratchIssue::UnreconcilableKey => FindingClass::RefusedKey,
            ScratchIssue::NoManifest
            | ScratchIssue::UnreadableManifest
            | ScratchIssue::MissingArtifact
            | ScratchIssue::UnclaimedArtifact
            | ScratchIssue::OrphanArtifact
            | ScratchIssue::ContentMismatch
            | ScratchIssue::DuplicateIdentity => FindingClass::Violation,
            ScratchIssue::NoContentHash
            | ScratchIssue::UndecodableEntry
            | ScratchIssue::UndecodableIdentity => FindingClass::Unverifiable,
            ScratchIssue::ForeignArtifact => FindingClass::ForeignMatter,
        }
    }

    /// Whether this finding compares the ledger against the store, and so cannot
    /// stand unless the two were a consistent snapshot.
    ///
    /// The rule is one principle, not a list: **without exclusion the pair
    /// (manifest, store) is not a consistent snapshot, so no finding that
    /// compares one against the other may stand.** Archive writes artifacts
    /// *before* the manifest and reconciles *after* it, so for the whole store
    /// pass a new `.zst` sits under a manifest that predates it and a rewritten
    /// `.zst` sits under an entry whose `content_sha256` describes the previous
    /// content. Every one of these would then be a true-looking accusation about
    /// a healthy store.
    ///
    /// The rest stand: each depends on a single atomically-replaced object (the
    /// manifest is temp-write + rename, so a reader sees old or new, never torn)
    /// or on the store path's classification, and archive never transiently
    /// produces them.
    /// An exhaustive `match` rather than a `matches!`, deliberately: a new issue
    /// that fails to declare itself must not silently stand — it must fail to
    /// compile. "Someone adds a comparative check and forgets the downgrade" is
    /// designed out here rather than remembered.
    pub fn requires_exclusion(self) -> bool {
        match self {
            ScratchIssue::NoManifest
            | ScratchIssue::MissingArtifact
            | ScratchIssue::UnclaimedArtifact
            | ScratchIssue::OrphanArtifact
            | ScratchIssue::ContentMismatch => true,
            // Each depends on a single atomically-replaced object or on the
            // store path's classification, and archive never transiently
            // produces it. `DuplicateIdentity` is the strongest case: archive
            // cannot produce one at all, transiently or otherwise.
            ScratchIssue::ForeignStoreDir
            | ScratchIssue::UnreadableStoreRoot
            | ScratchIssue::StoreKeyCollision
            | ScratchIssue::UnreadableManifest
            | ScratchIssue::UndecodableEntry
            | ScratchIssue::UnreconcilableKey
            | ScratchIssue::NoContentHash
            | ScratchIssue::ForeignArtifact
            | ScratchIssue::UndecodableIdentity
            | ScratchIssue::DuplicateIdentity => false,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ScratchIssue::ForeignStoreDir => "ForeignStoreDir",
            ScratchIssue::UnreadableStoreRoot => "UnreadableStoreRoot",
            ScratchIssue::StoreKeyCollision => "StoreKeyCollision",
            ScratchIssue::NoManifest => "NoManifest",
            ScratchIssue::UnreadableManifest => "UnreadableManifest",
            ScratchIssue::UndecodableEntry => "UndecodableEntry",
            ScratchIssue::UnreconcilableKey => "UnreconcilableKey",
            ScratchIssue::MissingArtifact => "MissingArtifact",
            ScratchIssue::UnclaimedArtifact => "UnclaimedArtifact",
            ScratchIssue::OrphanArtifact => "OrphanArtifact",
            ScratchIssue::ContentMismatch => "ContentMismatch",
            ScratchIssue::NoContentHash => "NoContentHash",
            ScratchIssue::ForeignArtifact => "ForeignArtifact",
            ScratchIssue::DuplicateIdentity => "DuplicateIdentity",
            ScratchIssue::UndecodableIdentity => "UndecodableIdentity",
        }
    }
}

/// One finding, naming the key and — for entry- and artifact-level issues — the
/// store-relative path it concerns.
#[derive(Debug, Clone)]
pub struct ScratchFinding {
    pub key: String,
    /// Store-relative path, lossy, for display only. Empty for key-level issues.
    pub rel: String,
    pub issue: ScratchIssue,
    /// The class this finding was filed under. Equal to `issue.class()` except
    /// where a comparative finding was downgraded for want of exclusion — the
    /// issue name never changes, only where it lands.
    pub class: FindingClass,
}

/// The scratch pass's result. Findings are partitioned by class so a caller
/// cannot accidentally fail the run on an `unverifiable`.
#[derive(Debug)]
pub struct ScratchVerifyReport {
    /// Whether the write lock was held for the pass. When false, no finding that
    /// compares the ledger against the store may stand, and the ones that would
    /// have are filed as `unverifiable` instead. A scheduled `verify` that is
    /// *never* exclusive has never checked S1 or S2 — that, not any individual
    /// downgraded finding, is the condition worth alerting on.
    pub exclusive: bool,
    /// Store directories examined, refusals included.
    pub keys: u64,
    /// Artifacts that decompressed to their `content_sha256`. Sound in either
    /// condition: an artifact that matched its entry is a true statement about
    /// that pair even if both change a moment later. Positives survive the
    /// downgrade; accusations do not.
    pub verified: u64,
    pub violations: Vec<ScratchFinding>,
    pub unverifiable: Vec<ScratchFinding>,
    pub foreign_matter: Vec<ScratchFinding>,
    pub refused: Vec<ScratchFinding>,
    /// What scratch contributes to law Q (§4). Collected here rather than by a
    /// second walk because this pass is the one that reads the manifests — the
    /// ledger law Q is stated over for scratch — and it reads them under the
    /// store-dir guards, so a key it refused contributes no claims, which is
    /// exactly right: a ledger not trusted enough to check S is not trusted
    /// enough to attest to an original either.
    pub quarantine_claims: Vec<crate::scan::quarantine::QuarantineClaim>,
    /// Quarantine-relative subtrees whose ledger was refused, so law Q's sweep
    /// must not judge anything under them.
    pub quarantine_unexamined: Vec<PathBuf>,
}

impl ScratchVerifyReport {
    fn new(exclusive: bool) -> Self {
        ScratchVerifyReport {
            exclusive,
            keys: 0,
            verified: 0,
            violations: Vec::new(),
            unverifiable: Vec::new(),
            foreign_matter: Vec::new(),
            refused: Vec::new(),
            quarantine_claims: Vec::new(),
            quarantine_unexamined: Vec::new(),
        }
    }

    fn push(&mut self, key: &str, rel: &str, issue: ScratchIssue) {
        let class = if !self.exclusive && issue.requires_exclusion() {
            FindingClass::Unverifiable
        } else {
            issue.class()
        };
        let f = ScratchFinding {
            key: key.to_string(),
            rel: rel.to_string(),
            issue,
            class,
        };
        match class {
            FindingClass::Violation => self.violations.push(f),
            FindingClass::Unverifiable => self.unverifiable.push(f),
            FindingClass::ForeignMatter => self.foreign_matter.push(f),
            FindingClass::RefusedKey => self.refused.push(f),
        }
    }

    /// Mark a scratch subtree as one law Q's sweep must not judge, named
    /// quarantine-relative (`_scratch/<key>`, which is what `quarantine_rel`
    /// yields for that key's artifacts).
    fn unexamine(&mut self, rel: &Path) {
        self.quarantine_unexamined.push(rel.to_path_buf());
    }

    /// Exit 2 on any violation and on any refused key. `unverifiable` and
    /// `foreign matter` are reported and do not by themselves fail the run.
    pub fn failed(&self) -> bool {
        !self.violations.is_empty() || !self.refused.is_empty()
    }
}

/// Check store law S over `archive/_scratch/*/`, scoped to the key carrying
/// `session` when one is given.
///
/// **Manifest-driven, because the manifest is what the delete gate trusts.**
/// Scratch writes no catalog row; mirroring it into the catalog purely to give
/// `verify` something to iterate would create a third ledger able to drift from
/// both the manifest and the store.
///
/// **Redaction non-exposure is structural.** The only things this reads are
/// `manifest.json` and the store's own `*.zst`. It never opens the live tree and
/// never opens `quarantine/`, so no un-redacted byte is reachable from here; and
/// decompressed bytes are hashed and dropped inside the loop below — no finding
/// carries content, so there is no path from a stored byte to the output.
/// **Cannot fail the command.** The catalog pass and this one attest to
/// different ledgers and neither is a precondition of the other, so a scratch
/// root that will not enumerate is a refusal of *this* pass — reported, with the
/// catalog results still emitted. Per-pass doubt degrades; only global doubt
/// aborts, the rule §5 already applies to the GC commit loop.
pub fn verify_stores(
    archive_dir: &Path,
    session: Option<&OsStr>,
    exclusive: bool,
) -> ScratchVerifyReport {
    let mut report = ScratchVerifyReport::new(exclusive);
    let root = store_root(archive_dir);
    // The root gets the same classification a key does. `read_dir` follows a
    // symlink, so without this the whole store could be read from outside the
    // archive tree — and every finding below would be drawn from a foreign
    // ledger. "A foreign ledger must not be read at all" is not a rule about
    // keys; it is a rule about store paths, and the root is one.
    match classify_store_dir(&root) {
        // A store that has never archived scratch is not a defect (W1/R8) — but
        // it produces no claims either, so law Q's sweep must not judge what sits
        // under `quarantine/_scratch/`. A store whose `_scratch` was deleted
        // still holds every original scratch ever quarantined, and calling those
        // strays would be a false label rather than a coarse one — the D-S7
        // mistake, which is the worse of the two. On a store that simply never
        // archived scratch this covers an empty subtree and says nothing.
        StoreDir::Absent => {
            report.unexamine(Path::new(SCRATCH_ROOT));
            return report;
        }
        StoreDir::Foreign => {
            report.push(SCRATCH_ROOT, "", ScratchIssue::ForeignStoreDir);
            report.unexamine(Path::new(SCRATCH_ROOT));
            return report;
        }
        StoreDir::Own => {}
    }
    let Ok(dir) = std::fs::read_dir(&root) else {
        report.push(SCRATCH_ROOT, "", ScratchIssue::UnreadableStoreRoot);
        report.unexamine(Path::new(SCRATCH_ROOT));
        return report;
    };

    let mut keys: Vec<(String, PathBuf)> = Vec::new();
    for e in dir.flatten() {
        let key = e.file_name().to_string_lossy().into_owned();
        // A session name selects the one store dir carrying it. `select_key` is
        // the shared resolver — a suffix test cannot address a hex key. Where the
        // name is ambiguous the recorded identity settles it, below, on the
        // manifest this pass reads anyway.
        // `Unreadable` is kept rather than filtered out: `verify_one_store`
        // names it, and a key dropped here would be a key this pass silently
        // failed to mention.
        if session.is_none_or(|u| select_key(&root, &key, u) != KeySelection::Miss) {
            keys.push((key, e.path()));
        }
    }
    keys.sort();

    for (key, store_dir) in keys {
        report.keys += 1;
        verify_one_store(&mut report, &key, &store_dir, session);
    }
    report
}

fn verify_one_store(
    report: &mut ScratchVerifyReport,
    key: &str,
    store_dir: &Path,
    session: Option<&OsStr>,
) {
    // A store path that is not a directory yomi owns may point anywhere, and
    // every fact drawn through it is foreign. The fourth caller of the one
    // predicate the writer, the reconciler and the GC gate already share.
    // A key whose ledger this pass does not read is a key whose originals law Q
    // must not judge either: nothing here can say which of them is claimed.
    let quarantine_subtree = Path::new(SCRATCH_ROOT).join(key);
    if classify_store_dir(store_dir) != StoreDir::Own {
        report.push(key, "", ScratchIssue::ForeignStoreDir);
        report.unexamine(&quarantine_subtree);
        return;
    }
    let mf = match read_manifest_at(&store_dir.join("manifest.json")) {
        ManifestRead::Ok(mf) => mf,
        ManifestRead::Missing => {
            report.push(key, "", ScratchIssue::NoManifest);
            report.unexamine(&quarantine_subtree);
            return;
        }
        ManifestRead::Unreadable => {
            report.push(key, "", ScratchIssue::UnreadableManifest);
            report.unexamine(&quarantine_subtree);
            return;
        }
    };

    // Immediately after the manifest is read and before any judgment drawn from
    // it. `verify` has no live tree to compare against — that is the GC gate's
    // half — so it makes the two store-side statements it can:
    //
    // * the identity a ledger records must be the identity that produces the key
    //   it sits under. A manifest that fails it describes some other tree, and
    //   every finding below would be a statement about that one;
    // * and when a selector picked this key by name, the ledger must agree that
    //   the name meant this session — the plain form's last residual, closed
    //   here at no extra open because the manifest is already in hand.
    let recorded = mf.recorded_identity();
    if recorded == RecordedIdentity::Corrupt {
        // Named, not acted on: the entries beside it are still checkable, and
        // this says what the ledger cannot prove about the tree as a whole.
        report.push(key, "", ScratchIssue::UndecodableIdentity);
    }
    let key_disagrees =
        matches!(&recorded, RecordedIdentity::Recorded(s, u) if store_key(s, u) != key);
    let selector_disagrees = session
        .is_some_and(|sel| confirm_selector(&mf, key, sel) == SelectorConfirmation::Collision);
    if key_disagrees || selector_disagrees {
        report.push(key, "", ScratchIssue::StoreKeyCollision);
        report.unexamine(&quarantine_subtree);
        return;
    }

    // Everything artifact-shaped in the store, split by what S1 can speak about.
    let mut regular: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for e in walkdir::WalkDir::new(store_dir)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        if e.path().extension().and_then(|x| x.to_str()) != Some("zst") {
            continue;
        }
        // The same predicate the read path applies, so the two layers cannot
        // classify one object differently.
        if is_stored_artifact(e.path()) {
            regular.insert(e.path().to_path_buf());
        } else {
            report.push(
                key,
                &store_rel_display(store_dir, e.path()),
                ScratchIssue::ForeignArtifact,
            );
        }
    }

    // Artifacts some entry explains, whether by claiming them or by disclaiming
    // them. The orphan sweep below reports what is left, so one object never
    // draws two names: an artifact a `stored: false` entry sits on is reported
    // once, as the more specific `UnclaimedArtifact`.
    let mut accounted: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut undecodable = false;
    // One identity, one artifact path — so a repeat must be checked once, or the
    // same object draws both a `verified` and a `ContentMismatch` and the counts
    // stop meaning anything. The first row wins (manifest order is stable, so
    // the choice is deterministic); the duplicate is reported once per repeated
    // identity, not once per extra row, and the ledger is broken either way.
    let mut seen: std::collections::HashSet<ScratchRel> = std::collections::HashSet::new();
    let mut reported_dup: std::collections::HashSet<ScratchRel> = std::collections::HashSet::new();
    for entry in &mf.entries {
        let Some(rel) = entry.rel() else {
            undecodable = true;
            report.push(key, &entry.path, ScratchIssue::UndecodableEntry);
            continue;
        };
        if !seen.insert(rel.clone()) {
            if reported_dup.insert(rel.clone()) {
                report.push(key, &entry.path, ScratchIssue::DuplicateIdentity);
            }
            continue;
        }
        // What this entry contributes to law Q. Every entry, not only the
        // quarantined ones: Q1 asks about the ones that record an original, but
        // Q2 asks whether a file is *claimed*, and the mirror rule makes an
        // artifact's path belong to it whether or not an original is recorded.
        report
            .quarantine_claims
            .push(crate::scan::quarantine::QuarantineClaim {
                owner: key.to_string(),
                stored_rel: Path::new(SCRATCH_ROOT).join(key).join(rel.store_rel()),
                quarantined: entry.quarantined,
                source_sha256: entry.source_sha256.clone(),
            });
        let artifact = store_dir.join(rel.store_rel());
        if !entry.stored {
            // S1, the other direction: the ledger disclaims bytes the store holds.
            if regular.contains(&artifact) {
                accounted.insert(artifact);
                report.push(key, &entry.path, ScratchIssue::UnclaimedArtifact);
            }
            continue;
        }
        if !regular.contains(&artifact) {
            report.push(key, &entry.path, ScratchIssue::MissingArtifact);
            continue;
        }
        accounted.insert(artifact.clone());
        let Some(content_sha) = &entry.content_sha256 else {
            // S2 does not apply. Not a defect — the pre-D2/R1 population.
            report.push(key, &entry.path, ScratchIssue::NoContentHash);
            continue;
        };
        // Decompressed here, hashed, and dropped: no finding carries content.
        let intact = std::fs::read(&artifact)
            .ok()
            .and_then(|raw| crate::archive::compress::decompress_all(&raw).ok())
            .is_some_and(|plain| &crate::util::sha256_hex(&plain) == content_sha);
        if intact {
            report.verified += 1;
        } else {
            report.push(key, &entry.path, ScratchIssue::ContentMismatch);
        }
    }

    // The orphan sweep is only sound when every artifact *can* be named. An
    // undecodable entry's `store_rel()` is unknowable, so an artifact left over
    // here may well be that entry's — and calling it unclaimed would be the very
    // mistake reconciliation refuses to make when it declines to prune such a
    // key. The key-level refusal below says so instead.
    if undecodable {
        report.push(key, "", ScratchIssue::UnreconcilableKey);
        // The same reasoning reaches law Q: that entry's quarantine path is
        // unknowable too, so an original under this key may well be its, and
        // calling it a stray would be the same false accusation.
        report.unexamine(&quarantine_subtree);
    } else {
        for orphan in regular.difference(&accounted) {
            report.push(
                key,
                &store_rel_display(store_dir, orphan),
                ScratchIssue::OrphanArtifact,
            );
        }
    }
}

fn store_rel_display(store_dir: &Path, path: &Path) -> String {
    path.strip_prefix(store_dir)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(bytes: &[u8]) -> OsString {
        OsString::from_vec(bytes.to_vec())
    }

    /// A store with no `archive/_scratch/` produces no claims, so law Q must not
    /// judge what sits under `quarantine/_scratch/`. On a store that never
    /// archived scratch this covers an empty subtree and costs nothing; on one
    /// whose `_scratch` was deleted it is the difference between "unexamined"
    /// and every scratch original reported as a stray — a false label, which is
    /// worse than a coarse one (D-S7).
    #[test]
    fn an_absent_scratch_root_leaves_law_q_nothing_to_judge() {
        let report = verify_stores(Path::new("/nonexistent-archive-dir"), None, true);
        assert_eq!(report.keys, 0);
        assert!(report.quarantine_claims.is_empty());
        assert_eq!(
            report.quarantine_unexamined,
            vec![PathBuf::from(SCRATCH_ROOT)],
            "an absent scratch root left its quarantine subtree open to accusation"
        );
        // Absent is still not a defect: W1/R8 holds either way.
        assert!(!report.failed());
    }

    fn live(session: &str, rel: &[u8]) -> Option<ScratchRel> {
        let session = Path::new(session);
        ScratchRel::from_live(session, &session.join(Path::new(&os(rel))))
    }

    /// Every name shape a Unix filesystem admits survives live -> manifest ->
    /// live unchanged. `\` is an ordinary filename byte here, not a separator.
    #[test]
    fn round_trips_utf8_non_utf8_and_backslash_names() {
        let cases: &[&[u8]] = &[
            b"scratchpad/a.md",
            b"tasks/run.output",
            b"scratchpad/deep/er/still/a.md",
            "scratchpad/\u{65e5}\u{672c}\u{8a9e}.md".as_bytes(),
            b"scratchpad/back\\slash.md",
            b"scratchpad/back\\slash/dir\\name.md",
            b"scratchpad/note-\xff.md",
            b"scratchpad/\xfe\x80-lone-continuation.md",
            b"scratchpad/mixed-\xff-\\-name.md",
        ];
        for raw in cases {
            let rel = live("/tmp/s/uuid", raw).expect("live rel");
            assert_eq!(rel.as_bytes(), *raw, "from_live lost bytes");

            let (path, path_hex) = rel.manifest_fields();
            let back =
                ScratchRel::from_manifest(&path, path_hex.as_deref()).expect("manifest round-trip");
            assert_eq!(back, rel, "round-trip changed the identity of {raw:?}");
            assert_eq!(back.as_bytes(), *raw);

            // hex appears exactly when the name is not representable as UTF-8.
            assert_eq!(
                path_hex.is_some(),
                std::str::from_utf8(raw).is_err(),
                "path_hex emitted for the wrong case on {raw:?}"
            );
        }
    }

    /// The regression this module exists for: two names that share one lossy
    /// form must not share a key, a manifest record, or a store path.
    #[test]
    fn lossy_colliding_names_keep_distinct_identities() {
        let a = live("/tmp/s/uuid", b"scratchpad/note-\xff.md").unwrap();
        let b = live("/tmp/s/uuid", b"scratchpad/note-\xfe.md").unwrap();

        let (a_path, a_hex) = a.manifest_fields();
        let (b_path, b_hex) = b.manifest_fields();
        assert_eq!(
            a_path, b_path,
            "fixture is not a lossy collision; the test proves nothing"
        );

        assert_ne!(a, b, "distinct raw names compared equal");
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_ne!(a_hex, b_hex, "the hex field collapsed the two names");
        assert_ne!(
            a.store_rel(),
            b.store_rel(),
            "two names resolved to one store path — their .zst overwrite each other"
        );
        assert_ne!(
            ScratchRel::from_manifest(&a_path, a_hex.as_deref()).unwrap(),
            ScratchRel::from_manifest(&b_path, b_hex.as_deref()).unwrap(),
        );

        // Without the hex — a manifest written before this field — they do
        // collide. That is the pre-existing behaviour, preserved for old files.
        assert_eq!(
            ScratchRel::from_manifest(&a_path, None).unwrap(),
            ScratchRel::from_manifest(&b_path, None).unwrap(),
        );
    }

    #[test]
    fn store_rel_appends_zst_to_the_raw_bytes() {
        let rel = live("/tmp/s/uuid", b"scratchpad/sub/a.md").unwrap();
        assert_eq!(rel.store_rel(), Path::new("scratchpad/sub/a.md.zst"));
        assert_eq!(
            rel.store_rel().as_os_str().as_bytes(),
            b"scratchpad/sub/a.md.zst"
        );

        let odd = live("/tmp/s/uuid", b"scratchpad/n-\xff.md").unwrap();
        assert_eq!(
            odd.store_rel().as_os_str().as_bytes(),
            b"scratchpad/n-\xff.md.zst",
            "store path is not derived from the raw bytes"
        );
    }

    #[test]
    fn glob_subpath_is_session_relative() {
        let rel = live("/tmp/s/uuid", b"scratchpad/repo/node_modules/x.js").unwrap();
        assert_eq!(rel.glob_subpath(), "scratchpad/repo/node_modules/x.js");
        assert_eq!(
            rel.to_rel_path(),
            Path::new("scratchpad/repo/node_modules/x.js")
        );
    }

    #[test]
    fn rejects_non_descendants_and_traversal() {
        let s = Path::new("/tmp/s/uuid");
        assert!(ScratchRel::from_live(s, Path::new("/tmp/other/a.md")).is_none());
        assert!(
            ScratchRel::from_live(s, s).is_none(),
            "the session dir itself is not an entry"
        );
        // A hostile or corrupt manifest must not produce a key that escapes the
        // store dir when joined by `store_rel`.
        assert!(ScratchRel::from_manifest("../../etc/passwd", None).is_none());
        assert!(ScratchRel::from_manifest("a/../../b", None).is_none());
        assert!(ScratchRel::from_manifest("/etc/passwd", None).is_none());
        assert!(ScratchRel::from_manifest("", None).is_none());
        // Malformed hex refuses rather than silently keying on the lossy path.
        assert!(ScratchRel::from_manifest("a.md", Some("zz")).is_none());
        assert!(ScratchRel::from_manifest("a.md", Some("abc")).is_none());
    }

    /// Every real slug and session name is UTF-8, and those keys must come out
    /// exactly as the old `format!("{slug}--{uuid}")` produced them — an existing
    /// store must not be renamed by this change.
    #[test]
    fn store_key_is_verbatim_for_utf8_names() {
        for (slug, uuid) in [
            ("-home-test", "aaaa1111-2222-3333-4444-555555555555"),
            // A real project slug contains `--`; nothing parses a key, so this is
            // passed through as-is.
            ("-home-yhi-code-github-yaoyorozu-hi--yomi", "uuid-1"),
            ("-", "x"),
            ("\u{65e5}\u{672c}", "\u{8a9e}"),
        ] {
            assert_eq!(
                store_key(OsStr::new(slug), OsStr::new(uuid)),
                format!("{slug}--{uuid}"),
                "the key for a UTF-8 session changed; existing stores would be \
                 orphaned"
            );
        }
    }

    /// The defect: two session directories differing only in invalid bytes must
    /// not share a store. They shared one directory, one manifest and one
    /// namespace of `.zst`, so the later run's live pass claimed the earlier
    /// one's identity and overwrote its only archived copy.
    #[test]
    fn store_key_separates_lossy_colliding_names() {
        let a = store_key(OsStr::new("-home-test"), &os(b"sess-\xfe"));
        let b = store_key(OsStr::new("-home-test"), &os(b"sess-\xff"));
        assert_eq!(
            OsStr::new("sess-\u{fffd}").to_string_lossy(),
            os(b"sess-\xfe").to_string_lossy(),
            "fixture is not a lossy collision; the test proves nothing"
        );
        assert_ne!(a, b, "two distinct session names produced one store key");

        // The slug side collides the same way and must separate the same way.
        let c = store_key(&os(b"slug-\xfe"), OsStr::new("u"));
        let d = store_key(&os(b"slug-\xff"), OsStr::new("u"));
        assert_ne!(c, d);
        // Encoding is injective on bytes, so it separates every pair, not just
        // the ones a test happens to name.
        for k in [&a, &b, &c, &d] {
            assert!(k.starts_with(HEX_KEY_PREFIX), "{k} is not the encoded form");
        }
    }

    /// The two key forms must occupy disjoint namespaces, or a UTF-8 session
    /// could be named so as to impersonate an encoded one.
    #[test]
    fn store_key_forms_cannot_impersonate_each_other() {
        // A UTF-8 pair whose plain form would begin with the marker is pushed
        // into the encoded branch instead of colliding with it.
        let impostor = store_key(OsStr::new("_hex"), OsStr::new("aabb--ccdd"));
        assert!(impostor.starts_with(HEX_KEY_PREFIX));
        let genuine = store_key(&os(b"\xaa\xbb"), &os(b"\xcc\xdd"));
        assert_eq!(genuine, "_hex--aabb--ccdd");
        assert_ne!(
            impostor, genuine,
            "a UTF-8 session impersonated an encoded key"
        );

        // Anything not starting with the marker stays plain.
        assert_eq!(
            store_key(OsStr::new("_he"), OsStr::new("x--y")),
            "_he--x--y"
        );

        // The third namespace is disjoint from the other two for the same
        // reason: a plain pair that would begin `_h256--` is encoded instead.
        let digest_impostor = store_key(OsStr::new("_h256"), OsStr::new("deadbeef"));
        assert!(digest_impostor.starts_with(HEX_KEY_PREFIX));
        assert!(!digest_impostor.starts_with(DIGEST_KEY_PREFIX));
    }

    /// A key over `KEY_MAX` takes the digest form, and the digest is over the
    /// hex-joined pair — hex carries no `-`, so the `--` inside it is an
    /// unambiguous separator even though the one in the plain form is not.
    #[test]
    fn an_over_long_key_takes_the_digest_form() {
        let long = "-".repeat(400);
        let k = store_key(OsStr::new(&long), OsStr::new("uuid-1"));
        assert!(k.starts_with(DIGEST_KEY_PREFIX), "{k}");
        assert_eq!(k.len(), DIGEST_KEY_PREFIX.len() + 64, "{k}");
        assert!(
            k[DIGEST_KEY_PREFIX.len()..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        );

        // Injective where the plain form is not: the two pairs that collide on
        // `a---b` differ under the digest, because the inner encoding separates
        // them before hashing.
        let a = store_key(&os(&[b'a'; 300]), OsStr::new("-b"));
        let b = store_key(&os(&[b'a'; 299]), OsStr::new("b"));
        assert!(a.starts_with(DIGEST_KEY_PREFIX) && b.starts_with(DIGEST_KEY_PREFIX));
        assert_ne!(a, b, "the digest form merged two distinct pairs");

        // And it is reached only when the shorter forms cannot be used: one byte
        // under the bound is still the plain form, verbatim.
        let fits = "x".repeat(KEY_MAX - "--u".len());
        let plain = store_key(OsStr::new(&fits), OsStr::new("u"));
        assert_eq!(plain, format!("{fits}--u"));
        assert_eq!(plain.len(), KEY_MAX);
    }

    /// The hazard the recorded identity exists for: two distinct trees whose
    /// plain keys are equal. The key cannot tell them apart — that is the defect
    /// — so the ledger must, and whoever does not match it refuses.
    #[test]
    fn a_recorded_identity_separates_two_trees_that_share_a_key() {
        assert_eq!(
            store_key(OsStr::new("a"), OsStr::new("-b")),
            store_key(OsStr::new("a-"), OsStr::new("b")),
            "fixture is not a key collision; the test proves nothing"
        );

        let mut mf = ScratchManifest {
            key: "a---b".into(),
            slug_hex: crate::util::hex(b"a"),
            uuid_hex: crate::util::hex(b"-b"),
            captured_at: String::new(),
            total_bytes: 0,
            over_total_cap: false,
            caps_lifted: false,
            entries: Vec::new(),
        };
        assert_eq!(
            identity_verdict(&mf, Path::new("/tmp/a/-b")),
            IdentityVerdict::Proceed,
            "a tree was refused its own ledger"
        );
        assert_eq!(
            identity_verdict(&mf, Path::new("/tmp/a-/b")),
            IdentityVerdict::Collision,
            "the second tree wrote through the first's ledger"
        );

        // A manifest from before the fields has nothing to contradict, so every
        // pre-U6 store proceeds and is stamped on the next write rather than
        // being refused forever.
        let pre_u6 = ScratchManifest {
            slug_hex: String::new(),
            uuid_hex: String::new(),
            ..mf.clone()
        };
        assert_eq!(pre_u6.recorded_identity(), RecordedIdentity::Unrecorded);
        assert_eq!(
            identity_verdict(&pre_u6, Path::new("/tmp/a-/b")),
            IdentityVerdict::Proceed
        );

        // A record this run cannot read is a *third* state. Folding it into
        // "records nothing" let one corrupted byte turn the check off and hand
        // the other tree the overwrite; folding it into "records something else"
        // locked the owner out of its own store, permanently, because a refused
        // archive can never restamp the field that would repair it.
        for (slug_hex, uuid_hex, why) in [
            ("zz".to_string(), crate::util::hex(b"-b"), "undecodable hex"),
            (crate::util::hex(b"a"), String::new(), "half recorded"),
            (String::new(), crate::util::hex(b"-b"), "half recorded"),
        ] {
            let broken = ScratchManifest {
                slug_hex,
                uuid_hex,
                ..mf.clone()
            };
            assert_eq!(
                broken.recorded_identity(),
                RecordedIdentity::Corrupt,
                "{why} read as an absent or a readable claim"
            );
            // Refused against *either* tree — including the one that owns it,
            // which is the point: nothing here can be shown to describe any
            // tree.
            for live in ["/tmp/a/-b", "/tmp/a-/b"] {
                assert_eq!(
                    identity_verdict(&broken, Path::new(live)),
                    IdentityVerdict::Refuse,
                    "{why} authorized a write to {live}"
                );
            }
        }

        // And the state is *named*, not merely acted on — refusing and reporting
        // are the two halves of one response.
        assert_eq!(
            ScratchIssue::UndecodableIdentity.class(),
            FindingClass::Unverifiable
        );
        mf.slug_hex = "zz".into();
        assert_eq!(mf.recorded_identity(), RecordedIdentity::Corrupt);
    }

    /// **No existing store is renamed.** The promise the whole approach rests on
    /// — detection was chosen over an injective encoding precisely because any
    /// injective encoding renames every store directory — so it is pinned
    /// against the derivation as it stood before `KEY_MAX` and the digest form
    /// existed, over every shape a real store holds.
    #[test]
    fn key_derivation_is_byte_identical_for_every_existing_store() {
        /// The derivation at 79390e0, verbatim.
        fn before(slug: &OsStr, uuid: &OsStr) -> String {
            if let (Some(slug), Some(uuid)) = (slug.to_str(), uuid.to_str()) {
                let plain = format!("{slug}--{uuid}");
                if !plain.starts_with(HEX_KEY_PREFIX) {
                    return plain;
                }
            }
            format!(
                "{HEX_KEY_PREFIX}{}--{}",
                crate::util::hex(slug.as_bytes()),
                crate::util::hex(uuid.as_bytes())
            )
        }

        let deep = format!("-home-yhi-{}", "code-".repeat(12));
        let cases: &[(&OsStr, &OsStr)] = &[
            // The real population: a cwd with `/`->`-`, and a session uuid.
            (
                OsStr::new("-home-yhi"),
                OsStr::new("2ec0a278-9fcf-4b22-99b8-9f1310c50e8f"),
            ),
            (OsStr::new("-home-test"), OsStr::new("s1")),
            // A slug that already contains `--`, which is routine.
            (OsStr::new("-home-yhi-code--x"), OsStr::new("uuid-1")),
            // Deep, but still inside the bound.
            (OsStr::new(&deep), OsStr::new("uuid-1")),
            // The encoded form, unchanged for names that are not UTF-8.
            (&os(b"slug-\xff"), &os(b"sess-\xfe")),
            (OsStr::new("_hex--a"), OsStr::new("b")),
        ];
        for (slug, uuid) in cases {
            let now = store_key(slug, uuid);
            assert_eq!(
                now,
                before(slug, uuid),
                "the key of {slug:?}/{uuid:?} moved, so its store directory would \
                 have to be renamed"
            );
            assert!(now.len() <= KEY_MAX, "fixture exceeds the bound: {now}");
        }
    }

    /// The resolver's residual, closed by the ledger: a session directory
    /// literally named `bbbb--cccc` matches the *name* of the key of slug
    /// `-a--bbbb` and session `cccc`. Pure ASCII, and not a miss — an ambiguity.
    #[test]
    fn a_name_ambiguous_key_is_a_collision_not_a_match() {
        let key = store_key(OsStr::new("-a--bbbb"), OsStr::new("cccc"));
        assert_eq!(key, "-a--bbbb--cccc");
        // The name test alone cannot tell the two apart — that is the residual.
        assert!(store_key_matches_session(&key, OsStr::new("cccc")));
        assert!(store_key_matches_session(&key, OsStr::new("bbbb--cccc")));

        // The filter stays a name test — it opens nothing, which is what keeps
        // resolution at one manifest open rather than one per store.
        let root = Path::new("/nonexistent-store-root");
        let sel = |s: &str| select_key(root, &key, OsStr::new(s));
        assert_eq!(sel("cccc"), KeySelection::Match);
        assert_eq!(sel("bbbb--cccc"), KeySelection::Match);
        assert_eq!(sel("nope"), KeySelection::Miss);
        // A full key names its own directory, whatever its form.
        assert_eq!(sel(&key), KeySelection::Match);

        // The ledger is what separates the two, on the manifest the caller has
        // already read.
        let mf = |uuid: &[u8]| ScratchManifest {
            key: key.clone(),
            slug_hex: crate::util::hex(b"-a--bbbb"),
            uuid_hex: crate::util::hex(uuid),
            captured_at: String::new(),
            total_bytes: 0,
            over_total_cap: false,
            caps_lifted: false,
            entries: Vec::new(),
        };
        assert_eq!(
            confirm_selector(&mf(b"cccc"), &key, OsStr::new("cccc")),
            SelectorConfirmation::Confirmed
        );
        assert_eq!(
            confirm_selector(&mf(b"cccc"), &key, OsStr::new("bbbb--cccc")),
            SelectorConfirmation::Collision,
            "a name-ambiguous key was served as the session it does not hold"
        );
        // A full key still makes no claim about a session, so nothing confirms.
        assert_eq!(
            confirm_selector(&mf(b"cccc"), &key, OsStr::new(&key)),
            SelectorConfirmation::Confirmed
        );
        // And a pre-U6 ledger confirms whatever the name matched, as before.
        let mut old = mf(b"cccc");
        old.slug_hex = String::new();
        old.uuid_hex = String::new();
        assert_eq!(
            confirm_selector(&old, &key, OsStr::new("bbbb--cccc")),
            SelectorConfirmation::Confirmed
        );

        // **The fourth layer reads the third state as the other three do.** A
        // ledger this run cannot decode is a claim it cannot read, not an absent
        // one — and here the cost of the other reading is not a lost byte but a
        // wrong answer: one corrupted byte turned a correctly refused question
        // into exit 0 serving another session's archived bytes.
        let mut damaged = mf(b"cccc");
        damaged.slug_hex = "zz".into();
        assert_eq!(damaged.recorded_identity(), RecordedIdentity::Corrupt);
        for asked in ["cccc", "bbbb--cccc"] {
            assert_eq!(
                confirm_selector(&damaged, &key, OsStr::new(asked)),
                SelectorConfirmation::Unreadable,
                "a damaged ledger answered for {asked}"
            );
        }
        // Naming the directory itself still works: it asks nothing of the ledger.
        assert_eq!(
            confirm_selector(&damaged, &key, OsStr::new(&key)),
            SelectorConfirmation::Confirmed
        );

        // A digest-form key encodes nothing recoverable, so with no ledger to
        // read it resolves to nothing rather than guessing.
        let digest = store_key(OsStr::new(&"-".repeat(400)), OsStr::new("uuid-1"));
        assert_eq!(
            select_key(root, &digest, OsStr::new("uuid-1")),
            KeySelection::Miss
        );
        assert_eq!(
            select_key(root, &digest, OsStr::new(&digest)),
            KeySelection::Match
        );
    }

    /// A suffix test cannot address a hex key, and the failure is silent: zero
    /// keys matched, exit 0, indistinguishable from a clean check.
    #[test]
    fn session_resolver_addresses_both_key_forms() {
        let uuid = OsStr::new("aaaa1111-2222-3333-4444-555555555555");
        let plain = store_key(OsStr::new("-home-test"), uuid);
        assert!(store_key_matches_session(&plain, uuid));

        // The hex form the old `ends_with("--<uuid>")` could never match.
        let hexed = store_key(&os(b"-proj-\xff"), uuid);
        assert!(hexed.starts_with(HEX_KEY_PREFIX), "{hexed} is not encoded");
        assert!(
            store_key_matches_session(&hexed, uuid),
            "a hex-encoded key could not be addressed by its real uuid: {hexed}"
        );

        // A non-UTF-8 *uuid* is likewise addressable, by its bytes.
        let odd_uuid = os(b"sess-\xfe");
        let both_hexed = store_key(&os(b"-proj-\xff"), &odd_uuid);
        assert!(store_key_matches_session(&both_hexed, &odd_uuid));
        assert!(!store_key_matches_session(&both_hexed, &os(b"sess-\xff")));
    }

    /// Dispatch on the key's form rather than trying both, or a plain uuid that
    /// happens to spell a hex field would address the wrong session.
    #[test]
    fn session_resolver_does_not_confuse_the_two_forms() {
        // `hex("11") == "3131"`, so this key's *real* uuid is `11`.
        let key = store_key(&os(b"\xff"), OsStr::new("11"));
        assert_eq!(key, "_hex--ff--3131");
        assert!(store_key_matches_session(&key, OsStr::new("11")));
        assert!(
            !store_key_matches_session(&key, OsStr::new("3131")),
            "a plain uuid matched a hex field it merely looks like"
        );
        // And a plain key is never parsed as hex.
        let plain = store_key(OsStr::new("-s"), OsStr::new("u"));
        assert!(store_key_matches_session(&plain, OsStr::new("u")));
        assert!(!store_key_matches_session(&plain, OsStr::new("-s")));
    }

    /// Only comparative findings move, and only their class moves.
    #[test]
    fn exclusion_downgrades_exactly_the_comparative_findings() {
        use ScratchIssue::*;
        let comparative = [
            NoManifest,
            MissingArtifact,
            UnclaimedArtifact,
            OrphanArtifact,
            ContentMismatch,
        ];
        let standing = [
            ForeignStoreDir,
            UnreadableStoreRoot,
            StoreKeyCollision,
            UnreadableManifest,
            UndecodableEntry,
            UnreconcilableKey,
            NoContentHash,
            ForeignArtifact,
            UndecodableIdentity,
            // The strongest case of all: archive cannot produce one at all, so
            // it cannot produce one transiently either.
            DuplicateIdentity,
        ];
        for i in comparative {
            assert!(i.requires_exclusion(), "{} must downgrade", i.as_str());
            assert_eq!(i.class(), FindingClass::Violation);
        }
        for i in standing {
            assert!(
                !i.requires_exclusion(),
                "{} must stand without the lock",
                i.as_str()
            );
        }

        // A downgraded finding keeps its issue name and stops failing the run.
        let mut r = ScratchVerifyReport::new(false);
        r.push("k", "a.md", OrphanArtifact);
        assert!(r.violations.is_empty());
        assert_eq!(r.unverifiable.len(), 1);
        assert_eq!(r.unverifiable[0].issue.as_str(), "OrphanArtifact");
        assert_eq!(r.unverifiable[0].class, FindingClass::Unverifiable);
        assert!(!r.failed(), "a downgraded finding failed the run");

        // Under exclusion the same finding is a violation.
        let mut r = ScratchVerifyReport::new(true);
        r.push("k", "a.md", OrphanArtifact);
        assert_eq!(r.violations.len(), 1);
        assert!(r.failed());

        // A standing finding fails the run in either condition.
        let mut r = ScratchVerifyReport::new(false);
        r.push("k", "", ForeignStoreDir);
        assert_eq!(r.refused.len(), 1);
        assert!(
            r.failed(),
            "a refusal stopped failing the run without the lock"
        );
    }

    /// Whatever branch it takes, the key is used as a directory name under
    /// `archive/_scratch/` and inside a quarantine path.
    #[test]
    fn store_key_is_always_a_legal_filename() {
        let long = "-".repeat(400);
        let keys = [
            store_key(OsStr::new("-home-test"), OsStr::new("uuid-1")),
            store_key(&os(b"slug-\xff"), &os(b"sess-\xfe")),
            store_key(OsStr::new("_hex--a"), OsStr::new("b")),
            // A deep `cwd` yields a long slug, and the hex form doubles it.
            store_key(OsStr::new(&long), OsStr::new("uuid-1")),
            store_key(&os(&vec![0xffu8; 300]), OsStr::new("uuid-1")),
        ];
        for k in keys {
            assert!(!k.is_empty());
            assert!(!k.contains('/'), "{k} would create a nested path");
            assert!(!k.contains('\0'), "{k} carries an interior NUL");
            assert_ne!(k, ".");
            assert_ne!(k, "..");
            // A key is one filename component, so `NAME_MAX` bounds it. Nothing
            // bounded it before, and the failure was `ENAMETOOLONG` out of
            // `create_dir_all` — which `archive_scratch` propagated, ending the
            // whole run.
            assert!(
                k.len() <= KEY_MAX,
                "key is {} bytes, over KEY_MAX: {k}",
                k.len()
            );
        }
    }

    /// A manifest written before `path_hex` existed must parse unchanged and key
    /// exactly as it did before.
    #[test]
    fn legacy_manifest_parses_and_keys_on_path() {
        let legacy = r#"{
          "key": "-home-test--aaaa",
          "captured_at": "2026-07-01T00:00:00.000Z",
          "total_bytes": 12,
          "over_total_cap": false,
          "entries": [
            {"path": "scratchpad/a.md", "bytes": 7, "stored": true,
             "source_sha256": "aa", "content_sha256": "bb"},
            {"path": "scratchpad/junk.bin", "bytes": 5, "stored": false}
          ]
        }"#;
        let mf: ScratchManifest = serde_json::from_str(legacy).expect("legacy manifest must parse");
        assert_eq!(mf.entries.len(), 2);
        assert!(mf.entries.iter().all(|e| e.path_hex.is_none()));
        assert_eq!(
            mf.entries[0].rel().unwrap().as_bytes(),
            b"scratchpad/a.md",
            "legacy entry no longer keys on `path`"
        );
        assert_eq!(
            mf.entries[1].rel().unwrap().as_bytes(),
            b"scratchpad/junk.bin"
        );
        assert_eq!(mf.entries[1].source_sha256, None);

        // The GC gate's old reader declared `entries` alone; a manifest missing
        // the scalars must stay parseable, or an old tree becomes unreclaimable.
        let minimal = r#"{"entries": [{"path": "a.md", "bytes": 1, "stored": false}]}"#;
        let mf: ScratchManifest = serde_json::from_str(minimal).expect("entries-only manifest");
        assert_eq!(mf.total_bytes, 0);
        assert!(!mf.over_total_cap);
    }

    /// A UTF-8 entry must serialize byte-identically to the pre-`path_hex`
    /// schema, so adding the field cannot rewrite the existing store.
    #[test]
    fn utf8_entry_serializes_without_the_hex_field() {
        let rel = live("/tmp/s/uuid", b"scratchpad/a.md").unwrap();
        let mut e = ScratchEntry::new(&rel, 7, None);
        e.source_sha256 = Some("aa".into());
        e.content_sha256 = Some("bb".into());
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"path":"scratchpad/a.md","bytes":7,"stored":true,"source_sha256":"aa","content_sha256":"bb"}"#
        );

        // A non-stored entry carries the recorded cause and nothing else; the
        // pre-`not_stored` shape is what an *unknown* cause still serializes to,
        // which is what keeps an old manifest readable unchanged.
        let odd = live("/tmp/s/uuid", b"scratchpad/n-\xff.md").unwrap();
        let e = ScratchEntry::new(&odd, 3, Some(NotStored::Denied));
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"path":"scratchpad/n-\u{fffd}.md","path_hex":"736372617463687061642f6e2dff2e6d64","bytes":3,"stored":false,"not_stored":"denied"}"#
                .replace("\\u{fffd}", "\u{fffd}")
        );
        assert_eq!(e.rel().unwrap(), odd);
    }
}
