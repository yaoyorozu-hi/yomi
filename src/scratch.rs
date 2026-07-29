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

/// Marker on a store key that had to be encoded. Chosen so the two key forms
/// occupy disjoint namespaces — see [`store_key`].
const HEX_KEY_PREFIX: &str = "_hex--";

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
/// The two forms cannot be confused. The hex form always begins `_hex--`, and a
/// plain form that would begin the same way is pushed into the hex branch, so
/// their output spaces are disjoint. Hex carries no `-`, so the `--` inside the
/// encoded form is an unambiguous separator even though the one in the plain
/// form is not (a real slug contains `--`, which is why nothing parses a key —
/// it only has to be unique).
///
/// The result is ASCII in the encoded case and a pair of existing directory
/// names in the plain case, so it is a legal filename either way: no `/`, no
/// NUL, never `.` or `..`.
pub fn store_key(slug: &OsStr, uuid: &OsStr) -> String {
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
        }
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
    #[serde(default)]
    pub captured_at: String,
    #[serde(default)]
    pub total_bytes: u64,
    #[serde(default)]
    pub over_total_cap: bool,
    pub entries: Vec<ScratchEntry>,
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
        for e in dir.flatten() {
            let key = e.file_name().to_string_lossy().into_owned();
            // A full key names itself; a uuid names the one store carrying it.
            // `store_key_matches_session` is the shared resolver — a suffix test
            // cannot address a hex key, and this must not be reimplemented here.
            if OsStr::new(&key) == selector || store_key_matches_session(&key, selector) {
                matched.push(key);
            }
        }
        matched.sort();
        matched.dedup();
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
/// [`Violation`]: ScratchClass::Violation
/// [`RefusedKey`]: ScratchClass::RefusedKey
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScratchClass {
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

impl ScratchClass {
    /// Whether a finding of this class makes the run exit non-zero.
    pub fn fails_the_run(self) -> bool {
        matches!(self, ScratchClass::Violation | ScratchClass::RefusedKey)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ScratchClass::Violation => "violation",
            ScratchClass::Unverifiable => "unverifiable",
            ScratchClass::ForeignMatter => "foreign matter",
            ScratchClass::RefusedKey => "refused key",
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
}

impl ScratchIssue {
    pub fn class(self) -> ScratchClass {
        match self {
            ScratchIssue::ForeignStoreDir
            | ScratchIssue::UnreadableStoreRoot
            | ScratchIssue::StoreKeyCollision
            | ScratchIssue::UnreconcilableKey => ScratchClass::RefusedKey,
            ScratchIssue::NoManifest
            | ScratchIssue::UnreadableManifest
            | ScratchIssue::MissingArtifact
            | ScratchIssue::UnclaimedArtifact
            | ScratchIssue::OrphanArtifact
            | ScratchIssue::ContentMismatch => ScratchClass::Violation,
            ScratchIssue::NoContentHash | ScratchIssue::UndecodableEntry => {
                ScratchClass::Unverifiable
            }
            ScratchIssue::ForeignArtifact => ScratchClass::ForeignMatter,
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
    pub fn requires_exclusion(self) -> bool {
        matches!(
            self,
            ScratchIssue::NoManifest
                | ScratchIssue::MissingArtifact
                | ScratchIssue::UnclaimedArtifact
                | ScratchIssue::OrphanArtifact
                | ScratchIssue::ContentMismatch
        )
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
    pub class: ScratchClass,
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
        }
    }

    fn push(&mut self, key: &str, rel: &str, issue: ScratchIssue) {
        let class = if !self.exclusive && issue.requires_exclusion() {
            ScratchClass::Unverifiable
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
            ScratchClass::Violation => self.violations.push(f),
            ScratchClass::Unverifiable => self.unverifiable.push(f),
            ScratchClass::ForeignMatter => self.foreign_matter.push(f),
            ScratchClass::RefusedKey => self.refused.push(f),
        }
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
        // A store that has never archived scratch is not a defect (W1/R8).
        StoreDir::Absent => return report,
        StoreDir::Foreign => {
            report.push(SCRATCH_ROOT, "", ScratchIssue::ForeignStoreDir);
            return report;
        }
        StoreDir::Own => {}
    }
    let Ok(dir) = std::fs::read_dir(&root) else {
        report.push(SCRATCH_ROOT, "", ScratchIssue::UnreadableStoreRoot);
        return report;
    };

    let mut keys: Vec<(String, PathBuf)> = Vec::new();
    for e in dir.flatten() {
        let key = e.file_name().to_string_lossy().into_owned();
        // A uuid selects the one store dir carrying it; keys are unique per
        // session, so at most one matches.
        if session.is_some_and(|u| !store_key_matches_session(&key, u)) {
            continue;
        }
        keys.push((key, e.path()));
    }
    keys.sort();

    for (key, store_dir) in keys {
        report.keys += 1;
        verify_one_store(&mut report, &key, &store_dir);
    }
    report
}

fn verify_one_store(report: &mut ScratchVerifyReport, key: &str, store_dir: &Path) {
    // A store path that is not a directory yomi owns may point anywhere, and
    // every fact drawn through it is foreign. The fourth caller of the one
    // predicate the writer, the reconciler and the GC gate already share.
    if classify_store_dir(store_dir) != StoreDir::Own {
        report.push(key, "", ScratchIssue::ForeignStoreDir);
        return;
    }
    let mf = match read_manifest_at(&store_dir.join("manifest.json")) {
        ManifestRead::Ok(mf) => mf,
        ManifestRead::Missing => {
            report.push(key, "", ScratchIssue::NoManifest);
            return;
        }
        ManifestRead::Unreadable => {
            report.push(key, "", ScratchIssue::UnreadableManifest);
            return;
        }
    };

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
    for entry in &mf.entries {
        let Some(rel) = entry.rel() else {
            undecodable = true;
            report.push(key, &entry.path, ScratchIssue::UndecodableEntry);
            continue;
        };
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
        ];
        for i in comparative {
            assert!(i.requires_exclusion(), "{} must downgrade", i.as_str());
            assert_eq!(i.class(), ScratchClass::Violation);
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
        assert_eq!(r.unverifiable[0].class, ScratchClass::Unverifiable);
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
        let keys = [
            store_key(OsStr::new("-home-test"), OsStr::new("uuid-1")),
            store_key(&os(b"slug-\xff"), &os(b"sess-\xfe")),
            store_key(OsStr::new("_hex--a"), OsStr::new("b")),
        ];
        for k in keys {
            assert!(!k.is_empty());
            assert!(!k.contains('/'), "{k} would create a nested path");
            assert!(!k.contains('\0'), "{k} carries an interior NUL");
            assert_ne!(k, ".");
            assert_ne!(k, "..");
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
