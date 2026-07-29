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
    pub fn new(rel: &ScratchRel, bytes: u64, stored: bool) -> Self {
        let (path, path_hex) = rel.manifest_fields();
        ScratchEntry {
            path,
            path_hex,
            bytes,
            stored,
            source_sha256: None,
            content_sha256: None,
            present: true,
            capture_failed: false,
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
        let mut e = ScratchEntry::new(&rel, 7, true);
        e.source_sha256 = Some("aa".into());
        e.content_sha256 = Some("bb".into());
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"path":"scratchpad/a.md","bytes":7,"stored":true,"source_sha256":"aa","content_sha256":"bb"}"#
        );

        let odd = live("/tmp/s/uuid", b"scratchpad/n-\xff.md").unwrap();
        let e = ScratchEntry::new(&odd, 3, false);
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"path":"scratchpad/n-\u{fffd}.md","path_hex":"736372617463687061642f6e2dff2e6d64","bytes":3,"stored":false}"#
                .replace("\\u{fffd}", "\u{fffd}")
        );
        assert_eq!(e.rel().unwrap(), odd);
    }
}
