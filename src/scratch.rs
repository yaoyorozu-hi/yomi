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

/// Read `manifest.json`. `None` for absent, unreadable or unparseable — every
/// one of which means the GC gate cannot prove coverage and must refuse.
pub fn read_manifest(path: &Path) -> Option<ScratchManifest> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
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
