//! Where an unredacted original lives, and the one derivation every writer uses.
//!
//! **Quarantine mirrors the archive**: `quarantine/<X>` holds the unredacted
//! original of `archive/<X>.zst`. The path is the artifact's archive-relative
//! stored path with the compression suffix removed, and nothing else.
//!
//! An original is named by the identity of the artifact it is the original *of*,
//! so it inherits the store's uniqueness and its losslessness instead of
//! restating them. Before this rule three call sites each built a path their own
//! way: a scratch original was keyed by the lossy display name (two non-UTF-8
//! names collided at `U+FFFD` and one original overwrote the other — in the one
//! place the lost object has no other copy), the scratch key appeared twice, and
//! archive and rescan disagreed about how much of the path the `<uuid>` level
//! had already consumed.

use crate::scratch::FindingClass;
use anyhow::{Context, Result};
use rustix::fs::{Mode, OFlags};
use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

/// Every directory yomi creates under `quarantine/`, and every original in it.
const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

/// The quarantine-relative path of the artifact stored at `stored_rel`, which is
/// that artifact's path relative to `archive/`.
///
/// Injective by construction, which is the whole point. A *compressed*
/// artifact's store path is its logical path with exactly one `.zst` appended,
/// so removing that suffix is the inverse of the map that added it; the only
/// *uncompressed* artifacts are subagent metas, whose names end `.meta.json` and
/// are therefore disjoint from the stripped set. Two originals can no longer
/// land on one path.
pub fn quarantine_rel(stored_rel: &Path) -> PathBuf {
    sanitize_rel(&strip_zst(stored_rel))
}

/// Drop one trailing `.zst`, on the raw bytes of the final component so a
/// non-UTF-8 name survives intact.
fn strip_zst(path: &Path) -> PathBuf {
    let Some(name) = path.file_name() else {
        return path.to_path_buf();
    };
    match name.as_bytes().strip_suffix(b".zst") {
        Some(stem) => path.with_file_name(OsStr::from_bytes(stem)),
        None => path.to_path_buf(),
    }
}

/// Keep only ordinary components, so a path can never escape the quarantine
/// root. Takes a `Path`, not a `&str`: a scratch store path is derived from raw
/// `ScratchRel` bytes, and a `&str` here is exactly where those bytes were lost.
fn sanitize_rel(rel: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in rel.components() {
        if let Component::Normal(c) = comp {
            out.push(c);
        }
    }
    if out.as_os_str().is_empty() {
        out.push("original");
    }
    out
}

/// Write an unredacted secret-bearing original to its mirrored path under
/// `quarantine_root` (every directory 700, the file 600), index-excluded and
/// recoverable.
///
/// `stored_rel` is the artifact's archive-relative stored path.
///
/// **The hierarchy is descended fd by fd, never by path.** Each level is
/// `mkdirat`-ed, opened `O_DIRECTORY|O_NOFOLLOW` from its parent's fd, and
/// `fchmod`-ed through that fd; the original is opened `O_CREAT|O_NOFOLLOW` and
/// `fchmod`-ed the same way. `create_dir_all` and `set_permissions` both follow
/// symlinks, so building the tree by path let anything planted at a mirrored
/// level redirect **the raw secret itself** — and re-mode the link's target on
/// the way. The store has `classify_store_dir` for that class; quarantine had
/// nothing, and the object at stake here is the one copy of an unredacted
/// original. Descending from fds refuses instead, with no window between the
/// check and the use because there is no check: the kernel resolves one
/// component at a time and never traverses a link.
///
/// Any error means the original was **not** preserved. Every caller treats that
/// as a refusal to archive the artifact at all — see `Archiver::capture` and
/// `rescan::commit`.
pub fn quarantine_original(
    quarantine_root: &Path,
    stored_rel: &Path,
    original: &[u8],
) -> Result<PathBuf> {
    let rel = quarantine_rel(stored_rel);
    let dest = quarantine_root.join(&rel);

    // The root is created and opened **by path**, following whatever it is:
    // `quarantine/` is a documented part of the layout an operator may
    // legitimately relocate — an encrypted volume being the obvious case, since
    // decision #6 leaves at-rest encryption to P6 — and `ensure_layout` already
    // creates and chmods it through the same path. Everything below it is a
    // namespace yomi derives from the artifact's own identity, which no operator
    // has a reason to hand-place, so that is where following stops.
    std::fs::create_dir_all(quarantine_root)
        .with_context(|| format!("create quarantine dir {}", quarantine_root.display()))?;
    set_700(quarantine_root)?;
    let mut dir = open_root(quarantine_root)?;

    let mut walked = quarantine_root.to_path_buf();
    for comp in rel.parent().unwrap_or(Path::new("")).components() {
        walked.push(comp);
        dir = open_level(&dir, comp.as_os_str(), &walked)?;
    }

    let name = rel
        .file_name()
        .context("quarantine path has no final component")?;
    write_original(&dir, name, original, &dest)?;
    Ok(dest)
}

fn set_700(dir: &Path) -> Result<()> {
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(DIR_MODE))
        .with_context(|| format!("chmod {DIR_MODE:o} {}", dir.display()))
}

fn open_root(path: &Path) -> Result<File> {
    let flags = OFlags::DIRECTORY | OFlags::CLOEXEC;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits() as i32)
        .open(path)
        .with_context(|| format!("open quarantine dir {}", path.display()))
}

/// Create (if absent) and open one mirrored level under `parent`, refusing
/// anything that is not a real directory reached without traversing a link.
fn open_level(parent: &File, name: &OsStr, display: &Path) -> Result<File> {
    // `mkdirat`'s mode is masked by the umask, so the `fchmod` below is what
    // actually establishes 700 — `Archiver` is a library type a caller can use
    // without `ensure_layout` ever having tightened the umask, and inherited
    // modes are not something to rely on for a tree of raw secrets.
    if let Err(e) = rustix::fs::mkdirat(parent, name, Mode::from_bits_truncate(DIR_MODE))
        && e != rustix::io::Errno::EXIST
    {
        return Err(anyhow::Error::new(e))
            .with_context(|| format!("create quarantine dir {}", display.display()));
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let dir: File = rustix::fs::openat(parent, name, flags, Mode::empty())
        .map_err(|e| {
            anyhow::anyhow!(
                "refusing to write an unredacted original through {}: {e} — that level \
                 could not be opened as a directory without following a link",
                display.display()
            )
        })?
        .into();
    rustix::fs::fchmod(&dir, Mode::from_bits_truncate(DIR_MODE))
        .with_context(|| format!("chmod {DIR_MODE:o} {}", display.display()))?;
    Ok(dir)
}

fn write_original(dir: &File, name: &OsStr, original: &[u8], display: &Path) -> Result<()> {
    let flags =
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut file: File = rustix::fs::openat(dir, name, flags, Mode::from_bits_truncate(FILE_MODE))
        .map_err(|e| {
            anyhow::anyhow!(
                "refusing to write an unredacted original to {}: {e}",
                display.display()
            )
        })?
        .into();
    // Before the bytes, not after: `O_CREAT`'s mode is masked by the umask, and
    // an already-existing file keeps the mode it had, so a permissive one would
    // otherwise hold a raw secret for the length of the write.
    rustix::fs::fchmod(&file, Mode::from_bits_truncate(FILE_MODE))
        .with_context(|| format!("chmod {FILE_MODE:o} {}", display.display()))?;
    file.write_all(original)
        .with_context(|| format!("write quarantine file {}", display.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Law Q — what is asserted about the quarantine tree, and who may check it
// (design §4, §5).
// ---------------------------------------------------------------------------

/// Permission to open a file that contains a raw secret.
///
/// **Q3 is the only check that opens anything, and this token is why it cannot
/// run by accident.** The store's non-exposure is structural — every reachable
/// byte is post-redaction, so even a bug that echoed content could not leak a
/// secret — while in `quarantine/` the bytes *are* the secret. The routine,
/// unattended, nightly command must therefore keep the property that it never
/// opens a file containing a raw secret, and "remember to check the flag" is not
/// that property.
///
/// The only constructor is [`OpenOriginals::requested`], which takes the flag;
/// the field is private, so no other module can mint one; and the only code in
/// this crate that reads a file under `quarantine/` is a method on this type.
/// Forgetting the flag is a compile error rather than a leak.
pub struct OpenOriginals(());

impl OpenOriginals {
    /// `Some` exactly when `verify --quarantine` was given.
    pub fn requested(flag: bool) -> Option<Self> {
        flag.then_some(OpenOriginals(()))
    }

    /// Q3: does the original at `path` hash to `expected`?
    ///
    /// Hashes and drops, exactly as the store pass does — the finding names a
    /// path and a mismatch and never carries content. An unreadable original
    /// answers `false`, which is the same accusation as a mismatch and the right
    /// one: the recovery copy cannot be shown to be what the ledger says it is.
    fn hashes_to(&self, path: &Path, expected: &str) -> bool {
        std::fs::read(path).is_ok_and(|bytes| crate::util::sha256_hex(&bytes) == expected)
    }
}

/// What the quarantine pass found. One variant per row of the §5 law-Q table,
/// plus the root guard every store path in this design gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineIssue {
    /// **Q0.** Two artifacts derive one quarantine path, so one original has
    /// overwritten another. The check that catches the collision, and it opens
    /// nothing: Q1 cannot catch it, because when two originals collide onto one
    /// path that path exists and existence holds for both while one original is
    /// gone.
    QuarantineCollision,
    /// **Q1.** An artifact recorded `quarantined` has no original at its path.
    QuarantineMissing,
    /// **Q2.** A file at a path a superseded derivation produced. Advisory, and
    /// deliberately also the inventory an operator needs to reconcile the tree by
    /// hand — there is no migration, because a legacy original may be the only
    /// copy that exists.
    QuarantineLegacyLayout,
    /// **Q2.** A file matching no derivation, current or legacy.
    QuarantineStray,
    /// **Q3.** The original does not hash to the artifact's `source_sha256`.
    /// Reachable only under `verify --quarantine`.
    QuarantineMismatch,
    /// **Q3 does not apply**: the ledger records an original but no
    /// `source_sha256` to check it against. Not a defect — a statement about what
    /// the ledger can prove, the same shape S2's `NoContentHash` has, and said
    /// rather than swallowed because that is the whole point of having three
    /// vocabularies. A silent skip is exactly the behaviour they exist to
    /// prevent.
    ///
    /// It is a real population, not a defensive branch. `upsert_artifact` writes
    /// `quarantined = excluded.quarantined`, so a re-archive that finds no secret
    /// clears the flag while the original stays — and the reverse pairing, a flag
    /// without a hash, arrives by the same routes that produce `UndecodableEntry`
    /// and `DuplicateIdentity`: a hand-edited or corrupted ledger, which this
    /// design chooses to report rather than assume away. Salvage carries
    /// `quarantined` and `source_sha256` together today; nothing guarantees a
    /// later shape will.
    ///
    /// Emitted **only** under `verify --quarantine`. Without the flag nothing is
    /// checked, so there is nothing to be unable to prove, and reporting it would
    /// be noise about a check that was never asked for.
    QuarantineNoSourceHash,
    /// The quarantine root is not a directory this run owns, so nothing under it
    /// may be stat'd or enumerated: every fact drawn through it would be drawn
    /// from another tree. The same rule §5 applies to the scratch store root,
    /// which `read_dir` and `stat` both follow a symlink into.
    QuarantineForeignRoot,
}

impl QuarantineIssue {
    pub fn class(self) -> FindingClass {
        match self {
            QuarantineIssue::QuarantineCollision
            | QuarantineIssue::QuarantineMissing
            | QuarantineIssue::QuarantineMismatch => FindingClass::Violation,
            QuarantineIssue::QuarantineLegacyLayout | QuarantineIssue::QuarantineStray => {
                FindingClass::ForeignMatter
            }
            QuarantineIssue::QuarantineNoSourceHash => FindingClass::Unverifiable,
            QuarantineIssue::QuarantineForeignRoot => FindingClass::RefusedKey,
        }
    }

    /// Whether this finding compares the ledger against the tree, and so cannot
    /// stand unless the two were a consistent snapshot. Exhaustive for the same
    /// reason the scratch predicate is: a new check must declare itself or fail
    /// to compile.
    ///
    /// Q1 stands, and the write order is why: every writer quarantines the
    /// original *before* the store write and the ledger update, so a concurrent
    /// archive can transiently produce a file the ledger does not yet claim — the
    /// Q2 direction — but never a claim whose file is missing. Nothing ever
    /// removes a file from `quarantine/`, which closes the other direction.
    pub fn requires_exclusion(self) -> bool {
        match self {
            // A stray is what a half-written archive looks like: the original
            // has landed and the row that claims it has not.
            QuarantineIssue::QuarantineStray => true,
            // Re-quarantining an artifact whose source changed truncates and
            // rewrites the original in place, so mid-run the file on disk and
            // the ledger's `source_sha256` legitimately disagree.
            QuarantineIssue::QuarantineMismatch => true,
            // Q0 is ledger-only. Q1 cannot be transiently violated (above). A
            // legacy-layout path is one no current writer produces at all, and
            // an absent `source_sha256` is a property of one ledger row that no
            // concurrent write can conjure.
            QuarantineIssue::QuarantineCollision
            | QuarantineIssue::QuarantineMissing
            | QuarantineIssue::QuarantineLegacyLayout
            | QuarantineIssue::QuarantineNoSourceHash
            | QuarantineIssue::QuarantineForeignRoot => false,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            QuarantineIssue::QuarantineCollision => "QuarantineCollision",
            QuarantineIssue::QuarantineMissing => "QuarantineMissing",
            QuarantineIssue::QuarantineLegacyLayout => "QuarantineLegacyLayout",
            QuarantineIssue::QuarantineStray => "QuarantineStray",
            QuarantineIssue::QuarantineMismatch => "QuarantineMismatch",
            QuarantineIssue::QuarantineNoSourceHash => "QuarantineNoSourceHash",
            QuarantineIssue::QuarantineForeignRoot => "QuarantineForeignRoot",
        }
    }
}

/// One finding, naming the artifact (or the file) it concerns. **Never the
/// bytes**: Q3 hashes and drops, and every other check opens nothing at all.
#[derive(Debug, Clone)]
pub struct QuarantineFinding {
    /// The artifact this concerns — a session artifact's `<uuid> [<role>]`, or a
    /// scratch key. Empty for a file no artifact owns.
    pub owner: String,
    /// Quarantine-relative path, lossy, for display only.
    pub rel: String,
    pub issue: QuarantineIssue,
    pub class: FindingClass,
}

/// One artifact's standing under law Q: where its original belongs, and what the
/// ledger says about it.
///
/// `quarantined` means **an original exists for this entry's stored artifact** —
/// not "this run wrote one". Salvage carries the flag forward with the capture it
/// salvages, precisely because the flag describes the `.zst` that is still there
/// and the original that still backs it.
#[derive(Debug, Clone)]
pub struct QuarantineClaim {
    pub owner: String,
    /// The artifact's archive-relative stored path — the thing the mirror rule is
    /// stated over.
    pub stored_rel: PathBuf,
    pub quarantined: bool,
    /// The sha of the bytes handed to quarantine, for Q3. Absent for an entry
    /// that records none (the pre-D2/R1 scratch population).
    pub source_sha256: Option<String>,
}

/// The quarantine pass's result, partitioned by class so a caller cannot
/// accidentally fail the run on foreign matter.
#[derive(Debug)]
pub struct QuarantineReport {
    pub exclusive: bool,
    /// Artifacts the ledger records as having an original.
    pub claims: u64,
    /// Of those, ones whose original is present at the path the mirror rule
    /// derives (Q1 satisfied).
    pub present: u64,
    /// Of those, ones whose original was found only at a path a superseded
    /// derivation produced. Not a defect — there is no migration, by design —
    /// and the count is the size of the by-hand reconciliation an operator has
    /// left to do.
    pub legacy: u64,
    /// Originals that hashed to their artifact's `source_sha256` (Q3). Always 0
    /// without `--quarantine`, because nothing was opened.
    pub verified: u64,
    /// Whether Q3 ran — i.e. whether any original was opened at all.
    pub opened_originals: bool,
    /// Whether the Q2 sweep ran, and why not when it did not.
    pub swept: bool,
    pub sweep_skipped: Option<SweepSkip>,
    /// Files seen by the Q2 sweep.
    pub files: u64,
    /// Files the sweep declined to judge because the ledger covering them was
    /// refused (a foreign store dir, an unreadable manifest). Not accusing them
    /// is the same rule that stops the orphan sweep on an unreconcilable key.
    pub unexamined: u64,
    pub violations: Vec<QuarantineFinding>,
    pub unverifiable: Vec<QuarantineFinding>,
    pub foreign_matter: Vec<QuarantineFinding>,
    pub refused: Vec<QuarantineFinding>,
}

impl QuarantineReport {
    fn new(exclusive: bool) -> Self {
        QuarantineReport {
            exclusive,
            claims: 0,
            present: 0,
            legacy: 0,
            verified: 0,
            opened_originals: false,
            swept: false,
            sweep_skipped: None,
            files: 0,
            unexamined: 0,
            violations: Vec::new(),
            unverifiable: Vec::new(),
            foreign_matter: Vec::new(),
            refused: Vec::new(),
        }
    }

    fn push(&mut self, owner: &str, rel: &str, issue: QuarantineIssue) {
        let class = if !self.exclusive && issue.requires_exclusion() {
            FindingClass::Unverifiable
        } else {
            issue.class()
        };
        let f = QuarantineFinding {
            owner: owner.to_string(),
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

    /// Q3, and the only place in the pass that can lead to a file being opened.
    /// A no-op without the token, which only `--quarantine` can mint.
    ///
    /// The two ways Q3 can fail to attest are kept apart, which is the same
    /// distinction S2 draws between `ContentMismatch` and `NoContentHash`: the
    /// original disagreeing with the ledger is a defect, and the ledger having
    /// nothing to disagree with is a statement about what it can prove. Neither
    /// may be silence.
    fn check_q3(
        &mut self,
        open: Option<&OpenOriginals>,
        claim: &QuarantineClaim,
        path: &Path,
        rel: &Path,
    ) {
        // Nothing was asked, so there is nothing to be unable to prove.
        let Some(open) = open else {
            return;
        };
        // An **empty** hash is an absent one. A legacy or hand-edited row can
        // carry `""`, and comparing against it can only ever fail — which would
        // accuse the store of a mismatch on the strength of a ledger that says
        // nothing, the exact inversion this vocabulary exists to prevent. S2
        // already draws the line here: `verify_stored` treats an empty
        // `content_sha256` as a legacy degradation rather than a defect.
        let Some(expected) = claim.source_sha256.as_deref().filter(|s| !s.is_empty()) else {
            self.push(
                &claim.owner,
                &rel.to_string_lossy(),
                QuarantineIssue::QuarantineNoSourceHash,
            );
            return;
        };
        if open.hashes_to(path, expected) {
            self.verified += 1;
        } else {
            self.push(
                &claim.owner,
                &rel.to_string_lossy(),
                QuarantineIssue::QuarantineMismatch,
            );
        }
    }

    /// Exit 2 on any violation and on any refusal. Foreign matter and
    /// unverifiable are reported and do not by themselves fail the run — a store
    /// with years of legacy originals is not broken, and a `verify` that fails on
    /// it every night is a `verify` that gets ignored.
    pub fn failed(&self) -> bool {
        !self.violations.is_empty() || !self.refused.is_empty()
    }
}

/// Whether Q2's sweep runs, and — when it does not — why.
///
/// "Not asked" and "asked and clean" are not the same answer, and neither is
/// "asked, but nothing here can say what is claimed". Each of the two refusals
/// below is a statement about the ledger rather than about the tree.
pub enum Sweep<'a> {
    Run(SweepScope<'a>),
    Skipped(SweepSkip),
}

/// Why the sweep did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepSkip {
    /// A session selector narrows the ledger, and "every file under
    /// `quarantine/` is claimed" is a statement about the whole tree — every
    /// other session's originals would read as strays.
    SessionScoped,
    /// The catalog is gone beside a store that is not. Session artifacts have no
    /// ledger at all here, so **every** original of theirs would read as a stray:
    /// an accusation drawn from the absence of the very record that would answer
    /// it. Withheld, and said, rather than reported as a clean tree.
    CatalogMissing,
}

impl SweepSkip {
    pub fn as_str(self) -> &'static str {
        match self {
            SweepSkip::SessionScoped => "session_scoped",
            SweepSkip::CatalogMissing => "catalog_missing",
        }
    }

    pub fn note(self) -> &'static str {
        match self {
            SweepSkip::SessionScoped => {
                "strays not swept: a session selector narrows the ledger, and \"every \
                 file under quarantine/ is claimed\" is a statement about the whole tree."
            }
            SweepSkip::CatalogMissing => {
                "strays not swept: state/catalog.db is missing beside a store that is \
                 not, so there is no ledger for the session artifacts whose originals \
                 sit here. Restore the catalog, or re-archive, before reading this \
                 tree's strays."
            }
        }
    }
}

/// How the sweep is scoped.
pub struct SweepScope<'a> {
    /// Subtrees whose ledger this run refused to read, quarantine-relative.
    /// Nothing under them is judged: an unreadable record is a reason to refuse,
    /// not a licence to accuse what it describes.
    pub unexamined: &'a [PathBuf],
}

/// Check law Q over `quarantine/`.
///
/// **Q0, Q1 and Q2 open nothing** — a ledger computation, a `stat` and a
/// `readdir`. That is the property that lets this run in cron over a tree of raw
/// secrets, and it is not a discipline to be remembered: the only code that opens
/// an original is behind [`OpenOriginals`], which only the `--quarantine` flag can
/// construct.
///
/// `sweep` carries its own refusal when it does not run — see [`SweepSkip`].
pub fn verify_law_q(
    quarantine_root: &Path,
    claims: &[QuarantineClaim],
    sweep: Sweep<'_>,
    exclusive: bool,
    open: Option<&OpenOriginals>,
) -> QuarantineReport {
    let mut report = QuarantineReport::new(exclusive);
    report.opened_originals = open.is_some();

    // Only a *foreign* root stops the pass. An **absent** one does not: a fresh
    // store has no claims either, so it reports nothing and creates nothing
    // (W1/R8) — but a store whose quarantine tree has been deleted out from
    // under a ledger that claims originals must not pass silently, and that is
    // exactly what an early return on `Absent` would do. Q0 needs no tree at
    // all, and Q1's stats are true statements about an empty one.
    if crate::scratch::classify_store_dir(quarantine_root) == crate::scratch::StoreDir::Foreign {
        report.push("", "", QuarantineIssue::QuarantineForeignRoot);
        return report;
    }

    // Q0 and Q1, over the artifacts whose ledger records an original.
    //
    // Q0's set is the quarantined artifacts alone: a collision destroys an
    // original only when both artifacts wrote one, and reporting a pair where
    // only one did would assert damage that has not happened.
    let mut by_path: std::collections::HashMap<&Path, &QuarantineClaim> =
        std::collections::HashMap::new();
    let mut collided: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut derived: Vec<(PathBuf, &QuarantineClaim)> = Vec::new();
    for claim in claims {
        if !claim.quarantined {
            continue;
        }
        report.claims += 1;
        derived.push((quarantine_rel(&claim.stored_rel), claim));
    }
    derived.sort_by(|a, b| a.0.cmp(&b.0));
    for (rel, claim) in &derived {
        if let Some(first) = by_path.insert(rel, claim) {
            // Once per colliding path, naming both sides across the two
            // findings rather than once per pair — the operator's question is
            // "which path lost an original", and the answer is this path.
            if collided.insert(rel.clone()) {
                report.push(
                    &format!("{} / {}", first.owner, claim.owner),
                    &rel.to_string_lossy(),
                    QuarantineIssue::QuarantineCollision,
                );
            }
        }
    }

    // Q1, over the *distinct* paths: when several claims collide onto one path
    // there is one original to find, and counting it once per claim would make
    // `present` disagree with the tree. Which claim speaks for the path is the
    // first in sorted order; `QuarantineCollision` above is the statement about
    // the rest.
    let mut located: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut asked: std::collections::HashSet<&Path> = std::collections::HashSet::new();
    for (rel, claim) in &derived {
        if !asked.insert(rel.as_path()) {
            continue;
        }
        let path = quarantine_root.join(rel);
        // `symlink_metadata`, never `metadata`: the point is to see the object
        // at the path rather than what it points at. An original is a regular
        // file at every write site, so anything else there is not the original,
        // and saying existence is satisfied would be a false negative on exactly
        // the class law Q exists to catch.
        if is_original(&path) {
            report.present += 1;
            located.insert(rel.clone());
            report.check_q3(open, claim, &path, rel);
            continue;
        }
        // Before accusing: there is **no migration**, deliberately, so every
        // original written before this rule sits at a path the current
        // derivation does not produce. Its artifact's ledger still records it,
        // and the recovery copy is there — reporting `QuarantineMissing` would
        // fail the run nightly on exactly the stores with the most history,
        // which is the outcome §5 refuses when it keeps a legacy population from
        // failing `verify`. It is the same fact Q2 reports for an unowned file,
        // named against the artifact that owns this one: advisory, and the
        // inventory an operator needs to reconcile the tree by hand.
        if let Some(old) = legacy_paths(&claim.stored_rel)
            .into_iter()
            .find(|p| is_original(&quarantine_root.join(p)))
        {
            report.legacy += 1;
            located.insert(old.clone());
            report.check_q3(open, claim, &quarantine_root.join(&old), &old);
            report.push(
                &claim.owner,
                &old.to_string_lossy(),
                QuarantineIssue::QuarantineLegacyLayout,
            );
            continue;
        }
        report.push(
            &claim.owner,
            &rel.to_string_lossy(),
            QuarantineIssue::QuarantineMissing,
        );
    }

    let sweep = match sweep {
        Sweep::Run(scope) => scope,
        Sweep::Skipped(why) => {
            report.sweep_skipped = Some(why);
            return report;
        }
    };
    report.swept = true;

    // Q2's claimed set is **every** artifact's mirror path, not only the
    // quarantined ones. The mirror rule says `quarantine/<X>` belongs to
    // `archive/<X>.zst`, so a file there is claimed by that artifact whether or
    // not the current ledger records an original — which is exactly the case of
    // an artifact quarantined by an earlier run and found clean by a later one.
    // Its original is still the only copy of what that source once held, nothing
    // removes it by design, and calling it a stray would report the design's own
    // behaviour as foreign matter, in the store with the most history first.
    let mut claimed: std::collections::HashSet<PathBuf> = claims
        .iter()
        .map(|c| quarantine_rel(&c.stored_rel))
        .collect();
    // An original Q1 already located at a legacy path is accounted for by its
    // artifact, so the sweep must not name it a second time: one object, one
    // finding — the rule §5 states for an artifact a `stored: false` entry
    // explains, applied here.
    claimed.extend(located);
    let legacy = LegacyRoots::from_claims(claims);

    // `WalkDir` does not follow symlinks, so the sweep cannot leave the tree,
    // and it opens nothing: `readdir` plus the entry's own file type.
    for e in walkdir::WalkDir::new(quarantine_root)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        if !e.file_type().is_file() && !e.file_type().is_symlink() {
            continue;
        }
        let Ok(rel) = e.path().strip_prefix(quarantine_root) else {
            continue;
        };
        report.files += 1;
        if sweep.unexamined.iter().any(|p| rel.starts_with(p)) {
            report.unexamined += 1;
            continue;
        }
        if claimed.contains(rel) {
            continue;
        }
        let issue = if legacy.matches(rel) {
            QuarantineIssue::QuarantineLegacyLayout
        } else {
            QuarantineIssue::QuarantineStray
        };
        report.push("", &rel.to_string_lossy(), issue);
    }
    report
}

/// Is there an original at this path? `symlink_metadata`, so a symlink is not
/// mistaken for the file it points at.
fn is_original(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|md| md.is_file())
}

/// Every quarantine path a **superseded** derivation would have produced for the
/// artifact stored at `stored_rel`, for Q1's fallback.
///
/// The old rule was `quarantine/<uuid-field>/<sanitized rel-field>`, and the
/// three writers disagreed about what those two fields held — which is the
/// divergence the mirror rule ended:
///
/// | Artifact | Superseded path |
/// |---|---|
/// | session, written by `archive` | `<uuid>/<session-relative rel>` |
/// | session, written by `rescan` | `<uuid>/<slug>/<uuid>/<rel>` — it spent the level twice |
/// | single-file store | `<category>/<category>/<name>` — likewise doubled |
/// | scratch | `_scratch--<K>/<K>/<lossy rel>` — the key doubled, the name lossy |
///
/// The scratch form is built through `to_string_lossy` deliberately: that is the
/// value the old writer used, `U+FFFD` and all, and reproducing it is the only
/// way to find what it wrote. This derives paths to `stat`; it never opens one,
/// and it is not the reader §4 leaves to its own design — nothing here can emit
/// an original.
fn legacy_paths(stored_rel: &Path) -> Vec<PathBuf> {
    let logical = quarantine_rel(stored_rel);
    let mut comps = logical.components();
    let Some(Component::Normal(first)) = comps.next() else {
        return Vec::new();
    };
    let rest: PathBuf = comps.collect();

    if first.as_bytes() == crate::scratch::SCRATCH_ROOT.as_bytes() {
        let mut inner = rest.components();
        let Some(Component::Normal(k)) = inner.next() else {
            return Vec::new();
        };
        let tail: PathBuf = inner.collect();
        let mut old = PathBuf::from(format!("_scratch--{}", k.to_string_lossy()));
        old.push(k);
        old.push(tail.to_string_lossy().as_ref());
        return vec![old];
    }
    if first.as_bytes().starts_with(b"_") {
        // A single-file store: the category stood in for the session uuid, and
        // the rel it was given was the whole archive-relative path.
        return vec![Path::new(first).join(&logical)];
    }
    // A session artifact: `<slug>/<uuid>/<rest>`.
    let mut inner = rest.components();
    let Some(Component::Normal(uuid)) = inner.next() else {
        return Vec::new();
    };
    let session_rel: PathBuf = inner.collect();
    vec![
        Path::new(uuid).join(&session_rel),
        Path::new(uuid).join(&logical),
    ]
}

/// Which first components a superseded derivation could have produced.
///
/// Both legacy layouts put something at the first level that the mirror rule
/// never does: the old session layout keyed by `<session-uuid>`, the old scratch
/// layout by `_scratch--<K>`. The uuids come from the claims themselves — a
/// session artifact's stored path is `<slug>/<uuid>/…`, so its second component
/// is exactly what the old first level held — so this needs no ledger the pass
/// does not already have, and it is exact for every session yomi knows about.
///
/// The single-file stores took a third shape: the category was passed where the
/// uuid went, giving `<cat>/<cat>/<name>`. That one is recognised by its own
/// doubling, which the mirror rule cannot produce.
struct LegacyRoots {
    uuids: std::collections::HashSet<std::ffi::OsString>,
}

impl LegacyRoots {
    fn from_claims(claims: &[QuarantineClaim]) -> Self {
        let mut uuids = std::collections::HashSet::new();
        for c in claims {
            let mut comps = c.stored_rel.components();
            let (Some(Component::Normal(first)), Some(Component::Normal(second))) =
                (comps.next(), comps.next())
            else {
                continue;
            };
            // Only a session artifact has a uuid at its second level. Every
            // other store is keyed by a category and its first component starts
            // `_` — `_scratch/<K>/…` names a key, the single-file stores name
            // themselves — and taking their second component would enter a
            // *filename* into the set of things a legacy first level could hold.
            // Project slugs are a cwd with `/`→`-`, so they never collide with
            // that test.
            if !first.as_bytes().starts_with(b"_") {
                uuids.insert(second.to_os_string());
            }
        }
        LegacyRoots { uuids }
    }

    fn matches(&self, rel: &Path) -> bool {
        let mut comps = rel.components();
        let Some(Component::Normal(first)) = comps.next() else {
            return false;
        };
        if first.as_bytes().starts_with(b"_scratch--") {
            return true;
        }
        if self.uuids.contains(first) {
            return true;
        }
        // The doubled single-file form: `_history/_history/history.jsonl`.
        matches!(comps.next(), Some(Component::Normal(second)) if second == first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    fn q(stored: &[u8]) -> Vec<u8> {
        quarantine_rel(Path::new(&OsString::from_vec(stored.to_vec())))
            .into_os_string()
            .into_vec()
    }

    /// The mirror rule, for each artifact shape the store holds.
    #[test]
    fn quarantine_path_mirrors_the_store_path() {
        assert_eq!(
            q(b"-home-test/uuid-1/transcript.jsonl.zst"),
            b"-home-test/uuid-1/transcript.jsonl"
        );
        // Uncompressed: subagent metas keep their name verbatim.
        assert_eq!(
            q(b"-home-test/uuid-1/subagents/x.meta.json"),
            b"-home-test/uuid-1/subagents/x.meta.json"
        );
        assert_eq!(
            q(b"_scratch/-home-test--uuid-1/scratchpad/a.md.zst"),
            b"_scratch/-home-test--uuid-1/scratchpad/a.md"
        );
    }

    /// The defect this rule exists to end: two non-UTF-8 names that share a
    /// lossy form must not share a quarantine path. Their store paths differ, so
    /// their quarantine paths do — provided the bytes are carried as a path.
    #[test]
    fn lossy_colliding_names_keep_distinct_quarantine_paths() {
        let a = q(b"_scratch/K/scratchpad/note-\xff.md.zst");
        let b = q(b"_scratch/K/scratchpad/note-\xfe.md.zst");
        assert_eq!(a, b"_scratch/K/scratchpad/note-\xff.md");
        assert_ne!(a, b, "two originals landed on one quarantine path");
    }

    /// Stripping the suffix must not merge a compressed artifact onto an
    /// uncompressed one: only `.zst` is removed, and only once.
    #[test]
    fn only_one_zst_suffix_is_removed() {
        assert_eq!(q(b"a/b.zst.zst"), b"a/b.zst");
        assert_eq!(q(b"a/b.json"), b"a/b.json");
        assert_eq!(q(b"a/b.zstx"), b"a/b.zstx");
        assert_eq!(q(b"a/zst"), b"a/zst");
    }

    /// Nothing a manifest could carry may escape the root.
    #[test]
    fn traversal_components_are_dropped() {
        assert_eq!(q(b"../../etc/passwd"), b"etc/passwd");
        assert_eq!(q(b"/etc/passwd"), b"etc/passwd");
        assert_eq!(q(b"a/../../b.zst"), b"a/b");
        assert_eq!(q(b".."), b"original");
        assert_eq!(q(b""), b"original");
    }

    // -- law Q ------------------------------------------------------------

    fn claim(owner: &str, stored: &str, quarantined: bool) -> QuarantineClaim {
        QuarantineClaim {
            owner: owner.into(),
            stored_rel: PathBuf::from(stored),
            quarantined,
            source_sha256: None,
        }
    }

    fn issues(v: &[QuarantineFinding]) -> Vec<(&str, &str)> {
        v.iter()
            .map(|f| (f.issue.as_str(), f.rel.as_str()))
            .collect()
    }

    /// Q0 is a computation over the ledger and opens nothing — so it reports on
    /// a root that does not exist at all, which is also the cheapest proof that
    /// it never stats anything.
    #[test]
    fn q0_finds_a_collision_without_touching_the_tree() {
        let root = Path::new("/nonexistent-quarantine-root-for-q0");
        // Two entries whose identities collapsed to one — the shape a manifest
        // written before `path_hex` produces for two non-UTF-8 names.
        let claims = [
            claim("k", "_scratch/K/scratchpad/note.md.zst", true),
            claim("k", "_scratch/K/scratchpad/note.md.zst", true),
        ];
        let r = verify_law_q(
            root,
            &claims,
            Sweep::Skipped(SweepSkip::SessionScoped),
            true,
            None,
        );
        assert_eq!(
            issues(&r.violations)
                .iter()
                .filter(|(i, _)| *i == "QuarantineCollision")
                .count(),
            1,
            "expected exactly one collision finding: {:?}",
            issues(&r.violations)
        );
        assert!(r.failed(), "a lost original did not fail the run");
        assert_eq!(r.claims, 2);
    }

    /// A collision needs two *originals*: one artifact recording none cannot
    /// have overwritten anything, and saying so would assert damage that has
    /// not happened.
    #[test]
    fn q0_ignores_a_shared_path_when_only_one_side_wrote_an_original() {
        let claims = [
            claim("a", "_scratch/K/scratchpad/note.md.zst", true),
            claim("b", "_scratch/K/scratchpad/note.md.zst", false),
        ];
        let r = verify_law_q(
            Path::new("/nonexistent"),
            &claims,
            Sweep::Skipped(SweepSkip::SessionScoped),
            true,
            None,
        );
        assert!(
            issues(&r.violations)
                .iter()
                .all(|(i, _)| *i != "QuarantineCollision")
        );
    }

    /// Q1 accuses only when the original is at neither the current path nor any
    /// superseded one, and its accusation names the artifact.
    #[test]
    fn q1_reports_a_missing_original() {
        let claims = [claim(
            "s [transcript]",
            "-home-t/u1/transcript.jsonl.zst",
            true,
        )];
        let r = verify_law_q(
            Path::new("/nonexistent"),
            &claims,
            Sweep::Skipped(SweepSkip::SessionScoped),
            true,
            None,
        );
        assert_eq!(
            issues(&r.violations),
            vec![("QuarantineMissing", "-home-t/u1/transcript.jsonl")]
        );
        assert_eq!(r.present, 0);
    }

    /// The three superseded shapes, each reproduced exactly as its writer built
    /// it — this is what Q1 stats before it accuses, and what keeps a store with
    /// pre-mirror originals from failing every night.
    #[test]
    fn legacy_paths_reproduce_every_superseded_derivation() {
        let p = |s: &str| -> Vec<String> {
            legacy_paths(Path::new(s))
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect()
        };
        // A session artifact: archive spent the level once, rescan twice.
        assert_eq!(
            p("-home-t/u1/transcript.jsonl.zst"),
            vec![
                "u1/transcript.jsonl".to_string(),
                "u1/-home-t/u1/transcript.jsonl".to_string(),
            ]
        );
        assert_eq!(
            p("-home-t/u1/subagents/x.meta.json"),
            vec![
                "u1/subagents/x.meta.json".to_string(),
                "u1/-home-t/u1/subagents/x.meta.json".to_string(),
            ]
        );
        // A single-file store doubled its category.
        assert_eq!(
            p("_history/history.jsonl.zst"),
            vec!["_history/_history/history.jsonl".to_string()]
        );
        assert_eq!(
            p("_mcp/srv/log.jsonl.zst"),
            vec!["_mcp/_mcp/srv/log.jsonl".to_string()]
        );
        // Scratch doubled its key and lost the name to `to_string_lossy`.
        assert_eq!(
            p("_scratch/-home-t--u1/scratchpad/a.md.zst"),
            vec![
                "_scratch--<K>/<K>/scratchpad/a.md"
                    .replace("<K>", "-home-t--u1")
                    .to_string()
            ]
        );
    }

    /// Q2 must not bury the signal: a file at a superseded path is advisory and
    /// doubles as the inventory for a by-hand reconciliation, while one matching
    /// no derivation at all is a stray. Neither fails the run.
    #[test]
    fn q2_separates_legacy_layouts_from_true_strays() {
        let claims = [claim(
            "s [transcript]",
            "-home-t/u1/transcript.jsonl.zst",
            true,
        )];
        let legacy = LegacyRoots::from_claims(&claims);
        assert!(legacy.matches(Path::new("u1/transcript.jsonl")));
        assert!(legacy.matches(Path::new("u1/-home-t/u1/transcript.jsonl")));
        assert!(legacy.matches(Path::new("_scratch--anything/K/a.md")));
        assert!(legacy.matches(Path::new("_history/_history/history.jsonl")));
        assert!(!legacy.matches(Path::new("-home-t/u1/transcript.jsonl")));
        assert!(!legacy.matches(Path::new("something-else/a.txt")));

        // A single-file store contributes no uuid: its second component is a
        // *filename*, and entering it would make a stray of that name read as a
        // superseded layout.
        let singles = [claim("_history", "_history/history.jsonl.zst", true)];
        assert!(
            !LegacyRoots::from_claims(&singles).matches(Path::new("history.jsonl/anything")),
            "a store filename was admitted as a legacy first level"
        );

        for issue in [
            QuarantineIssue::QuarantineLegacyLayout,
            QuarantineIssue::QuarantineStray,
        ] {
            assert_eq!(issue.class(), FindingClass::ForeignMatter);
            assert!(!issue.class().fails_the_run(), "{}", issue.as_str());
        }
    }

    /// Q3 opens files that hold raw secrets, so it must be impossible to reach
    /// without the flag — not merely conditional on remembering to check one.
    #[test]
    fn q3_cannot_run_without_the_flag() {
        assert!(OpenOriginals::requested(false).is_none());
        assert!(OpenOriginals::requested(true).is_some());

        let claims = [claim(
            "s [transcript]",
            "-home-t/u1/transcript.jsonl.zst",
            true,
        )];
        let r = verify_law_q(
            Path::new("/nonexistent"),
            &claims,
            Sweep::Skipped(SweepSkip::SessionScoped),
            true,
            None,
        );
        assert!(!r.opened_originals);
        assert_eq!(r.verified, 0);
        assert!(
            issues(&r.violations)
                .iter()
                .all(|(i, _)| *i != "QuarantineMismatch"),
            "a Q3 finding was produced with no permission to open anything"
        );
    }

    /// Only the comparative findings move, and only their class moves. The
    /// predicate itself is an exhaustive `match`, so a new issue that fails to
    /// declare itself does not compile.
    #[test]
    fn q_exclusion_downgrades_exactly_the_comparative_findings() {
        use QuarantineIssue::*;
        for i in [QuarantineStray, QuarantineMismatch] {
            assert!(i.requires_exclusion(), "{} must downgrade", i.as_str());
        }
        for i in [
            QuarantineCollision,
            QuarantineMissing,
            QuarantineLegacyLayout,
            QuarantineNoSourceHash,
            QuarantineForeignRoot,
        ] {
            assert!(
                !i.requires_exclusion(),
                "{} must stand without the lock",
                i.as_str()
            );
        }

        // A downgraded finding keeps its issue name and stops being a defect.
        let mut r = QuarantineReport::new(false);
        r.push("a", "x", QuarantineMismatch);
        assert!(r.violations.is_empty());
        assert_eq!(r.unverifiable.len(), 1);
        assert_eq!(r.unverifiable[0].issue.as_str(), "QuarantineMismatch");
        assert!(!r.failed());

        // And a missing original stands in either condition: no writer can
        // transiently produce one, because quarantine precedes the ledger and
        // nothing ever removes a file from the tree.
        let mut r = QuarantineReport::new(false);
        r.push("a", "x", QuarantineMissing);
        assert!(r.failed());
    }

    /// A ledger that records an original but no hash to check it against is
    /// *unverifiable*, and only ever says so when Q3 was asked for: without the
    /// flag nothing is checked, so there is nothing to be unable to prove.
    ///
    /// Reachable in ordinary operation, not merely by corruption — a re-archive
    /// that finds no secret writes `quarantined = excluded.quarantined` and
    /// clears the flag while the original stays — so the silent skip this
    /// replaces was the exact behaviour the three vocabularies exist to prevent.
    #[test]
    fn q3_says_when_the_ledger_gives_it_nothing_to_check() {
        let hashless = QuarantineClaim {
            source_sha256: None,
            ..claim("s [transcript]", "-home-t/u1/transcript.jsonl.zst", true)
        };
        let rel = Path::new("-home-t/u1/transcript.jsonl");

        // No flag: nothing was asked, so nothing is said — and nothing is
        // opened, which is the property the default pass keeps.
        let mut r = QuarantineReport::new(true);
        r.check_q3(None, &hashless, Path::new("/nonexistent"), rel);
        assert!(r.unverifiable.is_empty() && r.violations.is_empty());

        // Under `--quarantine` it is stated, as `unverifiable` — never opening
        // the file, because there is nothing to compare it against.
        let token = OpenOriginals::requested(true).expect("token");
        let mut r = QuarantineReport::new(true);
        r.check_q3(Some(&token), &hashless, Path::new("/nonexistent"), rel);
        assert_eq!(
            issues(&r.unverifiable),
            vec![("QuarantineNoSourceHash", "-home-t/u1/transcript.jsonl")]
        );
        assert_eq!(r.verified, 0);
        assert!(!r.failed(), "an unprovable claim failed the run");
        // The finding names the artifact and the path, and carries nothing else:
        // no byte of the original can reach it, because none was read.
        assert_eq!(r.unverifiable[0].owner, "s [transcript]");
    }

    /// An **empty** `source_sha256` is an absent one, not a hash that everything
    /// fails to match. `artifacts.source_sha256` is `NOT NULL`, so a legacy or
    /// hand-edited row carries `""` rather than nothing — and comparing against
    /// it can only ever fail, turning "the ledger cannot prove this" into an
    /// accusation that the store is corrupt. S2 already settles this direction:
    /// `verify_stored` degrades on an empty `content_sha256` instead of failing.
    #[test]
    fn an_empty_source_hash_is_unverifiable_not_a_mismatch() {
        let blank = QuarantineClaim {
            source_sha256: Some(String::new()),
            ..claim("s [transcript]", "-home-t/u1/transcript.jsonl.zst", true)
        };
        let token = OpenOriginals::requested(true).expect("token");
        let mut r = QuarantineReport::new(true);
        r.check_q3(
            Some(&token),
            &blank,
            Path::new("/nonexistent"),
            Path::new("-home-t/u1/transcript.jsonl"),
        );
        assert!(
            r.violations.is_empty(),
            "an unprovable claim was accused of a mismatch: {:?}",
            issues(&r.violations)
        );
        assert_eq!(
            issues(&r.unverifiable),
            vec![("QuarantineNoSourceHash", "-home-t/u1/transcript.jsonl")]
        );
        assert!(!r.failed());

        // And without the flag it stays silent, like every other Q3 outcome.
        let mut r = QuarantineReport::new(true);
        r.check_q3(
            None,
            &blank,
            Path::new("/nonexistent"),
            Path::new("-home-t/u1/transcript.jsonl"),
        );
        assert!(r.unverifiable.is_empty() && r.violations.is_empty());
    }

    /// The refusal a foreign quarantine root draws. Its exercise against a real
    /// symlinked root belongs in an integration test — these unit tests open
    /// nothing, which is the same property the default pass has.
    #[test]
    fn a_foreign_root_is_a_refusal_that_fails_the_run() {
        assert_eq!(
            QuarantineIssue::QuarantineForeignRoot.class(),
            FindingClass::RefusedKey
        );
        let mut r = QuarantineReport::new(false);
        r.push("", "", QuarantineIssue::QuarantineForeignRoot);
        assert!(
            r.failed(),
            "a refusal stopped failing the run without the lock"
        );
    }
}
