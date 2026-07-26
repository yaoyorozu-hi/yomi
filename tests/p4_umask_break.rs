//! P4 break test: `Env::ensure_layout`'s umask, after `libc::umask(0o077)` was
//! replaced by `rustix::process::umask(Mode::RWXG | Mode::RWXO)` in #4.
//!
//! umask is process-global, so this file holds exactly ONE test — a whole test
//! binary to itself — and observes the effect behaviourally (no libc/rustix
//! dev-dependency is added to the crate).

use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use yomi::config::Env;

/// Create a file asking for `req` and return the mode actually granted.
fn granted(path: &Path, req: u32) -> u32 {
    let _f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(req)
        .open(path)
        .unwrap();
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn p4m_ensure_layout_sets_and_never_restores_a_0o077_umask() {
    let base: PathBuf = std::env::temp_dir().join(format!("yomi-p4m-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();

    let inherited = granted(&base.join("before"), 0o666);

    let env = Env::resolve(Some(&base.join("store")), None).unwrap();
    env.ensure_layout(false).unwrap();

    // rustix Mode::RWXG|RWXO must be exactly 0o077, i.e. every group and other
    // bit masked off. A wrong Mode constant here silently widens the store.
    let after = granted(&base.join("after"), 0o666);
    assert_eq!(
        after, 0o600,
        "after ensure_layout a 0666 create was granted {after:o}, not 600 — \
         rustix Mode::RWXG|Mode::RWXO does not equal libc's 0o077"
    );
    let d = base.join("after-dir");
    std::fs::create_dir(&d).unwrap();
    let dmode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o7777;
    assert_eq!(dmode, 0o700, "directory create granted {dmode:o}, not 700");

    // Everything the layout itself created must be owner-only.
    let mut stack = vec![env.home.clone()];
    let mut loose = Vec::new();
    while let Some(p) = stack.pop() {
        let md = std::fs::symlink_metadata(&p).unwrap();
        let m = md.permissions().mode() & 0o7777;
        if m & 0o077 != 0 {
            loose.push(format!("{} = {m:o}", p.display()));
        }
        if md.is_dir() {
            for e in std::fs::read_dir(&p).unwrap().flatten() {
                stack.push(e.path());
            }
        }
    }
    assert!(
        loose.is_empty(),
        "store entries readable beyond owner: {loose:#?}"
    );

    // The umask is never restored: `rustix::process::umask` returns the previous
    // mask and ensure_layout discards it, so a caller that embeds yomi as a
    // library has its process umask permanently rewritten. Documented, not a
    // failure for the CLI — but every later create in this process is affected.
    let still = granted(&base.join("much-later"), 0o666);
    assert_eq!(
        still, 0o600,
        "the umask was restored between calls; if ensure_layout gained a restore \
         path, re-check that nothing is created while the mask is loose"
    );
    if inherited != 0o600 {
        // Confirms the tightening was real and not inherited from the harness.
        assert_ne!(inherited, still);
    }
}
