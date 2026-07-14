//! End-to-end tests against a synthesized fake `~/.claude`. No real Claude Code
//! data, credentials, or transcripts are touched: every fixture — including all
//! secret values — is fabricated in a tmpdir, and YOMI_HOME is isolated per test.

use std::path::{Path, PathBuf};
use std::process::Command;

use yomi::archive::compress::decompress_all;

const BIN: &str = env!("CARGO_BIN_EXE_yomi");

/// A fabricated AWS example key (public docs value, not a live credential).
const FIXTURE_AKIA: &str = "AKIAIOSFODNN7EXAMPLE";
/// Fabricated OAuth-looking token for the credentials-never-opened test.
const FIXTURE_CRED_SECRET: &str = "sk-cred-DEADBEEFdeadbeef0123456789abcdef";

struct Fixture {
    home: PathBuf,
    yomi_home: PathBuf,
    tmp_root: PathBuf,
    cache_home: PathBuf,
    proc_root: PathBuf,
    home_base: PathBuf,
    tmp_base: PathBuf,
    slug: String,
    uuid: String,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "yomi-e2e-{tag}-{}-{}",
            std::process::id(),
            unique()
        ));
        let home = base.join("home");
        let yomi_home = base.join("yomi");
        // Fixture-owned (empty) scratch and cache roots so a run never walks the
        // real /tmp/claude-1007 or ~/.cache (W3).
        let tmp_root = base.join("tmp");
        let cache_home = base.join("cache");
        // Fake /proc for liveness, and fake cross-user bases for discovery.
        let proc_root = base.join("proc");
        let home_base = base.join("homes");
        let tmp_base = base.join("tmpbase");
        let slug = "-home-test".to_string();
        let uuid = "11111111-2222-3333-4444-555555555555".to_string();
        std::fs::create_dir_all(home.join(".claude/projects").join(&slug)).unwrap();
        std::fs::create_dir_all(&tmp_root).unwrap();
        std::fs::create_dir_all(&cache_home).unwrap();
        std::fs::create_dir_all(&proc_root).unwrap();
        std::fs::create_dir_all(&home_base).unwrap();
        std::fs::create_dir_all(&tmp_base).unwrap();
        Fixture {
            home,
            yomi_home,
            tmp_root,
            cache_home,
            proc_root,
            home_base,
            tmp_base,
            slug,
            uuid,
        }
    }

    fn transcript_path(&self) -> PathBuf {
        self.home
            .join(".claude/projects")
            .join(&self.slug)
            .join(format!("{}.jsonl", self.uuid))
    }

    fn companion(&self) -> PathBuf {
        self.home
            .join(".claude/projects")
            .join(&self.slug)
            .join(&self.uuid)
    }

    fn write_transcript(&self, lines: &[String]) {
        let mut body = lines.join("\n");
        body.push('\n');
        std::fs::write(self.transcript_path(), body).unwrap();
    }

    fn append_transcript(&self, lines: &[String]) {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(self.transcript_path())
            .unwrap();
        for l in lines {
            writeln!(f, "{l}").unwrap();
        }
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(BIN)
            .args(args)
            .arg("--home")
            .arg(&self.yomi_home)
            .env("HOME", &self.home)
            .env("YOMI_TMP_ROOT", &self.tmp_root)
            .env("YOMI_CACHE_HOME", &self.cache_home)
            .env("YOMI_PROC_ROOT", &self.proc_root)
            .env("YOMI_HOME_BASE", &self.home_base)
            .env("YOMI_TMP_BASE", &self.tmp_base)
            .env_remove("YOMI_HOME")
            .env_remove("YOMI_CLAUDE_HOME")
            .output()
            .expect("run yomi")
    }

    fn scratch_session_dir(&self, uuid: &str) -> PathBuf {
        self.tmp_root.join(&self.slug).join(uuid)
    }

    /// Seed a scratch file for a given session uuid.
    fn write_scratch_for(&self, uuid: &str, rel: &str, bytes: &[u8]) {
        let dest = self.scratch_session_dir(uuid).join("scratchpad").join(rel);
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::write(dest, bytes).unwrap();
    }

    fn sessions_dir(&self) -> PathBuf {
        self.home.join(".claude/sessions")
    }

    /// Write `sessions/<pid>.json` linking a pid to a session uuid.
    fn write_session(&self, pid: u32, uuid: &str) {
        let dir = self.sessions_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(format!("{pid}.json")),
            serde_json::json!({"sessionId": uuid, "cwd": "/home/test"}).to_string(),
        )
        .unwrap();
    }

    fn set_live_pid(&self, pid: u32) {
        std::fs::create_dir_all(self.proc_root.join(pid.to_string())).unwrap();
    }

    fn set_dead_pid(&self, pid: u32) {
        let _ = std::fs::remove_dir_all(self.proc_root.join(pid.to_string()));
    }

    fn gc_log(&self) -> Vec<serde_json::Value> {
        let path = self.yomi_home.join("gc.log");
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn write_config(&self, toml: &str) {
        std::fs::create_dir_all(&self.yomi_home).unwrap();
        std::fs::write(self.yomi_home.join("config.toml"), toml).unwrap();
    }

    fn session_store(&self) -> PathBuf {
        self.yomi_home
            .join("archive")
            .join(&self.slug)
            .join(&self.uuid)
    }

    fn transcript_store(&self) -> PathBuf {
        self.session_store().join("transcript.jsonl.zst")
    }

    fn write_tool_result(&self, name: &str, bytes: &[u8]) {
        let dir = self.companion().join("tool-results");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), bytes).unwrap();
    }

    fn write_scratch_file(&self, rel: &str, bytes: &[u8]) {
        let dest = self
            .tmp_root
            .join(&self.slug)
            .join(&self.uuid)
            .join("scratchpad")
            .join(rel);
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::write(dest, bytes).unwrap();
    }

    fn quarantine_dir(&self) -> PathBuf {
        self.yomi_home.join("quarantine").join(&self.uuid)
    }
}

fn unique() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// Backdate a file/dir mtime by `days` (for age-gate tests).
fn set_mtime_days(path: &Path, days: u64) {
    let when = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86_400);
    filetime::set_file_mtime(path, filetime::FileTime::from_system_time(when)).unwrap();
}

/// Backdate every file under a tree (scratch age is the newest file mtime).
fn set_tree_mtime_days(root: &Path, days: u64) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    set_mtime_days(&p, days);
                }
            }
        }
    }
}

fn user_line(text: &str) -> String {
    serde_json::json!({
        "type": "user",
        "uuid": format!("u-{}", unique()),
        "parentUuid": null,
        "timestamp": "2026-07-12T10:00:00.000Z",
        "cwd": "/home/test",
        "gitBranch": "main",
        "version": "2.1.207",
        "sessionId": "11111111-2222-3333-4444-555555555555",
        "message": {"role": "user", "content": text}
    })
    .to_string()
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn read_store(path: &Path) -> Vec<u8> {
    decompress_all(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn session_archive_is_byte_faithful_and_idempotent() {
    let fx = Fixture::new("faithful");
    let lines = vec![
        user_line("hello world"),
        user_line("second turn with some detail"),
    ];
    fx.write_transcript(&lines);

    // Subagent transcript + verbatim meta.
    let sub_dir = fx.companion().join("subagents");
    std::fs::create_dir_all(&sub_dir).unwrap();
    std::fs::write(
        sub_dir.join("agent-abc.jsonl"),
        format!("{}\n", user_line("subagent work")),
    )
    .unwrap();
    std::fs::write(
        sub_dir.join("agent-abc.meta.json"),
        r#"{"agentType":"kanayama","description":"build","toolUseId":"toolu_x"}"#,
    )
    .unwrap();

    // Tool result.
    let tr_dir = fx.companion().join("tool-results");
    std::fs::create_dir_all(&tr_dir).unwrap();
    std::fs::write(tr_dir.join("toolu_res.txt"), "large tool output\nmore\n").unwrap();

    let out = fx.run(&["archive", "--all", "--include", "all", "--json"]);
    assert!(out.status.success(), "archive failed: {:?}", out);
    let v: serde_json::Value = serde_json::from_str(stdout(&out).lines().last().unwrap()).unwrap();
    assert_eq!(v["sessions"], 1);
    assert!(v["artifacts_written"].as_u64().unwrap() >= 3);

    // Byte-faithful transcript round-trip.
    let stored = read_store(&fx.session_store().join("transcript.jsonl.zst"));
    let expected = std::fs::read(fx.transcript_path()).unwrap();
    assert_eq!(stored, expected, "transcript not byte-faithful");

    // Manifest present with provenance.
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fx.session_store().join("manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["session_uuid"], fx.uuid);
    assert_eq!(manifest["cc_version"], "2.1.207");
    assert_eq!(manifest["git_branch"], "main");

    // Verify passes.
    let vout = fx.run(&["verify", "--all"]);
    assert!(vout.status.success());
    assert!(stdout(&vout).contains("Verified"));

    // Second archive is a no-op.
    let store_bytes_before =
        std::fs::read(fx.session_store().join("transcript.jsonl.zst")).unwrap();
    let out2 = fx.run(&["archive", "--all", "--include", "all", "--json"]);
    let v2: serde_json::Value =
        serde_json::from_str(stdout(&out2).lines().last().unwrap()).unwrap();
    assert_eq!(
        v2["artifacts_written"], 0,
        "second run should write nothing"
    );
    let store_bytes_after = std::fs::read(fx.session_store().join("transcript.jsonl.zst")).unwrap();
    assert_eq!(
        store_bytes_before, store_bytes_after,
        "store mutated on no-op"
    );
}

#[test]
fn secret_high_redacts_and_quarantines() {
    let fx = Fixture::new("secret");
    let lines = vec![
        user_line(&format!("here is a key {FIXTURE_AKIA} do not leak")),
        user_line("Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345"),
    ];
    fx.write_transcript(&lines);

    let out = fx.run(&["archive", "--all", "--json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(stdout(&out).lines().last().unwrap()).unwrap();
    assert!(
        v["quarantined"].as_u64().unwrap() >= 1,
        "no quarantine: {v}"
    );
    assert!(
        v["flagged"].as_u64().unwrap() >= 1,
        "bearer not flagged: {v}"
    );

    // Stored copy must not contain the raw secret.
    let stored = read_store(&fx.session_store().join("transcript.jsonl.zst"));
    let stored_str = String::from_utf8_lossy(&stored);
    assert!(
        !stored_str.contains(FIXTURE_AKIA),
        "raw HIGH secret leaked into store"
    );
    assert!(stored_str.contains("REDACTED:aws-key"));

    // Quarantine holds the unredacted original.
    let qdir = fx.yomi_home.join("quarantine").join(&fx.uuid);
    let found = std::fs::read_dir(&qdir)
        .unwrap()
        .filter_map(Result::ok)
        .any(|e| String::from_utf8_lossy(&std::fs::read(e.path()).unwrap()).contains(FIXTURE_AKIA));
    assert!(found, "quarantine missing unredacted original");

    // status --secrets surfaces findings.
    let sout = fx.run(&["status", "--secrets"]);
    let text = stdout(&sout);
    assert!(text.contains("aws-key"));
    assert!(text.contains("bearer"));
}

#[test]
fn incremental_append_adds_tail_frame() {
    let fx = Fixture::new("incr");
    fx.write_transcript(&[user_line("first")]);
    let out1 = fx.run(&["archive", "--all", "--json"]);
    assert!(out1.status.success());

    fx.append_transcript(&[user_line("second"), user_line("third")]);
    let out2 = fx.run(&["archive", "--all", "--json"]);
    let v2: serde_json::Value =
        serde_json::from_str(stdout(&out2).lines().last().unwrap()).unwrap();
    assert_eq!(
        v2["artifacts_written"], 1,
        "tail should re-write transcript"
    );

    // Decompressed store equals the full current source (frames concatenate).
    let stored = read_store(&fx.session_store().join("transcript.jsonl.zst"));
    let expected = std::fs::read(fx.transcript_path()).unwrap();
    assert_eq!(stored, expected, "incremental store diverged from source");

    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fx.session_store().join("manifest.json")).unwrap(),
    )
    .unwrap();
    let frames = manifest["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["role"] == "transcript")
        .unwrap()["frames"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(frames, 2, "expected two frames after append");

    assert!(fx.run(&["verify", "--all"]).status.success());
}

#[test]
fn blacklisted_credentials_never_archived() {
    let fx = Fixture::new("blacklist");
    fx.write_transcript(&[user_line("benign turn")]);

    let cred = fx.home.join(".claude/.credentials.json");
    std::fs::write(
        &cred,
        format!(r#"{{"claudeAiOauth":{{"accessToken":"{FIXTURE_CRED_SECRET}"}}}}"#),
    )
    .unwrap();

    let out = fx.run(&["archive", "--all", "--include", "all"]);
    assert!(out.status.success());

    // The credential file is untouched.
    assert!(cred.exists());
    let still = std::fs::read_to_string(&cred).unwrap();
    assert!(still.contains(FIXTURE_CRED_SECRET));

    // Its secret appears nowhere under YOMI_HOME.
    let leaked = walk_contains(&fx.yomi_home, FIXTURE_CRED_SECRET);
    assert!(!leaked, "blacklisted credential leaked into the store");
}

fn walk_contains(root: &Path, needle: &str) -> bool {
    for entry in walkdir_all(root) {
        if !entry.is_file() {
            continue;
        }
        let Ok(bytes) = std::fs::read(&entry) else {
            continue;
        };
        // Check raw and zstd-decompressed forms.
        if String::from_utf8_lossy(&bytes).contains(needle) {
            return true;
        }
        if entry.extension().and_then(|e| e.to_str()) == Some("zst")
            && let Ok(d) = decompress_all(&bytes)
            && String::from_utf8_lossy(&d).contains(needle)
        {
            return true;
        }
    }
    false
}

fn walkdir_all(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push(p);
                }
            }
        }
    }
    out
}

// ---- Security-path regressions (B1-B4, R5, W1-W2) ----

#[test]
fn b1_non_utf8_source_is_quarantined_whole() {
    let fx = Fixture::new("nonutf8");
    fx.write_transcript(&[user_line("ok")]);
    // Binary bytes that are invalid UTF-8 (0x80 is a stray continuation byte)
    // and do NOT begin with a BOM, embedding an ASCII secret.
    let mut blob = vec![0x80, 0x81, 0x82];
    blob.extend_from_slice(format!("secret {FIXTURE_AKIA} tail").as_bytes());
    fx.write_tool_result("blob.txt", &blob);

    let out = fx.run(&["archive", "--all", "--include", "all", "--json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(stdout(&out).lines().last().unwrap()).unwrap();
    assert!(
        v["quarantined"].as_u64().unwrap() >= 1,
        "not quarantined: {v}"
    );
    // The whole artifact is quarantined: no secret in the browsable store...
    assert!(
        !walk_contains(&fx.session_store(), FIXTURE_AKIA),
        "non-utf8 secret leaked into store"
    );
    // ...raw original recoverable from quarantine, and a marker is stored.
    assert!(
        walk_contains(&fx.quarantine_dir(), FIXTURE_AKIA),
        "quarantine missing the non-utf8 original"
    );
    assert!(walk_contains(&fx.session_store(), "QUARANTINED:non-utf8"));
}

#[test]
fn r5_json_escaped_secret_is_quarantined_whole() {
    let fx = Fixture::new("jsonesc");
    let escaped: String = FIXTURE_AKIA
        .chars()
        .map(|c| format!("\\u{:04x}", c as u32))
        .collect();
    // The transcript line embeds the secret only in \u-escaped form.
    let line = format!(
        "{{\"type\":\"user\",\"timestamp\":\"2026-07-12T10:00:00.000Z\",\"message\":{{\"role\":\"user\",\"content\":\"key {escaped} end\"}}}}"
    );
    fx.write_transcript(&[line]);

    let out = fx.run(&["archive", "--all", "--json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(stdout(&out).lines().last().unwrap()).unwrap();
    assert!(
        v["quarantined"].as_u64().unwrap() >= 1,
        "not quarantined: {v}"
    );

    let s = String::from_utf8_lossy(&read_store(&fx.transcript_store())).to_string();
    assert!(
        !s.contains(FIXTURE_AKIA),
        "escaped secret decoded into store: {s}"
    );
    assert!(
        s.contains("QUARANTINED:escape-hidden-secret"),
        "escape-hidden artifact not quarantined: {s}"
    );
    // The raw (escaped) original is preserved in quarantine.
    assert!(walk_contains(&fx.quarantine_dir(), "u0041"));
}

#[test]
fn b2_multiline_secret_in_malformed_jsonl_is_quarantined() {
    let fx = Fixture::new("pemframe");
    // A raw multi-line PEM can only appear in a transcript as non-JSON lines.
    // Such an artifact fails the JSONL structural gate and is quarantined whole,
    // so the key can never leak into the searchable store — across any frames.
    fx.write_transcript(&[user_line("start")]);
    fx.append_transcript(&[
        "-----BEGIN RSA PRIVATE KEY-----".to_string(),
        "MIIBfakekeybodyLINEone".to_string(),
    ]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    fx.append_transcript(&[
        "MIIBfakekeybodyLINEtwo".to_string(),
        "-----END RSA PRIVATE KEY-----".to_string(),
    ]);
    assert!(fx.run(&["archive", "--all"]).status.success());

    let s = String::from_utf8_lossy(&read_store(&fx.transcript_store())).to_string();
    assert!(
        !s.contains("BEGIN RSA PRIVATE KEY"),
        "key leaked into store: {s}"
    );
    assert!(
        s.contains("QUARANTINED:malformed-jsonl"),
        "not quarantined: {s}"
    );
    assert!(walk_contains(&fx.quarantine_dir(), "BEGIN RSA PRIVATE KEY"));
    assert!(fx.run(&["verify", "--all"]).status.success());
}

#[test]
fn utf16_tool_result_secret_does_not_leak() {
    let fx = Fixture::new("utf16");
    fx.write_transcript(&[user_line("ok")]);
    // A real UTF-16LE (BOM) tool-result carrying a visible secret.
    let mut blob = vec![0xFF, 0xFE];
    for u in format!("token {FIXTURE_AKIA} end").encode_utf16() {
        blob.extend_from_slice(&u.to_le_bytes());
    }
    fx.write_tool_result("u16.txt", &blob);

    let out = fx.run(&["archive", "--all", "--include", "all", "--json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(stdout(&out).lines().last().unwrap()).unwrap();
    assert!(
        v["quarantined"].as_u64().unwrap() >= 1,
        "not quarantined: {v}"
    );
    assert!(
        !walk_contains(&fx.session_store(), FIXTURE_AKIA),
        "utf16 secret leaked into store"
    );
}

#[test]
fn s1_zero_width_split_secret_is_quarantined() {
    let fx = Fixture::new("zwsp");
    // A zero-width space splits the key: valid UTF-8 + valid JSON, invisible to
    // a byte-regex, but contiguous once canonicalized.
    let split = format!("{}\u{200b}{}", &FIXTURE_AKIA[..4], &FIXTURE_AKIA[4..]);
    let line = format!(
        "{{\"type\":\"user\",\"timestamp\":\"2026-07-12T10:00:00.000Z\",\"message\":{{\"role\":\"user\",\"content\":\"key {split} end\"}}}}"
    );
    fx.write_transcript(&[line]);

    let out = fx.run(&["archive", "--all", "--json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(stdout(&out).lines().last().unwrap()).unwrap();
    assert!(
        v["quarantined"].as_u64().unwrap() >= 1,
        "not quarantined: {v}"
    );
    let s = String::from_utf8_lossy(&read_store(&fx.transcript_store())).to_string();
    assert!(
        !s.contains(FIXTURE_AKIA),
        "canonicalized secret leaked: {s}"
    );
    assert!(
        s.contains("QUARANTINED:escape-hidden-secret"),
        "not quarantined: {s}"
    );
}

#[test]
fn s2_utf16_island_in_ascii_is_quarantined() {
    let fx = Fixture::new("island");
    fx.write_transcript(&[user_line("ok")]);
    // A small UTF-16LE key island buried in a large ASCII tool-result body.
    let mut blob = vec![b'x'; 2000];
    let mut island = Vec::new();
    for c in FIXTURE_AKIA.bytes() {
        island.push(c);
        island.push(0);
    }
    blob.splice(1000..1000, island);
    fx.write_tool_result("mixed.txt", &blob);

    let out = fx.run(&["archive", "--all", "--include", "all", "--json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(stdout(&out).lines().last().unwrap()).unwrap();
    assert!(
        v["quarantined"].as_u64().unwrap() >= 1,
        "island not quarantined: {v}"
    );
    assert!(!walk_contains(&fx.session_store(), FIXTURE_AKIA));
}

#[test]
fn clean_japanese_content_stays_searchable() {
    let fx = Fixture::new("cjk");
    // Legitimate non-ASCII conversation content must NOT be over-quarantined.
    let line = "{\"type\":\"user\",\"timestamp\":\"2026-07-12T10:00:00.000Z\",\"message\":{\"role\":\"user\",\"content\":\"日本語のテキスト、絵文字 👨\u{200d}👩\u{200d}👧、記号 ①②③ を含む普通の会話\"}}";
    fx.write_transcript(&[line.to_string()]);

    let out = fx.run(&["archive", "--all", "--json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(stdout(&out).lines().last().unwrap()).unwrap();
    assert_eq!(v["quarantined"], 0, "clean CJK/emoji over-quarantined: {v}");
    // Stored byte-faithfully (no secret, no normalization mutation of the store).
    let stored = read_store(&fx.transcript_store());
    assert_eq!(stored, std::fs::read(fx.transcript_path()).unwrap());
}

#[test]
fn non_jsonl_role_escaped_secret_is_quarantined() {
    let fx = Fixture::new("plainesc");
    fx.write_transcript(&[user_line("ok")]);
    let escaped: String = FIXTURE_AKIA
        .chars()
        .map(|c| format!("\\u{:04x}", c as u32))
        .collect();
    // A plain (non-JSONL) tool-result hiding the secret behind \u escaping.
    fx.write_tool_result("log.txt", format!("event key={escaped}\n").as_bytes());

    let out = fx.run(&["archive", "--all", "--include", "all", "--json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(stdout(&out).lines().last().unwrap()).unwrap();
    assert!(
        v["quarantined"].as_u64().unwrap() >= 1,
        "not quarantined: {v}"
    );
    assert!(!walk_contains(&fx.session_store(), FIXTURE_AKIA));
}

#[test]
fn b3_verify_detects_store_corruption() {
    let fx = Fixture::new("corrupt");
    fx.write_transcript(&[user_line("one"), user_line("two")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    assert!(fx.run(&["verify", "--all"]).status.success());

    // Corrupt the stored artifact after archiving; verify must fail.
    let store = fx.transcript_store();
    let mut bytes = std::fs::read(&store).unwrap();
    bytes.extend_from_slice(&std::fs::read(&store).unwrap()); // duplicate frame
    std::fs::write(&store, &bytes).unwrap();

    let vout = fx.run(&["verify", "--all"]);
    assert!(!vout.status.success(), "verify passed on corrupted store");
    assert!(stdout(&vout).contains("FAILED"));
}

#[test]
fn b3_crash_interrupted_append_self_heals() {
    let fx = Fixture::new("selfheal");
    fx.write_transcript(&[user_line("one")]);
    assert!(fx.run(&["archive", "--all"]).status.success());

    // Simulate a crash *after* a store append but *before* the catalog commit:
    // the store has an extra (duplicate) frame the catalog doesn't know about.
    let store = fx.transcript_store();
    let mut bytes = std::fs::read(&store).unwrap();
    bytes.extend_from_slice(&std::fs::read(&store).unwrap());
    std::fs::write(&store, &bytes).unwrap();

    // A subsequent real growth must rewrite/heal the store, not compound it.
    fx.append_transcript(&[user_line("two")]);
    assert!(fx.run(&["archive", "--all"]).status.success());

    let stored = read_store(&fx.transcript_store());
    let expected = std::fs::read(fx.transcript_path()).unwrap();
    assert_eq!(stored, expected, "store not healed to match source");
    assert!(fx.run(&["verify", "--all"]).status.success());
}

#[test]
fn w1_fresh_home_read_commands_do_not_error() {
    let fx = Fixture::new("fresh");
    // No archive has run; YOMI_HOME does not exist yet.
    let s = fx.run(&["status"]);
    assert!(s.status.success(), "status errored on fresh home");
    assert!(stdout(&s).contains("Sessions:"));
    assert!(fx.run(&["verify", "--all"]).status.success());
    assert!(
        fx.run(&["archive", "--all", "--dry-run"]).status.success(),
        "dry-run errored on fresh home"
    );
    // A read-only command must not create the store.
    assert!(!fx.yomi_home.exists(), "read command created the store");
}

#[test]
fn w2_scratch_denies_nested_node_modules() {
    let fx = Fixture::new("scratchdeny");
    fx.write_transcript(&[user_line("ok")]);
    fx.write_scratch_file("notes.md", b"# keep me\n");
    fx.write_scratch_file("repo/node_modules/pkg/index.js", b"module.exports = 1\n");

    assert!(
        fx.run(&["archive", "--all", "--include", "scratch"])
            .status
            .success()
    );

    let store = fx
        .yomi_home
        .join("archive/_scratch")
        .join(format!("{}--{}", fx.slug, fx.uuid));
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(store.join("manifest.json")).unwrap())
            .unwrap();
    let entries = manifest["entries"].as_array().unwrap();
    let stored_of = |needle: &str| -> bool {
        entries
            .iter()
            .find(|e| e["path"].as_str().unwrap().contains(needle))
            .map(|e| e["stored"].as_bool().unwrap())
            .unwrap()
    };
    assert!(stored_of("notes.md"), "allowed file not stored");
    assert!(
        !stored_of("node_modules"),
        "nested node_modules was not denied"
    );
    assert!(!walk_contains(&store, "module.exports"));
}

// ---- P2 wipe / GC regression matrix (issue #2) ----

fn json_last(out: &std::process::Output) -> serde_json::Value {
    // gc --json emits a single pretty-printed value on stdout.
    serde_json::from_str(stdout(out).trim()).unwrap()
}

fn code(out: &std::process::Output) -> i32 {
    out.status.code().unwrap()
}

fn gc_log_has(fx: &Fixture, action: &str, needle: &str) -> bool {
    fx.gc_log().iter().any(|l| {
        l["action"] == action
            && (l["reason"]
                .as_str()
                .map(|r| r.contains(needle))
                .unwrap_or(false)
                || needle.is_empty())
    })
}

#[test]
fn p2_gc_all_gates_pass_deletes() {
    let fx = Fixture::new("gcpass");
    fx.write_transcript(&[user_line("one"), user_line("two")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    set_mtime_days(&fx.transcript_path(), 200);

    let out = fx.run(&["gc", "--targets", "transcripts", "--commit", "--json"]);
    assert_eq!(code(&out), 0, "commit not clean: {out:?}");
    assert!(!fx.transcript_path().exists(), "source not deleted");
    assert!(fx.transcript_store().exists(), "store was wrongly removed");
    assert!(gc_log_has(&fx, "delete", ""), "no delete in gc.log");
}

#[test]
fn p2_gc_sha_mismatch_refuses() {
    let fx = Fixture::new("gcsha");
    fx.write_transcript(&[user_line("one")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    // Live source drifts from the archived sha after capture.
    fx.append_transcript(&[user_line("late edit")]);
    set_mtime_days(&fx.transcript_path(), 200);

    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    assert_eq!(code(&out), 2, "expected EXIT_PARTIAL on sha mismatch");
    assert!(fx.transcript_path().exists(), "drifted source was deleted");
    assert!(gc_log_has(&fx, "skip", "ShaMismatch"));
}

#[test]
fn p2_gc_store_corruption_refuses() {
    let fx = Fixture::new("gccorrupt");
    fx.write_transcript(&[user_line("one"), user_line("two")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    set_mtime_days(&fx.transcript_path(), 200);
    // Corrupt the stored artifact (duplicate frame) after capture.
    let store = fx.transcript_store();
    let mut bytes = std::fs::read(&store).unwrap();
    bytes.extend_from_slice(&std::fs::read(&store).unwrap());
    std::fs::write(&store, &bytes).unwrap();

    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    assert_eq!(code(&out), 2, "expected refusal on store corruption");
    assert!(
        fx.transcript_path().exists(),
        "source deleted despite bad store"
    );
    assert!(gc_log_has(&fx, "skip", "StoreReverifyFailed"));
}

#[test]
fn p2_gc_no_archive_refuses() {
    let fx = Fixture::new("gcnoarch");
    fx.write_transcript(&[user_line("one")]);
    set_mtime_days(&fx.transcript_path(), 200);
    // Never archived → no catalog row.
    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    assert_eq!(code(&out), 2);
    assert!(fx.transcript_path().exists(), "un-archived source deleted");
    assert!(gc_log_has(&fx, "skip", "NoCatalogRow"));
}

#[test]
fn p2_gc_too_young_protected() {
    let fx = Fixture::new("gcyoung");
    fx.write_transcript(&[user_line("one")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    set_mtime_days(&fx.transcript_path(), 2); // within min_age (7d)

    let out = fx.run(&["gc", "--targets", "transcripts", "--json"]);
    assert_eq!(code(&out), 0);
    let v = json_last(&out);
    assert_eq!(v["deletable"], 0);
    assert!(v["protected"].as_u64().unwrap() >= 1);
    assert!(fx.transcript_path().exists());
}

#[test]
fn p2_gc_live_session_protected() {
    let fx = Fixture::new("gclive");
    fx.write_transcript(&[user_line("one")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    set_mtime_days(&fx.transcript_path(), 200); // aged well past retain
    fx.write_session(4242, &fx.uuid);
    fx.set_live_pid(4242);

    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    assert_eq!(code(&out), 0);
    assert!(
        fx.transcript_path().exists(),
        "live session's transcript was deleted"
    );
}

#[test]
fn p2_gc_dead_session_deletes() {
    let fx = Fixture::new("gcdead");
    fx.write_transcript(&[user_line("one")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    set_mtime_days(&fx.transcript_path(), 200);
    fx.write_session(4243, &fx.uuid);
    fx.set_dead_pid(4243); // no /proc/4243 → dead

    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    assert_eq!(code(&out), 0);
    assert!(!fx.transcript_path().exists(), "dead session not reclaimed");
}

#[test]
fn p2_gc_dry_run_default_no_delete() {
    let fx = Fixture::new("gcdry");
    fx.write_transcript(&[user_line("one")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    set_mtime_days(&fx.transcript_path(), 200);

    let out = fx.run(&["gc", "--targets", "transcripts", "--json"]);
    assert_eq!(code(&out), 0);
    let v = json_last(&out);
    assert_eq!(v["committed"], false);
    assert!(v["deletable"].as_u64().unwrap() >= 1);
    assert!(v["reclaimable_bytes"].as_u64().unwrap() > 0);
    assert!(fx.transcript_path().exists(), "dry-run deleted a file");
    assert!(
        !fx.yomi_home.join("gc.log").exists(),
        "dry-run wrote gc.log"
    );
}

#[test]
fn p2_gc_commit_deletes_and_reports_bytes() {
    let fx = Fixture::new("gccommit");
    fx.write_transcript(&[user_line("one"), user_line("two")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    set_mtime_days(&fx.transcript_path(), 200);

    let out = fx.run(&["gc", "--targets", "transcripts", "--commit", "--json"]);
    assert_eq!(code(&out), 0);
    let v = json_last(&out);
    assert_eq!(v["deleted"], 1);
    assert!(v["reclaimed_bytes"].as_u64().unwrap() > 0);
    assert!(!fx.transcript_path().exists());
}

#[test]
fn p2_gc_blacklisted_never_deleted() {
    let fx = Fixture::new("gcbl");
    let cred = fx.home.join(".claude/.credentials.json");
    std::fs::write(
        &cred,
        format!(r#"{{"accessToken":"{FIXTURE_CRED_SECRET}"}}"#),
    )
    .unwrap();
    // A hardlink to the credential at a transcript-shaped path.
    let link = fx
        .home
        .join(".claude/projects")
        .join(&fx.slug)
        .join("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.jsonl");
    std::fs::hard_link(&cred, &link).unwrap();
    set_mtime_days(&link, 200);

    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    assert!(link.exists(), "blacklisted hardlink was deleted");
    assert!(cred.exists(), "credential deleted via hardlink");
    assert!(gc_log_has(&fx, "skip", "Blacklisted"));
    let _ = code(&out);
}

#[test]
fn p2_gc_scratch_janitor() {
    let fx = Fixture::new("gcscratch");
    fx.write_scratch_for(&fx.uuid, "notes.md", b"# keep\n");
    fx.write_scratch_for(&fx.uuid, "repo/node_modules/x.js", b"module.exports=1\n");
    assert!(
        fx.run(&["archive", "--all", "--include", "scratch"])
            .status
            .success()
    );
    let tree = fx.scratch_session_dir(&fx.uuid);
    assert!(tree.exists());
    set_tree_mtime_days(&tree, 10); // > scratch_retain(3d) and > min_age(7d)

    let out = fx.run(&["gc", "--targets", "scratch", "--commit", "--json"]);
    assert_eq!(code(&out), 0, "scratch commit not clean: {out:?}");
    assert!(!tree.exists(), "scratch tree not reclaimed");
    assert!(gc_log_has(&fx, "delete", ""));
}

#[test]
fn p2_gc_empty_dirs_janitor() {
    let fx = Fixture::new("gcempty");
    let empty = fx.tmp_root.join("deadsess/empty-shell");
    std::fs::create_dir_all(&empty).unwrap();
    let keep = fx.tmp_root.join("deadsess/keep");
    std::fs::create_dir_all(&keep).unwrap();
    std::fs::write(keep.join("f"), b"x").unwrap();
    set_mtime_days(&empty, 10);

    let out = fx.run(&["gc", "--targets", "empty-dirs", "--commit"]);
    assert_eq!(code(&out), 0);
    assert!(!empty.exists(), "empty dir not removed");
    assert!(keep.join("f").exists(), "non-empty dir was touched");
}

#[test]
fn p2_gc_history_never_wiped() {
    let fx = Fixture::new("gchist");
    let hist = fx.home.join(".claude/history.jsonl");
    std::fs::write(&hist, b"{\"line\":1}\n").unwrap();
    set_mtime_days(&hist, 200);

    // No target reaches history, even on a full-default commit.
    let out = fx.run(&["gc", "--commit"]);
    assert_eq!(code(&out), 0);
    assert!(hist.exists(), "history.jsonl was wiped");
    // `history` is not even a valid target token.
    let bad = fx.run(&["gc", "--targets", "history"]);
    assert_ne!(code(&bad), 0, "history accepted as a target");
}

#[test]
fn p2_gc_lock_contention_refuses() {
    use fs2::FileExt;
    let fx = Fixture::new("gclock");
    fx.write_transcript(&[user_line("one")]);
    assert!(fx.run(&["archive", "--all"]).status.success());

    let lockf = std::fs::File::create(fx.yomi_home.join(".yomi.lock")).unwrap();
    lockf.try_lock_exclusive().unwrap();

    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    assert_eq!(code(&out), 3, "expected EXIT_REFUSED under lock contention");
    fs2::FileExt::unlock(&lockf).unwrap();
}

#[test]
fn p2_gc_min_age_only_raises() {
    let fx = Fixture::new("gcminage");
    let uuid_b = "22222222-3333-4444-5555-666666666666";
    fx.write_scratch_for(&fx.uuid, "a.md", b"aaa\n");
    fx.write_scratch_for(uuid_b, "b.md", b"bbb\n");
    assert!(
        fx.run(&["archive", "--all", "--include", "scratch"])
            .status
            .success()
    );
    set_tree_mtime_days(&fx.scratch_session_dir(&fx.uuid), 5); // < 7d floor
    set_tree_mtime_days(&fx.scratch_session_dir(uuid_b), 10); // > 7d floor

    // --min-age 1d cannot lower the 7d floor: the 5d tree stays protected,
    // only the 10d tree is deletable.
    let out = fx.run(&["gc", "--targets", "scratch", "--min-age", "1d", "--json"]);
    let v = json_last(&out);
    assert_eq!(v["deletable"], 1, "floor was lowered below 7d");
    assert_eq!(v["protected"], 1);

    // --min-age 30d raises the floor above both trees: nothing deletable.
    let out2 = fx.run(&["gc", "--targets", "scratch", "--min-age", "30d", "--json"]);
    let v2 = json_last(&out2);
    assert_eq!(v2["deletable"], 0, "raised floor did not protect");
    assert_eq!(v2["protected"], 2);
}

#[test]
fn p2_gc_require_indexed_unsatisfiable() {
    let fx = Fixture::new("gcidx");
    fx.write_transcript(&[user_line("one")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    set_mtime_days(&fx.transcript_path(), 200);
    // Configure require_indexed after the store exists (700-mode dir).
    fx.write_config("[gc]\nrequire_indexed = true\n");

    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    assert_eq!(code(&out), 2, "require_indexed did not refuse");
    assert!(
        fx.transcript_path().exists(),
        "deleted despite unsatisfiable index"
    );
    assert!(gc_log_has(&fx, "skip", "IndexUnsatisfiable"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("require_indexed"), "no warning emitted");
}

#[test]
fn p2_gc_discover_all_users_readonly() {
    let fx = Fixture::new("gcdiscover");
    // A fabricated multi-user tree under the discovery base.
    let alice = fx
        .home_base
        .join("alice/.claude/projects/-home-alice/uuid-alice-0000-1111-2222-333344445555.jsonl");
    std::fs::create_dir_all(alice.parent().unwrap()).unwrap();
    std::fs::write(&alice, b"{\"line\":1}\n").unwrap();
    let bob = fx
        .home_base
        .join("bob/.claude/projects/-home-bob/uuid-bob00-0000-1111-2222-333344445555.jsonl");
    std::fs::create_dir_all(bob.parent().unwrap()).unwrap();
    std::fs::write(&bob, b"{\"line\":1}\n").unwrap();

    let out = fx.run(&["gc", "--discover-all-users", "--json"]);
    assert_eq!(code(&out), 0);
    let v = json_last(&out);
    let arr = v.as_array().expect("discovery emits an array");
    assert!(!arr.is_empty(), "no shapes discovered");
    // READ-ONLY: foreign files remain, nothing was archived or deleted.
    assert!(
        alice.exists() && bob.exists(),
        "discovery mutated foreign data"
    );
    assert!(
        !fx.yomi_home.join("gc.log").exists(),
        "discovery wrote a gc.log"
    );
}

// ============================================================================
// p2_break_* — adversarial break tests (susanoo). Each asserts the SAFE outcome;
// a failure is a confirmed defect in the wipe/GC layer.
// ============================================================================

/// Snapshot every file under a dir as (relpath, len, sha256, is_file) — for
/// dry-run purity checks (no byte, no inode may change without --commit).
fn dir_snapshot(root: &Path) -> Vec<(String, u64, String, bool)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().to_string();
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                out.push((rel, 0, String::new(), false));
                stack.push(p);
            } else {
                let bytes = std::fs::read(&p).unwrap_or_default();
                let sha = yomi::util::sha256_hex(&bytes);
                out.push((rel, bytes.len() as u64, sha, true));
            }
        }
    }
    out.sort();
    out
}

/// DEFECT CANDIDATE (dry-run purity): a plan-only `gc` (no --commit) opens the
/// on-disk catalog read-write (open_env_read → Catalog::open → WAL pragma +
/// schema batch), which can mutate the db and/or leave sqlite sidecar inodes.
/// The design mandates a dry-run change nothing — not one byte, not one inode.
#[test]
fn p2_break_dry_run_is_byte_and_inode_pure() {
    let fx = Fixture::new("brkdry");
    fx.write_transcript(&[user_line("one"), user_line("two")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    set_mtime_days(&fx.transcript_path(), 200);

    let before = dir_snapshot(&fx.yomi_home);
    let out = fx.run(&["gc", "--targets", "transcripts", "--json"]);
    assert_eq!(code(&out), 0);
    let after = dir_snapshot(&fx.yomi_home);

    let new_paths: Vec<_> = after
        .iter()
        .filter(|(r, _, _, _)| !before.iter().any(|(br, _, _, _)| br == r))
        .map(|(r, ..)| r.clone())
        .collect();
    let changed: Vec<_> = after
        .iter()
        .filter(|(r, l, s, f)| {
            *f && before
                .iter()
                .any(|(br, bl, bs, _)| br == r && (bl != l || bs != s))
        })
        .map(|(r, ..)| r.clone())
        .collect();

    assert!(
        new_paths.is_empty(),
        "dry-run created new files under ~/.yomi: {new_paths:?}"
    );
    assert!(
        changed.is_empty(),
        "dry-run mutated files under ~/.yomi: {changed:?}"
    );
}

/// Create a scratch tree at an arbitrary slug/uuid (bypasses Fixture's fixed slug).
fn write_scratch_at(fx: &Fixture, slug: &str, uuid: &str, rel: &str, bytes: &[u8]) -> PathBuf {
    let sess = fx.tmp_root.join(slug).join(uuid);
    let dest = sess.join("scratchpad").join(rel);
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    std::fs::write(&dest, bytes).unwrap();
    sess
}

/// DEFECT CANDIDATE (live-session escape): GC derives a scratch tree's session
/// uuid via `key.split_once("--")`, but the store key is `<slug>--<uuid>` and
/// real Claude Code project slugs themselves contain `--` (e.g. this host's
/// `-home-yhi--zaibatsu`). The first `--` then splits inside the slug, yielding
/// the WRONG uuid, so the live-session guard never matches and an actively-live
/// session's scratch tree is deleted. Uses rsplit semantics as the safe oracle.
#[test]
fn p2_break_scratch_live_session_deleted_when_slug_has_double_dash() {
    let fx = Fixture::new("brkdd");
    let slug = "-home--proj"; // realistic: a path component beginning with '-'
    let uuid = "abababab-1111-2222-3333-444444444444";
    let tree = write_scratch_at(&fx, slug, uuid, "notes.md", b"# live work in progress\n");

    assert!(
        fx.run(&["archive", "--all", "--include", "scratch"])
            .status
            .success(),
        "scratch archive failed"
    );
    assert!(tree.exists());
    // Age the tree past retain+floor so only the live-session guard can save it.
    set_tree_mtime_days(&tree, 20);

    // Mark the session LIVE: sessions/<pid>.json → this uuid, and pid alive.
    fx.write_session(7777, uuid);
    fx.set_live_pid(7777);

    let out = fx.run(&["gc", "--targets", "scratch", "--commit", "--json"]);
    assert!(
        tree.exists(),
        "LIVE session's scratch tree was deleted (uuid mis-parse from '--' slug): {out:?}"
    );
}

/// DEFECT CANDIDATE (unverified-archive delete): scratch "store re-verification"
/// only checks that each stored `.zst` DECOMPRESSES — never that its content
/// matches the original (ScratchEntry carries no sha; scratch writes no catalog
/// row). So a stored archive whose bytes are wrong but still valid-zstd passes
/// the gate, and GC deletes the live original. The prime directive requires the
/// delete be gated on a *verified* archive; decompress-only is not verification.
#[test]
fn p2_break_scratch_deletes_despite_corrupt_archive_content() {
    let fx = Fixture::new("brkcorrupt");
    let tree = write_scratch_at(
        &fx,
        &fx.slug.clone(),
        &fx.uuid.clone(),
        "notes.md",
        b"REAL DATA\n",
    );
    assert!(
        fx.run(&["archive", "--all", "--include", "scratch"])
            .status
            .success()
    );

    // Corrupt every stored scratch artifact: replace with a VALID zstd frame of
    // entirely different bytes. decompress_all() still succeeds → gate 3 blind.
    let store = fx.yomi_home.join("archive").join("_scratch");
    let mut zsts = Vec::new();
    let mut stack = vec![store.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|x| x.to_str()) == Some("zst") {
                zsts.push(p);
            }
        }
    }
    assert!(!zsts.is_empty(), "no stored scratch artifact to corrupt");
    for z in &zsts {
        let bad = yomi::archive::compress::compress_frame(b"TOTALLY DIFFERENT CONTENT").unwrap();
        std::fs::write(z, &bad).unwrap();
    }

    set_tree_mtime_days(&tree, 20);
    let out = fx.run(&["gc", "--targets", "scratch", "--commit", "--json"]);
    assert!(
        tree.exists(),
        "scratch tree deleted though its archive holds corrupt/wrong content: {out:?}"
    );
}

/// CONTROL for the '--' defect above: an identical live-session scratch scenario
/// with a slug that has NO '--' parses the uuid correctly and IS protected. This
/// isolates the root cause to `split_once("--")` (should be rsplit) — scratch
/// liveness works, it is only the key parse that breaks on double-dash slugs.
#[test]
fn p2_break_scratch_live_session_protected_clean_slug() {
    let fx = Fixture::new("brkclean");
    let slug = "-home-proj"; // single dashes only
    let uuid = "cdcdcdcd-1111-2222-3333-444444444444";
    let tree = write_scratch_at(&fx, slug, uuid, "notes.md", b"# live work\n");
    assert!(
        fx.run(&["archive", "--all", "--include", "scratch"])
            .status
            .success()
    );
    set_tree_mtime_days(&tree, 20);
    fx.write_session(8888, uuid);
    fx.set_live_pid(8888);

    let out = fx.run(&["gc", "--targets", "scratch", "--commit", "--json"]);
    assert!(
        tree.exists(),
        "clean-slug live scratch was deleted — liveness itself is broken: {out:?}"
    );
}

// ============================================================================
// Single-file target families (mcp / paste / snapshots) — the File-gate delete
// path exercised end-to-end, plus gc.log permissions. (倶生: these families had
// no e2e coverage.)
// ============================================================================

#[test]
fn p2_gc_mcp_log_deletes_when_aged_and_archived() {
    let fx = Fixture::new("gcmcp");
    let src = fx
        .cache_home
        .join("someproj/mcp-logs-testsrv/00000000-0000-0000-0000-000000000abc.jsonl");
    std::fs::create_dir_all(src.parent().unwrap()).unwrap();
    std::fs::write(&src, b"{\"jsonrpc\":\"2.0\"}\n").unwrap();

    assert!(
        fx.run(&["archive", "--all", "--include", "mcp"])
            .status
            .success()
    );
    set_mtime_days(&src, 200); // > mcp_log_retain(14d) and > min_age(7d)

    let out = fx.run(&["gc", "--targets", "mcp", "--commit", "--json"]);
    assert_eq!(code(&out), 0, "mcp commit not clean: {out:?}");
    assert!(!src.exists(), "aged, archived mcp log not reclaimed");
    assert!(gc_log_has(&fx, "delete", ""));
}

#[test]
fn p2_gc_paste_deletes_when_aged_and_archived() {
    let fx = Fixture::new("gcpaste");
    let src = fx.home.join(".claude/paste-cache/p1.txt");
    std::fs::create_dir_all(src.parent().unwrap()).unwrap();
    std::fs::write(&src, b"pasted text\n").unwrap();

    assert!(
        fx.run(&["archive", "--all", "--include", "paste"])
            .status
            .success()
    );
    set_mtime_days(&src, 200); // > paste_retain(14d)

    let out = fx.run(&["gc", "--targets", "paste", "--commit", "--json"]);
    assert_eq!(code(&out), 0, "paste commit not clean: {out:?}");
    assert!(!src.exists(), "aged, archived paste not reclaimed");
    assert!(gc_log_has(&fx, "delete", ""));
}

#[test]
fn p2_gc_snapshot_deletes_when_aged_and_archived() {
    let fx = Fixture::new("gcsnap");
    let src = fx.home.join(".claude/shell-snapshots/snap-1.sh");
    std::fs::create_dir_all(src.parent().unwrap()).unwrap();
    std::fs::write(&src, b"#!/bin/sh\necho hi\n").unwrap();

    assert!(
        fx.run(&["archive", "--all", "--include", "snapshots"])
            .status
            .success()
    );
    set_mtime_days(&src, 200); // > snapshot_retain(30d)

    let out = fx.run(&["gc", "--targets", "snapshots", "--commit", "--json"]);
    assert_eq!(code(&out), 0, "snapshot commit not clean: {out:?}");
    assert!(!src.exists(), "aged, archived snapshot not reclaimed");
    assert!(gc_log_has(&fx, "delete", ""));
}

#[test]
fn p2_gc_log_is_mode_600() {
    use std::os::unix::fs::PermissionsExt;
    let fx = Fixture::new("gclogmode");
    fx.write_transcript(&[user_line("one")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    set_mtime_days(&fx.transcript_path(), 200);

    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    assert_eq!(code(&out), 0);
    let log = fx.yomi_home.join("gc.log");
    assert!(log.exists(), "gc.log not written on commit");
    let mode = std::fs::metadata(&log).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "gc.log is mode {mode:o}, expected 600");
}

/// A scratch tree that grew a NEW file after its last archive must not be
/// whole-tree deleted — the new file is unarchived data (R1). Uses the fixed
/// clean-slug path so only the manifest-coverage gate can protect it.
#[test]
fn p2_gc_scratch_new_unarchived_file_blocks_delete() {
    let fx = Fixture::new("gcnewfile");
    let tree = write_scratch_at(
        &fx,
        &fx.slug.clone(),
        &fx.uuid.clone(),
        "notes.md",
        b"kept\n",
    );
    assert!(
        fx.run(&["archive", "--all", "--include", "scratch"])
            .status
            .success()
    );
    // A file created AFTER archive — never captured.
    std::fs::write(tree.join("scratchpad/added-later.md"), b"unsaved work\n").unwrap();
    set_tree_mtime_days(&tree, 20);

    let out = fx.run(&["gc", "--targets", "scratch", "--commit", "--json"]);
    assert!(
        tree.exists(),
        "tree with an unarchived new file was deleted: {out:?}"
    );
    assert!(tree.join("scratchpad/added-later.md").exists());
}

/// R-1 (D2-fix effectiveness): the scratch archive build loop `continue`s past a
/// blacklisted candidate without pushing an entry, so a naive `entries.zip(
/// candidates)` misaligns every surviving entry with a wrong source path once any
/// earlier candidate is skipped. A kept file would then be stored under another
/// file's `.zst` slot with that other file's sha — silent data corruption that
/// also permanently blocks GC (live sha != recorded source sha → ShaMismatch).
/// The blacklisted file is named `_skip.env` so it sorts BEFORE the kept files
/// and thus triggers the mispair; `blacklist_add` makes it hard-denied.
#[test]
fn p2_scratch_archive_pairs_entries_after_blacklist_skip() {
    let fx = Fixture::new("scratchpair");
    fx.write_transcript(&[user_line("ok")]);
    let a = b"AAA content for a\n";
    let b = b"BBB different content for b\n";
    fx.write_scratch_for(&fx.uuid, "_skip.env", b"SECRET=leak\n");
    fx.write_scratch_for(&fx.uuid, "a.md", a);
    fx.write_scratch_for(&fx.uuid, "b.md", b);

    // Establish the 700 store layout first, then add the blacklist rule (writing
    // into the existing dir keeps its mode), then archive scratch under it.
    assert!(fx.run(&["archive", "--all"]).status.success());
    fx.write_config("blacklist_add = [\"**/_skip.env\"]\n");
    assert!(
        fx.run(&["archive", "--all", "--include", "scratch"])
            .status
            .success()
    );

    let store = fx
        .yomi_home
        .join("archive/_scratch")
        .join(format!("{}--{}", fx.slug, fx.uuid));

    // Each stored slot holds ITS OWN bytes, not a neighbor's (the mispair bug put
    // a.md's bytes into b.md.zst).
    assert_eq!(
        read_store(&store.join("scratchpad/a.md.zst")),
        a,
        "a.md slot mispaired"
    );
    assert_eq!(
        read_store(&store.join("scratchpad/b.md.zst")),
        b,
        "b.md slot mispaired"
    );

    // The manifest's recorded source sha for each entry matches its real content,
    // which is exactly what GC's Gate 2 (live sha == recorded source sha) checks.
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(store.join("manifest.json")).unwrap())
            .unwrap();
    let entries = manifest["entries"].as_array().unwrap();
    let src_sha = |needle: &str| -> String {
        entries
            .iter()
            .find(|e| e["path"].as_str().unwrap() == needle)
            .unwrap()["source_sha256"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(src_sha("scratchpad/a.md"), yomi::util::sha256_hex(a));
    assert_eq!(src_sha("scratchpad/b.md"), yomi::util::sha256_hex(b));

    // The blacklisted candidate never became an entry and its bytes never landed
    // in the store (guarded twice: skip here + read_source re-guard).
    assert!(
        !entries
            .iter()
            .any(|e| e["path"].as_str().unwrap().contains("_skip.env")),
        "blacklisted file leaked into the manifest"
    );
    assert!(!walk_contains(&store, "SECRET=leak"));
}

/// N-1 (D2 twin, catalog delete path): `verify_stored` keeps a legacy fallback
/// where an empty `content_sha256` degrades Gate 3 to a stored-bytes-only check,
/// which passes a valid-zstd frame of the wrong bytes. GC must never trust that
/// on a delete gate — a catalog row with no content hash is unverified and the
/// source is kept. Simulates a legacy row by blanking `content_sha256` in the
/// on-disk catalog after a normal archive.
#[test]
fn p2_gc_empty_content_sha_refuses() {
    let fx = Fixture::new("gcemptycsha");
    fx.write_transcript(&[user_line("one"), user_line("two")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    set_mtime_days(&fx.transcript_path(), 200);

    {
        let db = fx.yomi_home.join("state/catalog.db");
        let conn = rusqlite::Connection::open(&db).unwrap();
        let n = conn
            .execute("UPDATE artifacts SET content_sha256 = ''", [])
            .unwrap();
        assert!(n >= 1, "expected a catalog artifact row to blank");
    }

    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    assert_eq!(code(&out), 2, "expected refusal on empty content_sha");
    assert!(
        fx.transcript_path().exists(),
        "source deleted despite an unverifiable (empty) content hash"
    );
    assert!(gc_log_has(&fx, "skip", "EmptyContentSha"));
}
