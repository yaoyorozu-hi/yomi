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
const FIXTURE_CRED_SECRET: &str = "sk-cred-EXAMPLEFAKECREDENTIALNOTREAL0000";

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

    fn catalog_path(&self) -> PathBuf {
        self.yomi_home.join("state").join("catalog.db")
    }

    /// All `entries.text` values in the catalog (for redaction-exposure checks).
    fn entries_text(&self) -> Vec<String> {
        let conn = rusqlite::Connection::open(self.catalog_path()).unwrap();
        let mut stmt = conn.prepare("SELECT text FROM entries").unwrap();
        stmt.query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
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

fn assistant_line(text: &str, tool: Option<(&str, &str, &str)>) -> String {
    let mut content = vec![serde_json::json!({"type": "text", "text": text})];
    if let Some((id, name, command)) = tool {
        content.push(serde_json::json!({
            "type": "tool_use", "id": id, "name": name, "input": {"command": command}
        }));
    }
    serde_json::json!({
        "type": "assistant",
        "uuid": format!("a-{}", unique()),
        "parentUuid": null,
        "timestamp": "2026-07-12T11:00:00.000Z",
        "sessionId": "11111111-2222-3333-4444-555555555555",
        "message": {"role": "assistant", "content": content}
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
        v["redacted"].as_u64().unwrap() >= 2,
        "bearer + aws not both redacted: {v}"
    );

    // Stored copy must not contain the raw secret.
    let stored = read_store(&fx.session_store().join("transcript.jsonl.zst"));
    let stored_str = String::from_utf8_lossy(&stored);
    assert!(
        !stored_str.contains(FIXTURE_AKIA),
        "raw HIGH secret leaked into store"
    );
    assert!(stored_str.contains("REDACTED:aws-key"));
    assert!(
        !stored_str.contains("abcdefghijklmnopqrstuvwxyz012345"),
        "raw bearer token leaked into store"
    );
    assert!(stored_str.contains("REDACTED:bearer"));

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
    let fx = Fixture::new("gclock");
    fx.write_transcript(&[user_line("one")]);
    assert!(fx.run(&["archive", "--all"]).status.success());

    let lockf = std::fs::File::create(fx.yomi_home.join(".yomi.lock")).unwrap();
    lockf.try_lock().unwrap();

    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    assert_eq!(code(&out), 3, "expected EXIT_REFUSED under lock contention");
    lockf.unlock().unwrap();
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
fn p3_gc_require_indexed_gate() {
    // (a) archived-but-not-indexed → require_indexed skips the delete (NotIndexed).
    let fx = Fixture::new("gcidxa");
    fx.write_transcript(&[user_line("one")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    set_mtime_days(&fx.transcript_path(), 200);
    fx.write_config("[gc]\nrequire_indexed = true\n");
    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    assert_eq!(code(&out), 2, "unindexed source was not skipped");
    assert!(fx.transcript_path().exists(), "deleted despite no index");
    assert!(gc_log_has(&fx, "skip", "NotIndexed"));

    // (b) archived AND indexed → require_indexed permits the delete.
    let fx = Fixture::new("gcidxb");
    fx.write_transcript(&[user_line("one")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    assert!(fx.run(&["index"]).status.success());
    set_mtime_days(&fx.transcript_path(), 200);
    fx.write_config("[gc]\nrequire_indexed = true\n");
    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    assert_eq!(code(&out), 0, "indexed source was not deleted: {out:?}");
    assert!(!fx.transcript_path().exists(), "indexed source not deleted");
    assert!(gc_log_has(&fx, "delete", ""));

    // (c) indexed, then source changed (re-archived) but NOT reindexed → the
    // stale watermark (sha mismatch) fails the gate closed.
    let fx = Fixture::new("gcidxc");
    fx.write_transcript(&[user_line("one")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    assert!(fx.run(&["index"]).status.success());
    fx.append_transcript(&[user_line("two")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    set_mtime_days(&fx.transcript_path(), 200);
    fx.write_config("[gc]\nrequire_indexed = true\n");
    let out = fx.run(&["gc", "--targets", "transcripts", "--commit"]);
    assert_eq!(code(&out), 2, "stale-indexed source was not skipped");
    assert!(fx.transcript_path().exists(), "deleted on stale index");
    assert!(gc_log_has(&fx, "skip", "NotIndexed"));
}

#[test]
fn p3_index_and_search_roundtrip() {
    let fx = Fixture::new("idxroundtrip");
    fx.write_transcript(&[
        user_line("cargo build fails on the linker step"),
        assistant_line("Let me run the build.", Some(("t1", "Bash", "cargo build"))),
    ]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    let iout = fx.run(&["index", "--json"]);
    assert!(iout.status.success(), "index failed: {iout:?}");

    let out = fx.run(&["search", "cargo", "--json"]);
    assert_eq!(code(&out), 0);
    let v = json_last(&out);
    assert!(v["count"].as_u64().unwrap() >= 1, "no hits: {v}");
    let hits = v["hits"].as_array().unwrap();
    assert!(hits.iter().any(|h| h["role"] == "user"));
    assert!(
        hits.iter()
            .any(|h| h["snippet"].as_str().unwrap().contains("[cargo]")),
        "snippet not highlighted: {v}"
    );
}

#[test]
fn p3_search_facet_filters() {
    let fx = Fixture::new("idxfacet");
    fx.write_transcript(&[
        user_line("please investigate the widget"),
        assistant_line(
            "investigating the widget now",
            Some(("t9", "Bash", "grep widget")),
        ),
    ]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    assert!(fx.run(&["index"]).status.success());

    // Role filter keeps only assistant hits.
    let out = fx.run(&["search", "widget", "--role", "assistant", "--json"]);
    let v = json_last(&out);
    let hits = v["hits"].as_array().unwrap();
    assert!(!hits.is_empty(), "no assistant hits");
    assert!(hits.iter().all(|h| h["role"] == "assistant"));

    // Tool filter (inline field:value) keeps the Bash tool_use-bearing entry.
    let out = fx.run(&["search", "tool:Bash widget", "--json"]);
    let v = json_last(&out);
    let hits = v["hits"].as_array().unwrap();
    assert!(hits.iter().all(|h| h["tool"] == "Bash"));
    assert!(!hits.is_empty(), "tool filter dropped everything");

    // Metadata-only (no free text) with a role filter still returns rows.
    let out = fx.run(&["search", "role:user", "--json"]);
    let v = json_last(&out);
    assert!(
        v["count"].as_u64().unwrap() >= 1,
        "metadata-only path empty"
    );
}

#[test]
fn p3_index_no_raw_secret_exposure() {
    let fx = Fixture::new("idxsecret");
    // A visible AWS key in the transcript is redacted in place; a bare
    // segmented OpenAI key (no PEM wrapper — it must be caught on its own, not by
    // the private-key block detector) is redacted too; a whole-file quarantined
    // tool-result stores only a marker.
    let bare_sk = "sk-proj-EXAMPLEFAKEBAREPROJKEYNOTREAL0000";
    fx.write_transcript(&[
        user_line(&format!("deploy {FIXTURE_AKIA} to prod")),
        user_line(&format!("also my key is {bare_sk} do not share")),
    ]);
    fx.write_tool_result(
        "toolu_secret.txt",
        format!("-----BEGIN RSA PRIVATE KEY-----\n{FIXTURE_CRED_SECRET}\n-----END RSA PRIVATE KEY-----\n").as_bytes(),
    );
    assert!(
        fx.run(&["archive", "--all", "--include", "all"])
            .status
            .success()
    );
    assert!(fx.run(&["index"]).status.success());

    // (b) No entry text anywhere contains the raw secret material.
    for t in fx.entries_text() {
        assert!(!t.contains(FIXTURE_AKIA), "raw AWS key leaked into index");
        assert!(
            !t.contains(bare_sk),
            "raw bare sk-proj key leaked into index"
        );
        assert!(
            !t.contains(FIXTURE_CRED_SECRET),
            "raw quarantined secret leaked into index"
        );
    }

    // (a) Searching either raw secret returns nothing.
    for key in [FIXTURE_AKIA, bare_sk] {
        let out = fx.run(&["search", key, "--json"]);
        assert_eq!(
            json_last(&out)["count"].as_u64().unwrap(),
            0,
            "raw secret {key} searchable"
        );
    }

    // (c) The redaction placeholder is indexed and searchable.
    let out = fx.run(&["search", "REDACTED", "--json"]);
    assert!(
        json_last(&out)["count"].as_u64().unwrap() >= 1,
        "placeholder not searchable"
    );
}

#[test]
fn p3_index_reads_stored_not_source() {
    let fx = Fixture::new("idxstored");
    fx.write_transcript(&[user_line("original clean content about penguins")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    // Tamper the LIVE source after archiving, WITHOUT re-archiving: inject a secret.
    fx.append_transcript(&[user_line(&format!("smuggled {FIXTURE_AKIA} in later"))]);
    assert!(fx.run(&["index"]).status.success());

    // The tampered second line was never archived → never indexed; the store
    // (old redacted content) is the only thing indexed.
    for t in fx.entries_text() {
        assert!(
            !t.contains(FIXTURE_AKIA),
            "index read the tampered live source"
        );
    }
    let out = fx.run(&["search", "smuggled", "--json"]);
    assert_eq!(
        json_last(&out)["count"].as_u64().unwrap(),
        0,
        "tampered text indexed"
    );
    let out = fx.run(&["search", "penguins", "--json"]);
    assert!(
        json_last(&out)["count"].as_u64().unwrap() >= 1,
        "stored content missing"
    );
}

#[test]
fn p3_incremental_no_dup() {
    let fx = Fixture::new("idxincr");
    fx.write_transcript(&[user_line("first turn about apples")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    assert!(fx.run(&["index"]).status.success());
    let before = fx.entries_text().len();

    // Re-index with no change → nothing new, no duplicates.
    let out = fx.run(&["index", "--json"]);
    let v = json_last(&out);
    assert_eq!(
        v["artifacts_indexed"].as_u64().unwrap(),
        0,
        "reindexed unchanged"
    );
    assert!(v["artifacts_up_to_date"].as_u64().unwrap() >= 1);
    assert_eq!(
        fx.entries_text().len(),
        before,
        "duplicate entries appeared"
    );

    // Append a turn, re-archive, re-index → the appended turn is added, the old
    // ones are not duplicated.
    fx.append_transcript(&[user_line("second turn about bananas")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    assert!(fx.run(&["index"]).status.success());
    let after = fx.entries_text().len();
    assert_eq!(after, before + 1, "append did not add exactly one entry");
    let out = fx.run(&["search", "apples", "--json"]);
    assert_eq!(
        json_last(&out)["count"].as_u64().unwrap(),
        1,
        "apples duplicated or lost"
    );
}

#[test]
fn p3_reindex_rebuilds() {
    let fx = Fixture::new("idxreidx");
    fx.write_transcript(&[user_line("reindex me about oranges")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    assert!(fx.run(&["index"]).status.success());
    let before = fx.entries_text().len();

    let out = fx.run(&["index", "--reindex", "--json"]);
    assert!(out.status.success(), "reindex failed: {out:?}");
    assert_eq!(
        fx.entries_text().len(),
        before,
        "reindex changed entry count"
    );
    let out = fx.run(&["search", "oranges", "--json"]);
    assert!(
        json_last(&out)["count"].as_u64().unwrap() >= 1,
        "reindex lost content"
    );
}

/// WARN-1 regression: a fresh catalog under `[index].tokenizer = "trigram"` must
/// NOT silently record `trigram` against the unicode61 vtable that schema.sql
/// creates. The first plain `yomi index` detects the mismatch and refuses; only
/// `--reindex` rebuilds the FTS with the trigram tokenizer — after which a CJK
/// substring (which a bare unicode61 MATCH cannot find) is searchable.
#[test]
fn p3_trigram_reindex_enables_cjk_substring() {
    let fx = Fixture::new("idxtri");
    fx.write_transcript(&[user_line("設計レビュー 思兼課長の索引方針について")]);
    // Establish the 700 store layout first; writing config.toml into the existing
    // dir keeps its mode (archive would refuse a too-loose root created earlier).
    assert!(fx.run(&["archive", "--all"]).status.success());
    fx.write_config("[index]\ntokenizer = \"trigram\"\n");

    // First plain index: bootstrap records the real (unicode61) vtable tokenizer,
    // so the trigram config is a mismatch → refuse, do not index.
    let out = fx.run(&["index"]);
    assert_eq!(
        code(&out),
        3,
        "trigram config against a unicode61 vtable should refuse: {out:?}"
    );
    assert_eq!(
        fx.entries_text().len(),
        0,
        "refused index still wrote entries"
    );

    // --reindex rebuilds the FTS vtable with trigram and indexes.
    let out = fx.run(&["index", "--reindex", "--json"]);
    assert!(out.status.success(), "trigram reindex failed: {out:?}");
    assert!(!fx.entries_text().is_empty(), "reindex wrote no entries");

    // A 3-char CJK substring in the middle of a whitespace-free run — only a
    // trigram tokenizer resolves this.
    let out = fx.run(&["search", "思兼課", "--json"]);
    assert!(
        json_last(&out)["count"].as_u64().unwrap() >= 1,
        "trigram CJK substring search returned nothing"
    );

    // A subsequent plain index now agrees with the recorded tokenizer.
    let out = fx.run(&["index"]);
    assert_eq!(
        code(&out),
        0,
        "plain index after trigram reindex refused: {out:?}"
    );
}

#[test]
fn p3_search_fresh_home_zero_hits() {
    let fx = Fixture::new("idxfresh");
    let out = fx.run(&["search", "anything", "--json"]);
    assert_eq!(code(&out), 0, "fresh-home search errored");
    assert_eq!(json_last(&out)["count"].as_u64().unwrap(), 0);
}

#[test]
fn p3_read_jump_ref() {
    let fx = Fixture::new("idxread");
    fx.write_transcript(&[user_line("readable turn about turtles")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    assert!(fx.run(&["index"]).status.success());

    let out = fx.run(&["search", "turtles", "--json"]);
    let v = json_last(&out);
    let hit = &v["hits"].as_array().unwrap()[0];
    let entry_uuid = hit["entry_uuid"].as_str().unwrap();
    let session = hit["session"].as_str().unwrap();

    let rout = fx.run(&["read", session, "--entry", entry_uuid, "--json"]);
    assert_eq!(code(&rout), 0, "read jump failed: {rout:?}");
    assert!(stdout(&rout).contains("turtles"), "entry not shown");

    // --raw works without any index dependency.
    let raw = fx.run(&["read", session, "--raw"]);
    assert_eq!(code(&raw), 0);
    assert!(stdout(&raw).contains("turtles"));
}

#[test]
fn p3_index_lock_refused() {
    let fx = Fixture::new("idxlock");
    fx.write_transcript(&[user_line("locked")]);
    assert!(fx.run(&["archive", "--all"]).status.success());

    let lockf = std::fs::File::create(fx.yomi_home.join(".yomi.lock")).unwrap();
    lockf.try_lock().unwrap();
    let out = fx.run(&["index"]);
    assert_eq!(code(&out), 3, "index did not refuse under lock contention");
    lockf.unlock().unwrap();
}

#[test]
fn p3_index_malformed_jsonl_no_crash() {
    let fx = Fixture::new("idxmalformed");
    // A transcript with a well-formed line, a non-JSON line, and another good
    // line. The scanner holds conversation JSONL to a strict gate, so a stray
    // non-JSON line quarantines the whole artifact — the indexer must still not
    // crash, and no raw content leaks.
    fx.write_transcript(&[
        user_line("well formed line about robots"),
        "this is not valid json at all".to_string(),
        user_line("another good line about robots"),
    ]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    let out = fx.run(&["index", "--json"]);
    assert!(
        out.status.success(),
        "index crashed on malformed input: {out:?}"
    );
    // Never panics; the search path stays healthy.
    let s = fx.run(&["search", "robots", "--json"]);
    assert_eq!(code(&s), 0);
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

// ============================================================================
// 須佐之男 (Susanoo) — P3 adversarial break tests. Appended (test-only). These
// probe the "raw secret must never enter the search index" invariant, the
// quarantined=1 deviation, FTS/SQL injection, and parser robustness.
// ============================================================================

/// Modern OpenAI-style keys whose prefix segment ends in a hyphen. The old
/// `openai-key` detector `sk-[A-Za-z0-9]{20,}` could not match them (the class
/// terminated at the `-` after `proj`/`cred`); the segmented-body detector now
/// does.
const SK_PROJ_KEY: &str = "sk-proj-EXAMPLEFAKEKEYNOTAREALSECRET000000";
const SK_CRED_BARE: &str = "sk-cred-EXAMPLEFAKECREDENTIALNOTREAL0000";

/// Regression (was CRITICAL leak): a real-shaped `sk-proj-` / `sk-cred-` API key
/// is now detected by the scanner, redacted before storage, and therefore absent
/// from the index and unsearchable — the "raw secret never in index" invariant
/// holds for the modern segmented OpenAI key shapes.
#[test]
fn p3_index_sk_prefixed_key_is_redacted() {
    let fx = Fixture::new("brk-sk");
    // Plant in a transcript (PerEntry index mode) and a tool-result (SingleDoc).
    fx.write_transcript(&[
        user_line(&format!("here is my openai key {SK_PROJ_KEY} keep it safe")),
        assistant_line(&format!("stored {SK_CRED_BARE} for you"), None),
    ]);
    fx.write_tool_result(
        "toolu_leak.txt",
        format!("export OPENAI_API_KEY={SK_PROJ_KEY}\n").as_bytes(),
    );
    assert!(
        fx.run(&["archive", "--all", "--include", "all"])
            .status
            .success()
    );
    assert!(fx.run(&["index"]).status.success());

    for t in fx.entries_text() {
        assert!(!t.contains(SK_PROJ_KEY), "sk-proj key leaked into index");
        assert!(!t.contains(SK_CRED_BARE), "sk-cred key leaked into index");
    }

    // Neither raw key is searchable.
    for key in [SK_PROJ_KEY, SK_CRED_BARE] {
        let out = fx.run(&["search", key, "--json"]);
        assert_eq!(
            json_last(&out)["count"].as_u64().unwrap(),
            0,
            "raw key {key} still searchable"
        );
    }
    // The redaction placeholder is indexed in its place.
    let out = fx.run(&["search", "REDACTED", "--json"]);
    assert!(
        json_last(&out)["count"].as_u64().unwrap() >= 1,
        "redacted openai-key entries not indexed"
    );
}

/// Regression (was leak): a keyword-anchored high-entropy hex token and a
/// connection-string password are now detected and redacted, so neither reaches
/// the index. The connection-string host is intentionally preserved.
#[test]
fn p3_index_hex_and_connstring_secrets_are_redacted() {
    let fx = Fixture::new("brk-cls");
    let hex_secret = "deadbeefcafebabe0123456789abcdeffedcba9876543210"; // 48 hex, keyword'd
    let db_url = "postgres://admin:S3cr3tP@ssw0rd@db.internal:5432/prod";
    fx.write_transcript(&[
        user_line(&format!("token {hex_secret} here")),
        user_line(&format!("connect {db_url} now")),
    ]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    assert!(fx.run(&["index"]).status.success());
    let texts = fx.entries_text();
    assert!(
        !texts.iter().any(|t| t.contains(hex_secret)),
        "keyword'd hex secret leaked into index"
    );
    assert!(
        !texts.iter().any(|t| t.contains("S3cr3tP@ssw0rd")),
        "db password leaked into index"
    );
    // Host after the credential delimiter stays searchable.
    let out = fx.run(&["search", "db.internal", "--json"]);
    assert!(
        json_last(&out)["count"].as_u64().unwrap() >= 1,
        "connection-string host over-redacted"
    );
    for key in [hex_secret, "S3cr3tP@ssw0rd"] {
        let out = fx.run(&["search", key, "--json"]);
        assert_eq!(
            json_last(&out)["count"].as_u64().unwrap(),
            0,
            "raw secret {key} searchable"
        );
    }
}

/// Resolve the quarantined=1 fact conflict with a real archive+index:
/// a VISIBLE HIGH secret (AWS key) → quarantined=1, but stored content is
/// fully-redacted BROWSABLE text (placeholder), it IS indexed, and the raw key
/// is absent from both store and index. Confirms 金山's deviation is safe *for
/// detected secrets*.
#[test]
fn p3_quarantined_high_visible_is_redacted_browsable_and_indexed() {
    let fx = Fixture::new("q1-vis");
    fx.write_transcript(&[user_line(&format!("deploy {FIXTURE_AKIA} to prod now"))]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    assert!(fx.run(&["index"]).status.success());

    // Catalog: the artifact is quarantined=1 yet redacted=1 (in-place redaction).
    let conn = rusqlite::Connection::open(fx.catalog_path()).unwrap();
    let (q, red): (i64, i64) = conn
        .query_row(
            "SELECT quarantined, redacted FROM artifacts WHERE role='transcript'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(q, 1, "visible HIGH secret should quarantine the original");
    assert_eq!(red, 1, "stored content should be redacted-in-place");

    // Stored bytes are browsable redacted text, NOT an opaque marker.
    let stored = read_store(&fx.transcript_store());
    let s = String::from_utf8_lossy(&stored);
    assert!(!s.contains(FIXTURE_AKIA), "raw key in store");
    assert!(
        s.contains("REDACTED:aws-key"),
        "not browsable redacted text"
    );
    assert!(!s.contains("QUARANTINED:"), "unexpected opaque marker");

    // Indexed and searchable by placeholder; raw key absent + unsearchable.
    for t in fx.entries_text() {
        assert!(!t.contains(FIXTURE_AKIA), "raw key leaked to index");
    }
    let out = fx.run(&["search", FIXTURE_AKIA, "--json"]);
    assert_eq!(
        json_last(&out)["count"].as_u64().unwrap(),
        0,
        "raw key searchable"
    );
    let out = fx.run(&["search", "deploy", "--json"]);
    assert!(
        json_last(&out)["count"].as_u64().unwrap() >= 1,
        "redacted entry not indexed"
    );
}

/// FTS5 / SQL injection surface: malicious query strings must never panic, error
/// the process, or act as injection. Every one should exit 0 with a valid JSON
/// envelope.
#[test]
fn p3_break_fts_and_sql_injection_is_inert() {
    let fx = Fixture::new("brk-inj");
    fx.write_transcript(&[user_line("harmless indexed content about turbines")]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    assert!(fx.run(&["index"]).status.success());

    let payloads = [
        "\"",                                  // lone double quote
        "turbines\" OR \"1\"=\"1",             // FTS injection attempt
        "NEAR(a b)",                           // FTS operator syntax
        "a AND b OR c*",                       // operators
        "^turbines",                           // column/anchor op
        "turbines : NEAR",                     // stray colon
        "'; DROP TABLE entries;--",            // classic SQLi
        "role:user'); DELETE FROM entries;--", // facet SQLi
        "*",                                   // bare star
        "()))(((",                             // unbalanced parens
    ];
    for p in payloads {
        let out = fx.run(&["search", p, "--json"]);
        assert_eq!(
            code(&out),
            0,
            "query {p:?} did not exit cleanly: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        // Envelope must still parse and entries table must survive injection.
        let _ = json_last(&out);
    }
    // The index survived every payload.
    assert_eq!(
        fx.entries_text().len(),
        1,
        "entries table mutated by a query"
    );
    let out = fx.run(&["search", "turbines", "--json"]);
    assert!(
        json_last(&out)["count"].as_u64().unwrap() >= 1,
        "index destroyed"
    );
}

/// Parser fuzz part A: a VALID but pathological transcript (2 MB single line,
/// circular parentUuid, empty-type noise, deeply-nested-but-balanced value) must
/// archive + index without crashing, and the conversational lines stay
/// searchable. Everything here is well-formed JSONL so it survives the archive
/// scan gate and actually reaches the index parser.
#[test]
fn p3_break_parser_fuzz_valid_pathological_never_crashes() {
    let fx = Fixture::new("brk-fuzzA");
    let circular = serde_json::json!({
        "type":"user","uuid":"c1","parentUuid":"c1",
        "message":{"role":"user","content":"self parent marmot"}
    })
    .to_string();
    let giant = serde_json::json!({
        "type":"user","uuid":"g1",
        "message":{"role":"user","content":"X".repeat(2_000_000)}
    })
    .to_string();
    // 60-deep balanced array (under serde's ~128 recursion limit) as an
    // assistant content block list-of-lists; parser tolerates unknown shape.
    let deep = format!(
        "{{\"type\":\"assistant\",\"uuid\":\"d1\",\"message\":{{\"role\":\"assistant\",\"content\":{}{}}}}}",
        "[".repeat(60),
        "]".repeat(60)
    );
    let empty_type = serde_json::json!({"uuid":"e1","message":{"content":"no type"}}).to_string();
    let good = user_line("valid searchable capybara line");

    fx.write_transcript(&[circular, giant, deep, empty_type, good]);
    let out = fx.run(&["archive", "--all"]);
    assert!(out.status.success(), "archive crashed: {out:?}");
    let iout = fx.run(&["index", "--json"]);
    assert!(
        iout.status.success(),
        "index crashed on pathological input: {iout:?}"
    );

    let out = fx.run(&["search", "capybara", "--json"]);
    assert!(
        json_last(&out)["count"].as_u64().unwrap() >= 1,
        "good line lost among pathological-but-valid input"
    );
}

/// Parser fuzz part B: a transcript containing a malformed/truncated line. The
/// archive scan gate classifies the WHOLE artifact as `malformed-jsonl` and
/// stores only an opaque marker (fail-closed). Neither archive nor index crash;
/// the index carries the marker (searchable), and NONE of the sibling clean
/// content becomes searchable — a whole-artifact availability trade documented,
/// not an exposure.
#[test]
fn p3_break_malformed_line_quarantines_whole_no_crash() {
    let fx = Fixture::new("brk-fuzzB");
    let good = user_line("secret-free clean wolverine content");
    let truncated =
        "{\"type\":\"user\",\"uuid\":\"t1\",\"message\":{\"role\":\"user\",\"content\":\"cut"
            .to_string();
    fx.write_transcript(&[good, truncated]);
    let out = fx.run(&["archive", "--all"]);
    assert!(
        out.status.success(),
        "archive crashed on malformed line: {out:?}"
    );
    let iout = fx.run(&["index", "--json"]);
    assert!(
        iout.status.success(),
        "index crashed on quarantined marker: {iout:?}"
    );

    // Stored artifact is a whole-quarantine marker, not the clean sibling text.
    let stored = read_store(&fx.transcript_store());
    let s = String::from_utf8_lossy(&stored);
    assert!(
        s.contains("QUARANTINED:"),
        "malformed line not whole-quarantined: {s}"
    );

    // The clean sibling line is NOT independently searchable (whole-quarantine).
    let out = fx.run(&["search", "wolverine", "--json"]);
    assert_eq!(
        json_last(&out)["count"].as_u64().unwrap(),
        0,
        "clean content leaked past whole-quarantine"
    );
}

// ============================================================================
// SUSANOO re-break battery: does 金山's scan-layer fix actually hold end-to-end?
// Each test plants a secret in a transcript, runs archive→index, and asserts on
// the catalog's entries.text + `search`. A raw secret reaching entries.text is a
// CRITICAL residual leak.
// ============================================================================

/// The `/`-in-password bypass is closed: the connection-string password class
/// admits `/` and backtracks to the host `@`, so `aB3/xY9z` is redacted and the
/// raw password never reaches entries.text or the index. The host stays
/// searchable (only user+password+`@` is redacted). `/` in DB passwords is
/// common (base64/random-generated creds, e.g. RDS).
#[test]
fn p3_rebreak_connstring_slash_password_is_redacted() {
    let fx = Fixture::new("rb-cs-slash");
    let leak_url = "postgres://admin:aB3/xY9z@db.internal:5432/prod";
    let pw = "aB3/xY9z";
    fx.write_transcript(&[user_line(&format!("connect {leak_url} now"))]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    assert!(fx.run(&["index"]).status.success());

    let leaked_in_entries = fx.entries_text().iter().any(|t| t.contains(pw));
    let out = fx.run(&["search", pw, "--json"]);
    let searchable = json_last(&out)["count"].as_u64().unwrap();

    assert!(
        !leaked_in_entries,
        "CRITICAL: connection-string password with '/' leaked into entries.text"
    );
    assert_eq!(
        searchable, 0,
        "CRITICAL: connection-string password with '/' is searchable in the index"
    );

    // The host survives redaction and stays searchable.
    let host = fx.run(&["search", "internal", "--json"]);
    assert!(
        json_last(&host)["count"].as_u64().unwrap() >= 1,
        "host over-redacted: not searchable"
    );
}

/// Companion: the pct-encoded form (`%2F`) and embedded-`@` form ARE caught, to
/// prove the leak is specifically the raw-`/` bypass, not a total connstring miss.
#[test]
fn p3_rebreak_connstring_encoded_and_at_forms_are_caught() {
    let fx = Fixture::new("rb-cs-ok");
    let pct = "postgres://u:pa%2Fss@host.internal/db";
    let atpw = "postgres://admin:S3cr3tP@ssw0rd@db.internal:5432/prod";
    fx.write_transcript(&[
        user_line(&format!("a {pct} b")),
        user_line(&format!("c {atpw} d")),
    ]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    assert!(fx.run(&["index"]).status.success());
    let texts = fx.entries_text();
    assert!(
        !texts.iter().any(|t| t.contains("pa%2Fss")),
        "pct-encoded password leaked"
    );
    assert!(
        !texts.iter().any(|t| t.contains("S3cr3tP@ssw0rd")),
        "embedded-@ password leaked"
    );
}

/// bearer tokens are now Severity::Med → redacted. The raw token no longer
/// reaches stored content or the searchable index.
#[test]
fn p3_rebreak_bearer_token_is_redacted() {
    let fx = Fixture::new("rb-bearer");
    let token = "abcdefghijklmnopqrstuvwxyz012345";
    fx.write_transcript(&[user_line(&format!("Authorization: Bearer {token}"))]);
    assert!(fx.run(&["archive", "--all"]).status.success());
    assert!(fx.run(&["index"]).status.success());

    let in_entries = fx.entries_text().iter().any(|t| t.contains(token));
    let out = fx.run(&["search", token, "--json"]);
    let searchable = json_last(&out)["count"].as_u64().unwrap();
    assert!(!in_entries, "bearer token leaked into entries.text");
    assert_eq!(searchable, 0, "bearer token is searchable in the index");
}

/// High-prevalence secret classes newly covered this round (bearer/password=/
/// Basic/npm/pypi/SendGrid): each is planted in its real-world form and must be
/// redacted — none reaches entries.text. The deferred classes (Twilio `SK`,
/// Azure SAS `sig=`, keyword-less hi-entropy) are documented as known residual
/// in docs/design.md and are intentionally not asserted here.
#[test]
fn p3_rebreak_covered_secret_classes_are_redacted() {
    let fx = Fixture::new("rb-sweep");
    // (label, line, planted secret) — all fabricated, none live.
    let cases = [
        (
            "npm",
            "npm token npm_EXAMPLEFAKENPMTOKENNOTREAL0000000000 trailing",
            "npm_EXAMPLEFAKENPMTOKENNOTREAL0000000000",
        ),
        (
            "pypi",
            "pypi token pypi-EXAMPLEFAKEPYPITOKENNOTREAL00 trailing",
            "pypi-EXAMPLEFAKEPYPITOKENNOTREAL00",
        ),
        (
            "sendgrid",
            "sendgrid SG.EXAMPLEFAKE00000000000.EXAMPLEFAKESENDGRIDKEY000000000000000000000 trailing",
            "SG.EXAMPLEFAKE00000000000.EXAMPLEFAKESENDGRIDKEY000000000000000000000",
        ),
        (
            "basic-auth",
            "Authorization: Basic dXNlcjpzdXBlcnNlY3JldHBhc3N3b3Jk",
            "dXNlcjpzdXBlcnNlY3JldHBhc3N3b3Jk",
        ),
        (
            "password-eq",
            "config password=SuperSecretDbPass123 trailing",
            "SuperSecretDbPass123",
        ),
    ];
    let lines: Vec<String> = cases.iter().map(|(_, line, _)| user_line(line)).collect();
    fx.write_transcript(&lines);
    assert!(fx.run(&["archive", "--all"]).status.success());
    assert!(fx.run(&["index"]).status.success());

    let texts = fx.entries_text();
    let leaked: Vec<&str> = cases
        .iter()
        .filter(|(_, _, secret)| texts.iter().any(|t| t.contains(secret)))
        .map(|(label, _, _)| *label)
        .collect();
    assert!(
        leaked.is_empty(),
        "covered secret classes leaked into entries.text: {leaked:?}"
    );
}
