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
        let slug = "-home-test".to_string();
        let uuid = "11111111-2222-3333-4444-555555555555".to_string();
        std::fs::create_dir_all(home.join(".claude/projects").join(&slug)).unwrap();
        std::fs::create_dir_all(&tmp_root).unwrap();
        std::fs::create_dir_all(&cache_home).unwrap();
        Fixture {
            home,
            yomi_home,
            tmp_root,
            cache_home,
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
            .env_remove("YOMI_HOME")
            .env_remove("YOMI_CLAUDE_HOME")
            .output()
            .expect("run yomi")
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
