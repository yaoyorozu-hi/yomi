use super::{EXIT_OK, EXIT_PARTIAL};
use crate::archive::compress::decompress_all;
use crate::catalog;
use crate::config::Env;
use crate::index::EntryRow;
use anyhow::Result;

#[derive(clap::Args)]
pub struct ReadArgs {
    /// Session UUID to read; with --scratch, a session UUID or a full store key.
    ///
    /// Hyphen-leading values are accepted because every real scratch store key
    /// begins with one: a key is `<slug>--<uuid>` and a slug is a cwd path with
    /// its separators replaced, so it starts `-home-…`. Without this the
    /// documented "or a full store key" form is unusable for every key that
    /// actually exists.
    #[arg(allow_hyphen_values = true)]
    pub session: String,
    /// Jump to a single entry by its entry_uuid.
    #[arg(long, conflicts_with = "scratch")]
    pub entry: Option<String>,
    /// Include subagent transcripts, not just the main thread.
    #[arg(long, conflicts_with = "scratch")]
    pub agents: bool,
    /// Show only entries whose text contains this literal substring.
    #[arg(long, conflicts_with = "scratch")]
    pub grep: Option<String>,
    /// Emit the raw decompressed stored JSONL (index-independent).
    #[arg(long, conflicts_with = "scratch")]
    pub raw: bool,
    /// Read the archived scratch tree instead of the transcript. Without --file,
    /// lists the manifest.
    #[arg(long)]
    pub scratch: bool,
    /// With --scratch: write one entry's stored bytes to stdout. Matched against
    /// the manifest, never joined to a path.
    #[arg(long, requires = "scratch", value_name = "REL")]
    pub file: Option<std::ffi::OsString>,
}

pub fn run(env: &Env, args: &ReadArgs, json: bool) -> Result<i32> {
    if args.scratch {
        return scratch::run(env, args, json);
    }
    let cat = catalog::open_env_read(env)?.catalog;

    if args.raw {
        return read_raw(env, &cat, &args.session);
    }

    if let Some(entry_uuid) = &args.entry {
        return match cat.entry_by_uuid(&args.session, entry_uuid)? {
            Some(row) => {
                emit_entries(std::slice::from_ref(&row), json);
                Ok(EXIT_OK)
            }
            None => {
                eprintln!(
                    "entry {entry_uuid} not found in session {} (run `yomi index` if not yet indexed)",
                    args.session
                );
                Ok(EXIT_PARTIAL)
            }
        };
    }

    let rows = cat.entries_for_session(&args.session, args.agents)?;
    let filtered: Vec<EntryRow> = match &args.grep {
        Some(needle) => rows
            .into_iter()
            .filter(|r| r.text.contains(needle))
            .collect(),
        None => rows,
    };
    if filtered.is_empty() {
        eprintln!(
            "no indexed entries for session {} (run `yomi index`, or use --raw for the stored transcript)",
            args.session
        );
        return Ok(EXIT_PARTIAL);
    }
    emit_entries(&filtered, json);
    Ok(EXIT_OK)
}

/// Decompress and print the stored transcript (and, per session, subagent)
/// artifacts. Independent of the index, so it works before `yomi index` runs.
fn read_raw(env: &Env, cat: &catalog::Catalog, session: &str) -> Result<i32> {
    let archive_dir = env.archive_dir();
    let mut printed = false;
    for c in cat.index_candidates_for_session(session)? {
        if c.role != "transcript" && c.role != "subagent" {
            continue;
        }
        let Ok(raw) = std::fs::read(archive_dir.join(&c.stored_path)) else {
            continue;
        };
        let Ok(text) = decompress_all(&raw) else {
            continue;
        };
        print!("{}", String::from_utf8_lossy(&text));
        printed = true;
    }
    if !printed {
        eprintln!("no stored transcript for session {session}");
        return Ok(EXIT_PARTIAL);
    }
    Ok(EXIT_OK)
}

fn emit_entries(rows: &[EntryRow], json: bool) {
    if json {
        let items: Vec<_> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "entry_uuid": r.entry_uuid,
                    "parent_uuid": r.parent_uuid,
                    "role": r.role,
                    "agent": r.agent,
                    "tool": r.tool_name,
                    "timestamp": r.timestamp,
                    "has_redaction": r.has_redaction,
                    "text": r.text,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&items).unwrap_or_default()
        );
        return;
    }
    for r in rows {
        let ts = r.timestamp.as_deref().unwrap_or("-");
        let tool = r
            .tool_name
            .as_deref()
            .map(|t| format!("/{t}"))
            .unwrap_or_default();
        let redacted = if r.has_redaction { " [redacted]" } else { "" };
        println!("── {} · {}{} · {ts}{redacted}", r.role, r.agent, tool);
        println!("{}", r.text);
        println!();
    }
}

/// `yomi read --scratch` — the retrieval half of "scratch is archived, not
/// disposable". GC deletes a scratch tree because the archive covers it; an
/// archive with no retrieval path is not an archive.
mod scratch {
    use super::{EXIT_OK, EXIT_PARTIAL};
    use crate::config::Env;
    use crate::scratch::{ScratchEntry, ScratchManifest, ScratchStore, StoredEntry};
    use anyhow::Result;
    use std::io::Write;

    pub fn run(env: &Env, args: &super::ReadArgs, json: bool) -> Result<i32> {
        let store =
            match ScratchStore::open(&env.archive_dir(), std::ffi::OsStr::new(&args.session)) {
                Ok(s) => s,
                Err(e) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "error": e.code(), "reason": e.reason(),
                            }))?
                        );
                    } else {
                        eprintln!("refuse: {}", e.reason());
                    }
                    return Ok(EXIT_PARTIAL);
                }
            };
        match &args.file {
            Some(rel) => emit_file(env, &store, rel, json),
            None => {
                emit_listing(&store, json)?;
                Ok(EXIT_OK)
            }
        }
    }

    /// Why an entry's bytes are not in the store. Never a bare "not found": the
    /// reader's question is *why*.
    ///
    /// Precedence follows the order archive applies its decisions — a denylisted
    /// inode and a capture failure both mean *nothing was read* and outrank
    /// policy; the tree cap outranks the per-file rules; the recorded policy
    /// cause answers the rest.
    ///
    /// Only the last step can fall back to inference, and only for a manifest
    /// written before the cause was recorded. That path is **labelled in the
    /// output**, because inferring from the config in force *now* is exactly how
    /// a widened `file_cap` made yomi blame the globs for a rejection they had
    /// no part in.
    fn not_stored_reason(env: &Env, mf: &ScratchManifest, e: &ScratchEntry) -> String {
        if e.blacklisted {
            return "its inode is on the compiled-in denylist, so it was never opened — \
                    §4 forbids opening a blacklisted path for read or delete"
                .into();
        }
        if e.capture_failed {
            return "the capture failed — nothing of this file was ever read (an I/O or \
                    permission error, a denylisted inode, or a file past the read bound). \
                    Re-run `yomi archive` once it is readable"
                .into();
        }
        if mf.over_total_cap {
            // The measured quantity comes from the ledger and the cap from the
            // config, because only one of the two was ever written down. Saying
            // which bytes were summed matters here: the cap counts what the globs
            // admit, so an operator looking at a tree whose bulk is `target/` is
            // otherwise sent to measure the wrong thing.
            let measured = match mf.admitted_bytes {
                Some(n) => format!("{n} bytes of admitted content in this tree"),
                None => "this tree's admitted content".to_string(),
            };
            return format!(
                "{measured} exceeded [scratch] total_cap ({} bytes as it stands \
                 now), so the whole tree was manifested without storing anything",
                env.config.scratch.total_cap.0
            );
        }
        if let Some(cause) = e.not_stored {
            return cause.reason().to_string();
        }
        // Pre-`not_stored` manifest: the cause was never written down, so this is
        // a guess made from a config that may not be the one that produced the
        // entry. Say so rather than assert it.
        let file_cap = env.config.scratch.file_cap.0;
        let guess = if e.bytes > file_cap {
            format!("{} bytes is over [scratch] file_cap ({file_cap})", e.bytes)
        } else {
            "the [scratch] allow/deny globs did not admit it".into()
        };
        format!(
            "{guess} — inferred from the current config, because this manifest predates \
             the recorded reason; re-run `yomi archive` to record it"
        )
    }

    fn emit_file(
        env: &Env,
        store: &ScratchStore,
        rel: &std::ffi::OsStr,
        json: bool,
    ) -> Result<i32> {
        let Some(found) = store.find(rel) else {
            let shown = rel.to_string_lossy();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "error": "NotFound",
                        "reason": format!("no manifest entry named {shown}"),
                    }))?
                );
            } else {
                eprintln!(
                    "not found: no manifest entry named {shown} in {}",
                    store.key()
                );
            }
            return Ok(EXIT_PARTIAL);
        };
        if !found.entry().stored {
            let reason = not_stored_reason(env, store.manifest(), found.entry());
            let (shown, hex) = found.rel().manifest_fields();
            if json {
                let mut v = serde_json::json!({
                    "error": "NotStored", "rel": shown, "reason": reason,
                });
                if let Some(h) = hex {
                    v["rel_hex"] = serde_json::Value::String(h);
                }
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                eprintln!("not stored: {shown} — {reason}");
            }
            return Ok(EXIT_PARTIAL);
        }
        // A store defect is not a tool failure: exit 1 is reserved for "yomi
        // failed", and nothing here did — the bytes are simply not there to
        // hand over. The refusal joins the same `{error, reason}` vocabulary
        // every other one in this command uses, and names no cause it cannot
        // establish.
        let bytes = match found.read() {
            Ok(b) => b,
            Err(e) => {
                let (shown, hex) = found.rel().manifest_fields();
                if json {
                    let mut v = serde_json::json!({
                        "error": e.code(), "rel": shown, "reason": e.reason(),
                    });
                    if let Some(h) = hex {
                        v["rel_hex"] = serde_json::Value::String(h);
                    }
                    println!("{}", serde_json::to_string_pretty(&v)?);
                } else {
                    eprintln!("{}: {shown} — {}", e.code(), e.reason());
                }
                return Ok(EXIT_PARTIAL);
            }
        };
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&file_json(&found, &bytes))?
            );
        } else {
            // Written raw: a scratch file may be binary, and a lossy string
            // conversion would silently corrupt it.
            std::io::stdout().write_all(&bytes)?;
            std::io::stdout().flush()?;
        }
        Ok(EXIT_OK)
    }

    fn file_json(found: &StoredEntry<'_>, bytes: &[u8]) -> serde_json::Value {
        let (rel, rel_hex) = found.rel().manifest_fields();
        // `utf8` verbatim, else hex — the same encoder `path_hex` uses, so
        // `--json` adds no dependency and never puts invalid UTF-8 inside a JSON
        // string.
        let (encoding, content) = match std::str::from_utf8(bytes) {
            Ok(s) => ("utf8", s.to_string()),
            Err(_) => ("hex", crate::util::hex(bytes)),
        };
        // `content_bytes`, not `bytes`: the listing's `bytes` is the manifest
        // value — the live source's size before redaction — and one name may not
        // carry two claims in one command's output. Redaction makes the two
        // genuinely differ.
        let mut v = serde_json::json!({
            "rel": rel,
            "content_bytes": bytes.len(),
            "encoding": encoding,
            "content": content,
        });
        if let Some(h) = rel_hex {
            v["rel_hex"] = serde_json::Value::String(h);
        }
        v
    }

    /// `quarantined` is deliberately not among these fields. This command's
    /// non-exposure boundary is that it never opens, names, or points at
    /// `quarantine/`, and under the mirror rule (§4) an entry's quarantine path
    /// is derivable from its own identity — so a per-entry "an original is over
    /// there" flag is a pointer at the tree. The stored bytes already answer the
    /// reader's question: a quarantined entry reads back as the opaque marker.
    fn entry_json(e: &ScratchEntry) -> serde_json::Value {
        let mut v = serde_json::json!({
            "rel": e.path,
            "bytes": e.bytes,
            "stored": e.stored,
            "present": e.present,
            "capture_failed": e.capture_failed,
            "blacklisted": e.blacklisted,
            "not_stored": e.not_stored.map(|c| c.as_str()),
            "source_sha256": e.source_sha256,
            "content_sha256": e.content_sha256,
        });
        // The lossy `rel` above cannot be handed back to `--file`; this says
        // exactly which bytes to pass.
        if let Some(h) = &e.path_hex {
            v["rel_hex"] = serde_json::Value::String(h.clone());
        }
        v
    }

    fn emit_listing(store: &ScratchStore, json: bool) -> Result<()> {
        let mf = store.manifest();
        if json {
            let v = serde_json::json!({
                "key": store.key(),
                "captured_at": mf.captured_at,
                "total_bytes": mf.total_bytes,
                "admitted_bytes": mf.admitted_bytes,
                "over_total_cap": mf.over_total_cap,
                "entries": mf.entries.iter().map(entry_json).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&v)?);
            return Ok(());
        }
        // Both totals, because the flag is a verdict on the second one: a tree
        // reading "4,466,661,813 bytes  [over total_cap]" invites the conclusion
        // that a 64MB cap is hopeless for it, when the figure the cap compared may
        // have been a few MB of notes.
        let admitted = match mf.admitted_bytes {
            Some(n) => format!("  {n} admitted"),
            None => String::new(),
        };
        println!(
            "scratch {}  captured {}  {} bytes{admitted}{}",
            store.key(),
            mf.captured_at,
            mf.total_bytes,
            if mf.over_total_cap {
                "  [over total_cap: manifest-only]"
            } else {
                ""
            }
        );
        for e in &mf.entries {
            // `present` and `capture_failed` are shown rather than folded into
            // `stored`: they are the two states where "why can I not get these
            // bytes?" has a different answer and a different remedy.
            let mut flags = Vec::new();
            flags.push(if e.stored { "stored" } else { "not stored" });
            if !e.present {
                flags.push("absent from the live tree");
            }
            if e.capture_failed {
                flags.push("capture failed");
            }
            // Named here because a denylisted name is why its tree is refused
            // forever, and the refusal was otherwise reported nowhere a human
            // looks (D-S5).
            if e.blacklisted {
                flags.push("denylisted");
            }
            println!("  {:>10}  {}  [{}]", e.bytes, e.path, flags.join(", "));
        }
        Ok(())
    }
}
