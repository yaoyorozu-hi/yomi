//! JSONL transcript parser: decompressed redacted bytes → per-entry docs. Pure,
//! no I/O. Never panics and never propagates a parse error — a malformed line is
//! skipped and counted, so a single corrupt line can never abort an index run.

use serde_json::Value;

/// The conversational role of a parsed doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryRole {
    User,
    Assistant,
    ToolResult,
    System,
    Summary,
}

impl EntryRole {
    pub fn as_str(self) -> &'static str {
        match self {
            EntryRole::User => "user",
            EntryRole::Assistant => "assistant",
            EntryRole::ToolResult => "tool_result",
            EntryRole::System => "system",
            EntryRole::Summary => "summary",
        }
    }
}

/// One parsed JSONL entry. `entry_uuid` is empty when the source line carried no
/// `uuid`; the caller substitutes a synthetic `line:<artifact>:<seq>` id.
pub struct ParsedEntry {
    pub entry_uuid: String,
    pub parent_uuid: Option<String>,
    pub role: EntryRole,
    pub tool_name: Option<String>,
    pub timestamp: Option<String>,
    pub text: String,
    pub seq: u64,
}

/// Per-tool_use input keys promoted into the indexed text of an assistant entry,
/// in this fixed order. Bounded to short scalars — the full input JSON is never
/// stringified into the index.
const TOOL_INPUT_KEYS: [&str; 5] = ["command", "file_path", "description", "pattern", "path"];

/// Upper bound on the rendered text contributed by a single tool_use block.
const TOOL_USE_TEXT_CAP: usize = 4096;

/// Parse a decompressed, redacted transcript/subagent JSONL blob into per-line
/// docs. Returns the docs (empty-text lines dropped) and the count of lines that
/// failed to parse or were skipped as non-conversational noise-with-error.
pub fn parse_transcript(bytes: &[u8]) -> (Vec<ParsedEntry>, u64) {
    let text = String::from_utf8_lossy(bytes);
    let raw_lines: Vec<&str> = text.lines().collect();

    let mut values: Vec<Option<Value>> = Vec::with_capacity(raw_lines.len());
    let mut skipped = 0u64;
    for line in &raw_lines {
        if line.trim().is_empty() {
            values.push(None);
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(v) => values.push(Some(v)),
            Err(_) => {
                skipped += 1;
                tracing::debug!("index parse: skipped malformed JSONL line");
                values.push(None);
            }
        }
    }

    let tool_names = tool_name_map(&values);

    let mut out = Vec::new();
    for (seq, value) in values.iter().enumerate() {
        let Some(v) = value else { continue };
        if let Some(entry) = parse_line(v, seq as u64, &tool_names) {
            if entry.text.trim().is_empty() {
                continue;
            }
            out.push(entry);
        }
    }
    (out, skipped)
}

/// Build a `tool_use_id → tool_name` map from every assistant `tool_use` block,
/// so a later `tool_result` line can inherit the name of the tool it answers.
fn tool_name_map(values: &[Option<Value>]) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for value in values.iter().flatten() {
        if value.get("type").and_then(Value::as_str) != Some("assistant") {
            continue;
        }
        let Some(blocks) = value.pointer("/message/content").and_then(Value::as_array) else {
            continue;
        };
        for b in blocks {
            if b.get("type").and_then(Value::as_str) == Some("tool_use")
                && let (Some(id), Some(name)) = (
                    b.get("id").and_then(Value::as_str),
                    b.get("name").and_then(Value::as_str),
                )
            {
                map.insert(id.to_string(), name.to_string());
            }
        }
    }
    map
}

fn parse_line(
    v: &Value,
    seq: u64,
    tool_names: &std::collections::HashMap<String, String>,
) -> Option<ParsedEntry> {
    let ty = v.get("type").and_then(Value::as_str)?;
    let entry_uuid = v
        .get("uuid")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let parent_uuid = v
        .get("parentUuid")
        .and_then(Value::as_str)
        .map(str::to_string);
    let timestamp = v
        .get("timestamp")
        .and_then(Value::as_str)
        .map(str::to_string);

    let (role, text, tool_name) = match ty {
        "user" => user_entry(v, tool_names)?,
        "assistant" => assistant_entry(v)?,
        "system" => (EntryRole::System, system_text(v)?, None),
        "summary" => (
            EntryRole::Summary,
            v.get("summary").and_then(Value::as_str)?.to_string(),
            None,
        ),
        _ => return None,
    };

    Some(ParsedEntry {
        entry_uuid,
        parent_uuid,
        role,
        tool_name,
        timestamp,
        text,
        seq,
    })
}

fn user_entry(
    v: &Value,
    tool_names: &std::collections::HashMap<String, String>,
) -> Option<(EntryRole, String, Option<String>)> {
    let content = v.pointer("/message/content")?;
    if let Some(s) = content.as_str() {
        return Some((EntryRole::User, s.to_string(), None));
    }
    let blocks = content.as_array()?;

    let has_tool_result = blocks
        .iter()
        .any(|b| b.get("type").and_then(Value::as_str) == Some("tool_result"));
    if has_tool_result {
        let mut parts = Vec::new();
        let mut tool_name = None;
        for b in blocks {
            if b.get("type").and_then(Value::as_str) != Some("tool_result") {
                continue;
            }
            if tool_name.is_none()
                && let Some(id) = b.get("tool_use_id").and_then(Value::as_str)
            {
                tool_name = tool_names.get(id).cloned();
            }
            let mut body = flatten_block_content(b.get("content"));
            if b.get("is_error").and_then(Value::as_bool) == Some(true) {
                body = format!("[error] {body}");
            }
            if !body.trim().is_empty() {
                parts.push(body);
            }
        }
        return Some((EntryRole::ToolResult, parts.join("\n"), tool_name));
    }

    let text = concat_text_blocks(blocks);
    Some((EntryRole::User, text, None))
}

fn assistant_entry(v: &Value) -> Option<(EntryRole, String, Option<String>)> {
    let blocks = v.pointer("/message/content")?.as_array()?;
    let mut parts = Vec::new();
    let mut tool_name = None;
    for b in blocks {
        match b.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(t) = b.get("text").and_then(Value::as_str) {
                    parts.push(t.to_string());
                }
            }
            Some("thinking") => {
                if let Some(t) = b.get("thinking").and_then(Value::as_str) {
                    parts.push(t.to_string());
                }
            }
            Some("tool_use") => {
                if tool_name.is_none() {
                    tool_name = b.get("name").and_then(Value::as_str).map(str::to_string);
                }
                parts.push(render_tool_use(b));
            }
            _ => {}
        }
    }
    Some((EntryRole::Assistant, parts.join("\n"), tool_name))
}

fn system_text(v: &Value) -> Option<String> {
    if let Some(s) = v.get("content").and_then(Value::as_str) {
        return Some(s.to_string());
    }
    v.pointer("/message/content")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Render a `tool_use` block as `$<name> <short scalar inputs>`, bounded.
fn render_tool_use(b: &Value) -> String {
    let name = b.get("name").and_then(Value::as_str).unwrap_or("tool");
    let mut scalars = Vec::new();
    if let Some(input) = b.get("input").and_then(Value::as_object) {
        for key in TOOL_INPUT_KEYS {
            if let Some(val) = input.get(key)
                && let Some(s) = scalar_str(val)
            {
                scalars.push(s);
            }
        }
    }
    let mut rendered = format!("${name} {}", scalars.join(" "));
    truncate_chars(&mut rendered, TOOL_USE_TEXT_CAP);
    rendered
}

/// Flatten a block's `content` (string, or array of `{type:text,text}`) to text.
fn flatten_block_content(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(items)) => concat_text_blocks(items),
        _ => String::new(),
    }
}

fn concat_text_blocks(blocks: &[Value]) -> String {
    let mut parts = Vec::new();
    for b in blocks {
        if b.get("type").and_then(Value::as_str) == Some("text")
            && let Some(t) = b.get("text").and_then(Value::as_str)
        {
            parts.push(t.to_string());
        }
    }
    parts.join("\n")
}

fn scalar_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Truncate a string in place to at most `max` chars on a UTF-8 boundary.
fn truncate_chars(s: &mut String, max: usize) {
    if s.chars().count() <= max {
        return;
    }
    let cut = s.char_indices().nth(max).map(|(i, _)| i).unwrap_or(s.len());
    s.truncate(cut);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(v: serde_json::Value) -> String {
        v.to_string()
    }

    #[test]
    fn parse_user_string_line() {
        let blob = line(serde_json::json!({
            "type": "user",
            "uuid": "u1",
            "parentUuid": "p0",
            "timestamp": "2026-07-12T10:00:00.000Z",
            "message": {"role": "user", "content": "cargo build fails here"}
        }));
        let (docs, skipped) = parse_transcript(blob.as_bytes());
        assert_eq!(skipped, 0);
        assert_eq!(docs.len(), 1);
        let d = &docs[0];
        assert_eq!(d.role, EntryRole::User);
        assert_eq!(d.entry_uuid, "u1");
        assert_eq!(d.parent_uuid.as_deref(), Some("p0"));
        assert_eq!(d.text, "cargo build fails here");
    }

    #[test]
    fn parse_assistant_blocks() {
        let blob = line(serde_json::json!({
            "type": "assistant",
            "uuid": "a1",
            "message": {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "let me run it"},
                {"type": "text", "text": "Running the build."},
                {"type": "tool_use", "id": "t1", "name": "Bash",
                 "input": {"command": "cargo build", "description": "build"}}
            ]}
        }));
        let (docs, _) = parse_transcript(blob.as_bytes());
        assert_eq!(docs.len(), 1);
        let d = &docs[0];
        assert_eq!(d.role, EntryRole::Assistant);
        assert_eq!(d.tool_name.as_deref(), Some("Bash"));
        assert!(d.text.contains("let me run it"));
        assert!(d.text.contains("Running the build."));
        assert!(d.text.contains("cargo build"));
    }

    #[test]
    fn parse_tool_result_line() {
        let blob = [
            line(serde_json::json!({
                "type": "assistant",
                "uuid": "a1",
                "message": {"role": "assistant", "content": [
                    {"type": "tool_use", "id": "toolu_9", "name": "Bash", "input": {"command": "ls"}}
                ]}
            })),
            line(serde_json::json!({
                "type": "user",
                "uuid": "u2",
                "message": {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_9",
                     "is_error": true, "content": "boom: no such file"}
                ]}
            })),
        ]
        .join("\n");
        let (docs, _) = parse_transcript(blob.as_bytes());
        let tr = docs
            .iter()
            .find(|d| d.role == EntryRole::ToolResult)
            .unwrap();
        assert_eq!(tr.tool_name.as_deref(), Some("Bash"));
        assert!(tr.text.starts_with("[error] "));
        assert!(tr.text.contains("boom: no such file"));
    }

    #[test]
    fn parse_skips_noise_types() {
        let blob = [
            line(serde_json::json!({"type": "attachment", "uuid": "x1"})),
            line(serde_json::json!({"type": "queue-operation", "uuid": "x2"})),
            line(serde_json::json!({"type": "last-prompt", "uuid": "x3"})),
            line(serde_json::json!({"type": "file-history-snapshot", "uuid": "x4"})),
        ]
        .join("\n");
        let (docs, skipped) = parse_transcript(blob.as_bytes());
        assert_eq!(docs.len(), 0);
        assert_eq!(skipped, 0);
    }

    #[test]
    fn parse_malformed_line_skipped() {
        let blob = [
            line(serde_json::json!({
                "type": "user", "uuid": "u1",
                "message": {"role": "user", "content": "good"}
            })),
            "{not valid json at all".to_string(),
            line(serde_json::json!({
                "type": "user", "uuid": "u2",
                "message": {"role": "user", "content": "also good"}
            })),
        ]
        .join("\n");
        let (docs, skipped) = parse_transcript(blob.as_bytes());
        assert_eq!(skipped, 1);
        assert_eq!(docs.len(), 2);
    }

    #[test]
    fn parse_empty_text_doc_dropped() {
        let blob = line(serde_json::json!({
            "type": "assistant",
            "uuid": "a1",
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": "t1", "name": "Read", "input": {}}
            ]}
        }));
        let (docs, _) = parse_transcript(blob.as_bytes());
        // A tool_use with an empty input still renders "$Read", which is non-empty
        // and legitimately searchable by tool name; a truly empty assistant is
        // dropped.
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].text.trim(), "$Read");

        let empty = line(serde_json::json!({
            "type": "assistant",
            "uuid": "a2",
            "message": {"role": "assistant", "content": []}
        }));
        let (docs2, _) = parse_transcript(empty.as_bytes());
        assert_eq!(docs2.len(), 0);
    }

    #[test]
    fn cjk_text_preserved() {
        let blob = line(serde_json::json!({
            "type": "user", "uuid": "u1",
            "message": {"role": "user", "content": "思兼課長にビルドを依頼"}
        }));
        let (docs, _) = parse_transcript(blob.as_bytes());
        assert_eq!(docs[0].text, "思兼課長にビルドを依頼");
    }
}
