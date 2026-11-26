//! Layer 2 streaming host session log analyzer (Claude Code `.jsonl` files).
//!
//! Constitutional guarantees:
//! - Strictly streams every file line-by-line via `BufReader` + [`read_bounded_line`]
//!   with a per-line RAM cap (never `fs::read`).
//! - UTF-8-safe handling on truncated oversized lines (zero char-boundary panics).
//! - 4 locked regression guards:
//!   1. `big_file_reads` counts ONLY file-read tools (> 20,000 chars), never Bash/Grep/WebFetch.
//!   2. `repeated_overlapping_reads` checks `(file_path, start_line..=end_line)` overlap,
//!      so sequential `offset`/`limit` chunks never trigger false alarms.
//!   3. Subagent paths `.../<project>/<session>/subagents/agent-*.jsonl` resolve `<project>`.
//!   4. `mcp__klens__*` tool uses are tracked as first-class `klens_calls`.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde_json::Value;

use crate::error::KlensError;
use crate::telemetry::types::{
    BIG_FILE_READ_CHAR_THRESHOLD, HostTotals, LineReadOutcome, ModelUsage, SessionSummary,
    read_bounded_line, utf8_safe_prefix,
};
use crate::time::{UtcParts, parse_iso8601_utc_secs};

/// Full, untruncated Layer 2 aggregation result.
#[derive(Debug, Clone, Default)]
pub(crate) struct Layer2Aggregate {
    pub host_logs_connected: bool,
    pub host_totals: Option<HostTotals>,
    pub host_klens_calls: u64,
    pub by_model: Vec<ModelUsage>,
    pub recent_sessions: Vec<SessionSummary>,
}

#[derive(Debug, Clone)]
struct TrackedToolUse {
    name: String,
}

#[derive(Debug, Default)]
struct DedupMessageUsage {
    base_in: u64,
    cache_create: u64,
    cache_read: u64,
    output: u64,
    has_usage: bool,
    model: Option<String>,
}

#[derive(Debug, Default)]
struct ParsedSession {
    session_id: String,
    project: String,
    is_subagent: bool,
    latest_ts: Option<i64>,
    input_tokens: u64,
    fresh_input_tokens: u64,
    cache_creation_tokens: u64,
    cache_read_tokens: u64,
    output_tokens: u64,
    peak_context_tokens: u64,
    big_file_reads: u64,
    repeated_overlapping_reads: u64,
    klens_calls: u64,
    model_tokens: BTreeMap<String, u64>,
}

/// Extract `(project_name, is_subagent)` from a Claude Code `.jsonl` log path.
///
/// Correctly handles both standard and subagent layouts on Windows and Unix:
/// - `projects/MyApp/sess-1/subagents/agent-2.jsonl` -> `("MyApp", true)`
/// - `~/.claude/projects/MyApp/sess-1.jsonl` -> `("MyApp", false)`
/// - `MyApp/sess-1/subagents/agent-2.jsonl` -> `("MyApp", true)`
pub fn extract_project_name_from_log_path(path: &Path) -> (String, bool) {
    let comps: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(os) => Some(os.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();

    if comps.len() < 2 {
        return ("unknown".to_string(), false);
    }

    let is_subagent = comps
        .get(comps.len().saturating_sub(2))
        .is_some_and(|parent| parent.eq_ignore_ascii_case("subagents"));

    // Prefer the segment immediately following the last `"projects"` directory.
    if let Some(proj_idx) = comps
        .iter()
        .rposition(|c| c.eq_ignore_ascii_case("projects"))
        && proj_idx + 1 < comps.len() - 1
    {
        let candidate = &comps[proj_idx + 1];
        if !candidate.eq_ignore_ascii_case("subagents") && !candidate.is_empty() {
            return (candidate.clone(), is_subagent);
        }
    }

    // Fallback when no `"projects"` ancestor exists:
    // `<project>/<session>/subagents/agent-*.jsonl` -> index `len - 4`.
    if is_subagent && comps.len() >= 4 {
        return (comps[comps.len() - 4].clone(), true);
    }

    let fallback = comps[comps.len() - 2].clone();
    if fallback.eq_ignore_ascii_case("subagents") {
        ("unknown".to_string(), true)
    } else {
        (fallback, is_subagent)
    }
}

/// Returns `true` if `tool_name` is a direct file-reading tool (and NOT Bash/Grep/WebFetch).
pub fn is_file_read_tool(tool_name: &str) -> bool {
    matches!(
        tool_name.trim().to_ascii_lowercase().as_str(),
        "read" | "read_file" | "view_file" | "file_read" | "readfile"
    )
}

/// Returns `true` if `tool_name` is a Karasu Lens MCP tool call (`mcp__klens__*`).
pub fn is_klens_mcp_tool(tool_name: &str) -> bool {
    let lower = tool_name.trim().to_ascii_lowercase();
    lower.starts_with("mcp__klens__")
}

/// Returns `true` if a model identifier is a synthetic placeholder (e.g. `<synthetic>` or `synthetic`).
fn is_synthetic_model(model: &str) -> bool {
    let trimmed = model.trim();
    trimmed.eq_ignore_ascii_case("<synthetic>") || trimmed.eq_ignore_ascii_case("synthetic")
}

/// Stream and aggregate all `.jsonl` session files under `claude_projects_dir`.
pub(crate) fn aggregate_layer2_host_logs(
    claude_projects_dir: &Path,
    cutoff_unix_secs: Option<i64>,
    project_filter: Option<&str>,
    max_line_bytes: usize,
    recent_limit: usize,
) -> Result<Layer2Aggregate, KlensError> {
    if !claude_projects_dir.is_dir() {
        return Ok(Layer2Aggregate::default());
    }

    let mut jsonl_files = Vec::new();
    collect_jsonl_files(claude_projects_dir, &mut jsonl_files);
    jsonl_files.sort();

    if jsonl_files.is_empty() {
        return Ok(Layer2Aggregate::default());
    }

    let mut totals = HostTotals::default();
    let mut host_klens_calls = 0u64;
    // model_name -> (session_count, total_tokens)
    let mut model_agg: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut all_sessions: Vec<(i64, SessionSummary)> = Vec::new();

    for path in &jsonl_files {
        let Ok(session) = parse_session_file_streaming(path, max_line_bytes) else {
            continue;
        };

        let ts = session
            .latest_ts
            .or_else(|| file_mtime_unix_secs(path))
            .unwrap_or(0);

        if let Some(cutoff) = cutoff_unix_secs
            && ts < cutoff
        {
            continue;
        }

        if !matches_host_project_filter(&session.project, project_filter) {
            continue;
        }

        totals.sessions_count = totals.sessions_count.saturating_add(1);
        totals.total_input_tokens = totals
            .total_input_tokens
            .saturating_add(session.input_tokens);
        totals.fresh_input_tokens = totals
            .fresh_input_tokens
            .saturating_add(session.fresh_input_tokens);
        totals.cache_creation_tokens = totals
            .cache_creation_tokens
            .saturating_add(session.cache_creation_tokens);
        totals.cache_read_tokens = totals
            .cache_read_tokens
            .saturating_add(session.cache_read_tokens);
        totals.total_output_tokens = totals
            .total_output_tokens
            .saturating_add(session.output_tokens);
        totals.peak_context_tokens = totals.peak_context_tokens.max(session.peak_context_tokens);
        totals.big_file_reads = totals.big_file_reads.saturating_add(session.big_file_reads);
        totals.repeated_overlapping_reads = totals
            .repeated_overlapping_reads
            .saturating_add(session.repeated_overlapping_reads);

        host_klens_calls = host_klens_calls.saturating_add(session.klens_calls);

        for (model, tokens) in &session.model_tokens {
            let entry = model_agg.entry(model.clone()).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(1);
            entry.1 = entry.1.saturating_add(*tokens);
        }

        let primary_model = session
            .model_tokens
            .iter()
            .max_by(|(m_a, t_a), (m_b, t_b)| t_a.cmp(t_b).then_with(|| m_b.cmp(m_a)))
            .map(|(m, _)| m.clone());

        let summary = SessionSummary {
            session_id: session.session_id,
            project: session.project,
            timestamp_utc: UtcParts::from_unix_secs(ts, 0).to_iso8601(),
            model: primary_model,
            input_tokens: session.input_tokens,
            output_tokens: session.output_tokens,
            peak_context_tokens: session.peak_context_tokens,
            big_file_reads: session.big_file_reads,
            repeated_overlapping_reads: session.repeated_overlapping_reads,
            klens_calls: session.klens_calls,
            is_subagent: session.is_subagent,
        };
        all_sessions.push((ts, summary));
    }

    // Deterministic sort: newest first, tie-break by session_id ascending.
    all_sessions.sort_by(|(ts_a, s_a), (ts_b, s_b)| {
        ts_b.cmp(ts_a)
            .then_with(|| s_a.session_id.cmp(&s_b.session_id))
    });

    let recent_sessions: Vec<SessionSummary> = all_sessions
        .into_iter()
        .take(recent_limit)
        .map(|(_, summary)| summary)
        .collect();

    let mut by_model: Vec<ModelUsage> = model_agg
        .into_iter()
        .map(|(model, (sessions, tokens))| ModelUsage {
            model,
            sessions,
            tokens,
        })
        .collect();
    // Deterministic sort: highest tokens first, tie-break by model name ascending.
    by_model.sort_by(|a, b| b.tokens.cmp(&a.tokens).then_with(|| a.model.cmp(&b.model)));

    Ok(Layer2Aggregate {
        host_logs_connected: true,
        host_totals: Some(totals),
        host_klens_calls,
        by_model,
        recent_sessions,
    })
}

fn collect_jsonl_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut children: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|x| x.path())).collect();
    children.sort();

    for path in children {
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            collect_jsonl_files(&path, out);
        } else if meta.is_file()
            && path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"))
        {
            out.push(path);
        }
    }
}

fn file_mtime_unix_secs(path: &Path) -> Option<i64> {
    let meta = fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let dur = modified.duration_since(UNIX_EPOCH).ok()?;
    Some(dur.as_secs() as i64)
}

fn parse_session_file_streaming(
    path: &Path,
    max_line_bytes: usize,
) -> Result<ParsedSession, KlensError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buf = Vec::new();

    let (project, is_subagent) = extract_project_name_from_log_path(path);
    let fallback_session_id = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("session")
        .to_string();

    let mut session = ParsedSession {
        session_id: fallback_session_id,
        project,
        is_subagent,
        ..ParsedSession::default()
    };

    let mut tool_uses: HashMap<String, TrackedToolUse> = HashMap::new();
    let mut read_ranges: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
    let mut dedup_messages: HashMap<String, DedupMessageUsage> = HashMap::new();

    loop {
        match read_bounded_line(&mut reader, &mut buf, max_line_bytes)? {
            LineReadOutcome::Eof => break,
            LineReadOutcome::Truncated { .. } => {
                // Validate UTF-8 prefix safely (guarantees zero char-boundary panics)
                // and skip this oversized record; `read_bounded_line` already drained to `\n`.
                let _safe_prefix = utf8_safe_prefix(&buf);
                continue;
            }
            LineReadOutcome::Complete => {
                let text = utf8_safe_prefix(&buf).trim();
                if text.is_empty() {
                    continue;
                }
                let Ok(val) = serde_json::from_str::<Value>(text) else {
                    continue;
                };
                process_log_record(
                    &val,
                    &mut session,
                    &mut tool_uses,
                    &mut read_ranges,
                    &mut dedup_messages,
                );
            }
        }
    }

    // Fold deduplicated streaming messages exactly once per unique `message.id`.
    for msg in dedup_messages.into_values() {
        if msg.has_usage {
            record_turn_usage(
                &mut session,
                msg.base_in,
                msg.cache_create,
                msg.cache_read,
                msg.output,
                msg.model.as_deref(),
            );
        } else if let Some(model) = msg.model {
            session.model_tokens.entry(model).or_insert(0);
        }
    }

    Ok(session)
}

fn record_turn_usage(
    session: &mut ParsedSession,
    base_in: u64,
    cache_create: u64,
    cache_read: u64,
    output: u64,
    model_opt: Option<&str>,
) {
    let turn_input = base_in
        .saturating_add(cache_create)
        .saturating_add(cache_read);

    session.fresh_input_tokens = session.fresh_input_tokens.saturating_add(base_in);
    session.cache_creation_tokens = session.cache_creation_tokens.saturating_add(cache_create);
    session.cache_read_tokens = session.cache_read_tokens.saturating_add(cache_read);
    session.input_tokens = session.input_tokens.saturating_add(turn_input);
    session.output_tokens = session.output_tokens.saturating_add(output);
    session.peak_context_tokens = session.peak_context_tokens.max(turn_input);

    if let Some(model) = model_opt
        && !is_synthetic_model(model)
    {
        let entry = session.model_tokens.entry(model.to_string()).or_insert(0);
        *entry = entry.saturating_add(turn_input.saturating_add(output));
    }
}

fn process_log_record(
    val: &Value,
    session: &mut ParsedSession,
    tool_uses: &mut HashMap<String, TrackedToolUse>,
    read_ranges: &mut HashMap<String, Vec<(usize, usize)>>,
    dedup_messages: &mut HashMap<String, DedupMessageUsage>,
) {
    if let Some(ts_str) = val.get("timestamp").and_then(Value::as_str)
        && let Some(secs) = parse_iso8601_utc_secs(ts_str)
    {
        session.latest_ts = Some(session.latest_ts.map_or(secs, |prev| prev.max(secs)));
    }

    if let Some(sid) = val.get("sessionId").and_then(Value::as_str)
        && !sid.trim().is_empty()
        && !session.is_subagent
    {
        session.session_id = sid.trim().to_string();
    }

    let message = val.get("message");
    let message_id_opt = message
        .and_then(|m| m.get("id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());

    // Extract usage & model metrics (filtering out synthetic placeholder models).
    let usage_opt = message
        .and_then(|m| m.get("usage"))
        .or_else(|| val.get("usage"));
    let model_opt = message
        .and_then(|m| m.get("model"))
        .and_then(Value::as_str)
        .or_else(|| val.get("model").and_then(Value::as_str))
        .map(str::trim)
        .filter(|s| !s.is_empty() && !is_synthetic_model(s));

    if let Some(msg_id) = message_id_opt {
        if usage_opt.is_some() || model_opt.is_some() {
            let entry = dedup_messages.entry(msg_id.to_string()).or_default();
            if let Some(usage) = usage_opt {
                let base_in = usage
                    .get("input_tokens")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let cache_create = usage
                    .get("cache_creation_input_tokens")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let cache_read = usage
                    .get("cache_read_input_tokens")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let output = usage
                    .get("output_tokens")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);

                entry.base_in = entry.base_in.max(base_in);
                entry.cache_create = entry.cache_create.max(cache_create);
                entry.cache_read = entry.cache_read.max(cache_read);
                entry.output = entry.output.max(output);
                entry.has_usage = true;
            }
            if let Some(model) = model_opt {
                entry.model = Some(model.to_string());
            }
        }
    } else if let Some(usage) = usage_opt {
        let base_in = usage
            .get("input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let cache_create = usage
            .get("cache_creation_input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let cache_read = usage
            .get("cache_read_input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let output = usage
            .get("output_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        record_turn_usage(
            session,
            base_in,
            cache_create,
            cache_read,
            output,
            model_opt,
        );
    } else if let Some(model) = model_opt {
        session.model_tokens.entry(model.to_string()).or_insert(0);
    }

    // Inspect content blocks (`tool_use` and `tool_result`).
    let content_blocks = message
        .and_then(|m| m.get("content"))
        .and_then(Value::as_array)
        .or_else(|| val.get("content").and_then(Value::as_array));

    let Some(blocks) = content_blocks else {
        return;
    };

    for block in blocks {
        let Some(block_type) = block.get("type").and_then(Value::as_str) else {
            continue;
        };

        match block_type {
            "tool_use" => handle_tool_use(block, session, tool_uses, read_ranges),
            "tool_result" => handle_tool_result(block, session, tool_uses),
            _ => {}
        }
    }
}

fn handle_tool_use(
    block: &Value,
    session: &mut ParsedSession,
    tool_uses: &mut HashMap<String, TrackedToolUse>,
    read_ranges: &mut HashMap<String, Vec<(usize, usize)>>,
) {
    let Some(name) = block.get("name").and_then(Value::as_str) else {
        return;
    };

    if let Some(id) = block.get("id").and_then(Value::as_str) {
        tool_uses.insert(
            id.to_string(),
            TrackedToolUse {
                name: name.to_string(),
            },
        );
    }

    if is_klens_mcp_tool(name) {
        session.klens_calls = session.klens_calls.saturating_add(1);
    }

    if is_file_read_tool(name)
        && let Some(input) = block.get("input")
        && let Some(raw_path) = input
            .get("file_path")
            .or_else(|| input.get("path"))
            .and_then(Value::as_str)
    {
        let norm_path = normalize_tracked_path(raw_path);
        let range = extract_read_line_range(input);
        let seen = read_ranges.entry(norm_path).or_default();
        if seen.iter().any(|&prev| ranges_overlap(prev, range)) {
            session.repeated_overlapping_reads =
                session.repeated_overlapping_reads.saturating_add(1);
        }
        seen.push(range);
    }
}

fn handle_tool_result(
    block: &Value,
    session: &mut ParsedSession,
    tool_uses: &HashMap<String, TrackedToolUse>,
) {
    let Some(tool_use_id) = block.get("tool_use_id").and_then(Value::as_str) else {
        return;
    };
    let Some(tracked) = tool_uses.get(tool_use_id) else {
        return;
    };

    // Regression Lock 1: ONLY direct file-read tools count toward `big_file_reads`.
    if !is_file_read_tool(&tracked.name) {
        return;
    }

    let char_count = count_tool_result_chars(block.get("content"));
    if char_count > BIG_FILE_READ_CHAR_THRESHOLD {
        session.big_file_reads = session.big_file_reads.saturating_add(1);
    }
}

fn count_tool_result_chars(content: Option<&Value>) -> usize {
    match content {
        Some(Value::String(s)) => s.chars().count(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| {
                item.get("text")
                    .and_then(Value::as_str)
                    .or_else(|| item.as_str())
            })
            .map(|s| s.chars().count())
            .sum(),
        _ => 0,
    }
}

fn normalize_tracked_path(raw: &str) -> String {
    let replaced = raw.trim().replace('\\', "/");
    replaced.strip_prefix("./").unwrap_or(&replaced).to_string()
}

/// Extract an inclusive 1-based `(start_line, end_line)` range from a file-read tool's input.
///
/// Supports Claude Code `offset`/`limit`, `start_line`/`end_line`, and `lines: "start:end"`.
/// Unbounded whole-file reads map to `(1, usize::MAX)`.
fn extract_read_line_range(input: &Value) -> (usize, usize) {
    let offset = input.get("offset").and_then(Value::as_u64);
    let limit = input.get("limit").and_then(Value::as_u64);
    if offset.is_some() || limit.is_some() {
        let start = offset.unwrap_or(1).max(1) as usize;
        let end = match limit {
            Some(l) if l > 0 => start.saturating_add((l as usize).saturating_sub(1)),
            _ => usize::MAX,
        };
        return (start, end);
    }

    let start_line = input.get("start_line").and_then(Value::as_u64);
    let end_line = input.get("end_line").and_then(Value::as_u64);
    if start_line.is_some() || end_line.is_some() {
        let start = start_line.unwrap_or(1).max(1) as usize;
        let end = end_line.map_or(usize::MAX, |e| (e as usize).max(start));
        return (start, end);
    }

    if let Some(lines_spec) = input.get("lines").and_then(Value::as_str)
        && let Some((a, b)) = lines_spec
            .split_once(':')
            .or_else(|| lines_spec.split_once('-'))
        && let (Ok(s), Ok(e)) = (a.trim().parse::<usize>(), b.trim().parse::<usize>())
        && s >= 1
        && e >= s
    {
        return (s, e);
    }

    (1, usize::MAX)
}

const fn ranges_overlap(a: (usize, usize), b: (usize, usize)) -> bool {
    a.0 <= b.1 && b.0 <= a.1
}

fn matches_host_project_filter(session_project: &str, filter: Option<&str>) -> bool {
    let Some(f) = filter else {
        return true;
    };
    if f.eq_ignore_ascii_case("all") || f.is_empty() {
        return true;
    }
    if session_project.eq_ignore_ascii_case(f) {
        return true;
    }
    // Support Claude Code's encoded path directories (e.g. `C--Users-foo-MyApp` matching `MyApp`).
    let proj_lower = session_project.to_ascii_lowercase();
    let f_lower = f.to_ascii_lowercase();
    proj_lower.ends_with(&format!("-{f_lower}")) || proj_lower.ends_with(&format!("_{f_lower}"))
}
