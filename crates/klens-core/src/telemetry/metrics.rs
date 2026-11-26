//! Layer 1 universal telemetry storage (`~/.klens/metrics.jsonl`).
//!
//! Records every real `klens` tool invocation across all AI clients (Antigravity,
//! Claude Code, Codex, Generic) and streams them back with `BufReader` and a strict
//! single-line memory cap.

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Write};
use std::path::Path;

use crate::error::KlensError;
use crate::telemetry::types::{LineReadOutcome, MetricEvent, read_bounded_line};
use crate::time::parse_iso8601_utc_secs;

/// Aggregated Layer 1 counters separated by whether the client is Claude Code (to prevent
/// double-counting when Layer 2 Claude session logs are also present).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Layer1Aggregate {
    pub non_claude_calls: u64,
    pub claude_calls: u64,
    pub estimated_tokens_saved: u64,
    pub runs_filtered: u64,
    pub stale_memories_caught: u64,
}

/// Size at which `metrics.jsonl` is rotated to `metrics.jsonl.1` (the previous `.1` is replaced).
pub const MAX_METRICS_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Longest stored value for client-supplied text fields (`clientInfo.name` etc.).
pub const MAX_METRIC_FIELD_CHARS: usize = 128;

/// Append a single Layer 1 [`MetricEvent`] as one compact JSON line to `metrics_path`.
///
/// Client-supplied names are capped at [`MAX_METRIC_FIELD_CHARS`] and the file is rotated at
/// [`MAX_METRICS_FILE_BYTES`], so a misbehaving MCP client cannot grow it without bound.
pub fn append_metric_event(metrics_path: &Path, event: &MetricEvent) -> Result<(), KlensError> {
    if let Some(parent) = metrics_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    if fs::metadata(metrics_path).is_ok_and(|m| m.len() > MAX_METRICS_FILE_BYTES) {
        let mut rotated = metrics_path.as_os_str().to_os_string();
        rotated.push(".1");
        fs::rename(metrics_path, rotated)?;
    }

    let cap = |s: &str| s.chars().take(MAX_METRIC_FIELD_CHARS).collect::<String>();
    let mut event = event.clone();
    event.client_name = cap(&event.client_name);
    event.client_version = cap(&event.client_version);
    event.tool = cap(&event.tool);
    event.project_name = event.project_name.as_deref().map(cap);

    let mut line = serde_json::to_string(&event)?;
    line.push('\n');

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(metrics_path)?;
    file.write_all(line.as_bytes())?;
    file.flush()?;
    Ok(())
}

/// Stream `~/.klens/metrics.jsonl` line-by-line and aggregate matching events.
pub(crate) fn aggregate_layer1_metrics(
    metrics_path: &Path,
    cutoff_unix_secs: Option<i64>,
    project_filter: Option<&str>,
    project_id_filter: Option<&str>,
    max_line_bytes: usize,
) -> Result<Layer1Aggregate, KlensError> {
    if !metrics_path.is_file() {
        return Ok(Layer1Aggregate::default());
    }

    let file = File::open(metrics_path)?;
    let mut reader = BufReader::new(file);
    let mut buf = Vec::new();
    let mut agg = Layer1Aggregate::default();

    loop {
        match read_bounded_line(&mut reader, &mut buf, max_line_bytes)? {
            LineReadOutcome::Eof => break,
            LineReadOutcome::Truncated { .. } => {
                // Oversized line cannot be valid compact JSONL; drained cleanly to next line.
                continue;
            }
            LineReadOutcome::Complete => {
                let Ok(text) = std::str::from_utf8(&buf) else {
                    continue;
                };
                let trimmed = text.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let Ok(event) = serde_json::from_str::<MetricEvent>(trimmed) else {
                    continue;
                };

                if let Some(cutoff) = cutoff_unix_secs {
                    let Some(ts) = parse_iso8601_utc_secs(&event.timestamp_utc) else {
                        continue;
                    };
                    if ts < cutoff {
                        continue;
                    }
                }

                if !matches_project_filter(&event, project_filter, project_id_filter) {
                    continue;
                }

                if is_claude_client(&event.client_name) {
                    agg.claude_calls = agg.claude_calls.saturating_add(1);
                } else {
                    agg.non_claude_calls = agg.non_claude_calls.saturating_add(1);
                }

                let saved = if event.tokens_saved > 0 {
                    event.tokens_saved
                } else {
                    event
                        .raw_est_tokens
                        .saturating_sub(event.filtered_est_tokens)
                };
                agg.estimated_tokens_saved = agg.estimated_tokens_saved.saturating_add(saved);

                if event.is_run_filtered {
                    agg.runs_filtered = agg.runs_filtered.saturating_add(1);
                }
                agg.stale_memories_caught = agg
                    .stale_memories_caught
                    .saturating_add(event.stale_memories_caught);
            }
        }
    }

    Ok(agg)
}

fn is_claude_client(client_name: &str) -> bool {
    let lower = client_name.trim().to_ascii_lowercase();
    lower == "claude-code" || lower == "claude_code" || lower == "claude"
}

fn matches_project_filter(
    event: &MetricEvent,
    project_filter: Option<&str>,
    project_id_filter: Option<&str>,
) -> bool {
    if let Some(pid) = project_id_filter {
        return event.project_id.eq_ignore_ascii_case(pid);
    }

    let Some(filter) = project_filter else {
        return true;
    };
    if filter.eq_ignore_ascii_case("all") || filter.is_empty() {
        return true;
    }

    if event.project_id.eq_ignore_ascii_case(filter) {
        return true;
    }
    if let Some(name) = &event.project_name
        && name.eq_ignore_ascii_case(filter)
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(client: &str) -> MetricEvent {
        MetricEvent::new(
            "2026-11-26T12:00:00Z",
            "proj",
            None,
            client,
            "1",
            "klens_read",
            10,
            5,
            false,
        )
    }

    #[test]
    fn client_supplied_names_are_capped_and_file_rotates() {
        let dir = std::env::temp_dir().join(format!("klens-metrics-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("metrics.jsonl");

        append_metric_event(&path, &event(&"x".repeat(100_000))).unwrap();
        let line_len = fs::metadata(&path).unwrap().len();

        let big = usize::try_from(MAX_METRICS_FILE_BYTES).unwrap() + 1;
        fs::write(&path, "y".repeat(big)).unwrap();
        append_metric_event(&path, &event("claude-code")).unwrap();
        let after = fs::metadata(&path).unwrap().len();
        let rotated = dir.join("metrics.jsonl.1").is_file();
        let _ = fs::remove_dir_all(&dir);

        assert!(line_len < 1_000, "stored line is {line_len} bytes");
        assert!(rotated, "old file was not rotated");
        assert!(after < 1_000, "file kept growing: {after} bytes");
    }
}
