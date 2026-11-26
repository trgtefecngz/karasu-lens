//! Shared leaf types and bounded UTF-8-safe streaming helpers for `klens-core::telemetry`.

use std::io::{self, BufRead};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::envelope::SCHEMA_VERSION;
use crate::time::{SECS_PER_DAY, start_of_utc_day_secs};

/// Minimum character length for a file-read `tool_result` to count as a `big_file_read`.
pub const BIG_FILE_READ_CHAR_THRESHOLD: usize = 20_000;

/// Default single-line memory cap (2 MiB) when streaming `.jsonl` logs with `BufReader`.
pub const DEFAULT_MAX_LINE_BYTES: usize = 2 * 1024 * 1024;

/// Default number of recent sessions included in `StatsReport.recent_sessions`.
///
/// NOTE: `klens_metrics`, `host_totals`, and `by_model` are ALWAYS aggregated over 100% of
/// matching sessions, never truncated by this display limit.
pub const DEFAULT_RECENT_SESSIONS_LIMIT: usize = 50;

const fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

/// Time window filter for telemetry queries (`today | 7d | 30d | all`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum StatsRange {
    #[serde(rename = "today")]
    Today,
    #[default]
    #[serde(rename = "7d")]
    Days7,
    #[serde(rename = "30d")]
    Days30,
    #[serde(rename = "all")]
    All,
}

impl StatsRange {
    /// Parse a CLI or API range label (`today`, `7d`, `30d`, `all`).
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "today" => Some(Self::Today),
            "7d" => Some(Self::Days7),
            "30d" => Some(Self::Days30),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    /// Canonical string identifier matching `docs/02-DATA-SCHEMAS.md`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Today => "today",
            Self::Days7 => "7d",
            Self::Days30 => "30d",
            Self::All => "all",
        }
    }

    /// Inclusive UTC Unix-second cutoff for `now_unix_secs` (`None` for `All`).
    pub const fn cutoff_unix_secs(self, now_unix_secs: i64) -> Option<i64> {
        match self {
            Self::Today => Some(start_of_utc_day_secs(now_unix_secs)),
            Self::Days7 => Some(now_unix_secs - 7 * SECS_PER_DAY),
            Self::Days30 => Some(now_unix_secs - 30 * SECS_PER_DAY),
            Self::All => None,
        }
    }
}

/// Layer 1 universal telemetry record appended to `~/.klens/metrics.jsonl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricEvent {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub timestamp_utc: String,
    pub project_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_name: Option<String>,
    pub client_name: String,
    #[serde(default)]
    pub client_version: String,
    pub tool: String,
    #[serde(default)]
    pub raw_est_tokens: u64,
    #[serde(default)]
    pub filtered_est_tokens: u64,
    #[serde(default)]
    pub tokens_saved: u64,
    #[serde(default)]
    pub is_run_filtered: bool,
    #[serde(default)]
    pub stale_memories_caught: u64,
}

impl MetricEvent {
    /// Construct a new Layer 1 metric event with computed `tokens_saved`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        timestamp_utc: impl Into<String>,
        project_id: impl Into<String>,
        project_name: Option<String>,
        client_name: impl Into<String>,
        client_version: impl Into<String>,
        tool: impl Into<String>,
        raw_est_tokens: u64,
        filtered_est_tokens: u64,
        is_run_filtered: bool,
    ) -> Self {
        let tokens_saved = raw_est_tokens.saturating_sub(filtered_est_tokens);
        Self {
            schema_version: SCHEMA_VERSION,
            timestamp_utc: timestamp_utc.into(),
            project_id: project_id.into(),
            project_name,
            client_name: client_name.into(),
            client_version: client_version.into(),
            tool: tool.into(),
            raw_est_tokens,
            filtered_est_tokens,
            tokens_saved,
            is_run_filtered,
            stale_memories_caught: 0,
        }
    }
}

/// Aggregated Layer 1 (`klens`) metrics (plus `mcp__klens__*` calls from Layer 2 when present).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KlensMetricsSummary {
    pub klens_calls: u64,
    pub estimated_tokens_saved: u64,
    pub runs_filtered: u64,
    pub stale_memories_caught: u64,
}

/// Aggregated Layer 2 host session totals across 100% of matching sessions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostTotals {
    pub sessions_count: u64,
    pub total_input_tokens: u64,
    #[serde(default)]
    pub fresh_input_tokens: u64,
    #[serde(default)]
    pub cache_creation_tokens: u64,
    #[serde(default)]
    pub cache_read_tokens: u64,
    pub total_output_tokens: u64,
    pub peak_context_tokens: u64,
    pub big_file_reads: u64,
    pub repeated_overlapping_reads: u64,
}

/// Per-model usage breakdown across 100% of matching host sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelUsage {
    pub model: String,
    pub sessions: u64,
    pub tokens: u64,
}

/// Single session summary for `recent_sessions` display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub project: String,
    pub timestamp_utc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub peak_context_tokens: u64,
    pub big_file_reads: u64,
    pub repeated_overlapping_reads: u64,
    pub klens_calls: u64,
    pub is_subagent: bool,
}

/// Unified 2-layer telemetry report matching `docs/02-DATA-SCHEMAS.md` Section 7.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsReport {
    pub schema_version: u32,
    pub range: StatsRange,
    pub project_filter: String,
    pub host_logs_connected: bool,
    pub host_logs_source: Option<String>,
    pub klens_metrics: KlensMetricsSummary,
    pub host_totals: Option<HostTotals>,
    pub by_model: Vec<ModelUsage>,
    pub recent_sessions: Vec<SessionSummary>,
}

/// Query configuration for computing a [`StatsReport`].
#[derive(Debug, Clone)]
pub struct StatsQuery {
    pub range: StatsRange,
    /// Optional project filter matching either `project_id` or project directory/name.
    pub project_filter: Option<String>,
    /// Optional explicit project ID when filtering by a local project root path.
    pub project_id_filter: Option<String>,
    /// Path to Layer 1 `~/.klens/metrics.jsonl`.
    pub metrics_path: Option<PathBuf>,
    /// Directory containing Layer 2 Claude Code project logs (`~/.claude/projects`).
    pub claude_projects_dir: Option<PathBuf>,
    /// Maximum bytes buffered for a single JSONL line before streaming drain.
    pub max_line_bytes: usize,
    /// Maximum sessions included in `recent_sessions` (totals always cover 100%).
    pub recent_limit: usize,
    /// Explicit "now" Unix seconds (defaults to current UTC clock when `None`).
    pub now_unix_secs: Option<i64>,
}

impl Default for StatsQuery {
    fn default() -> Self {
        Self {
            range: StatsRange::Days7,
            project_filter: None,
            project_id_filter: None,
            metrics_path: default_metrics_path(),
            claude_projects_dir: default_claude_projects_dir(),
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
            recent_limit: DEFAULT_RECENT_SESSIONS_LIMIT,
            now_unix_secs: None,
        }
    }
}

/// Resolve the default Layer 1 metrics log path: `~/.klens/metrics.jsonl`.
pub fn default_metrics_path() -> Option<PathBuf> {
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))?;
    Some(PathBuf::from(home).join(".klens").join("metrics.jsonl"))
}

/// Resolve the default Layer 2 Claude Code projects log directory: `~/.claude/projects`.
pub fn default_claude_projects_dir() -> Option<PathBuf> {
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))?;
    Some(PathBuf::from(home).join(".claude").join("projects"))
}

/// Outcome of reading a single line with a strict per-line RAM cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineReadOutcome {
    /// End of stream reached with zero bytes read.
    Eof,
    /// Complete line fit within `max_bytes`.
    Complete,
    /// Line exceeded `max_bytes`; buffer holds the capped prefix and the remainder
    /// up to `\n` (or EOF) was drained cleanly without growing RAM.
    Truncated { total_bytes: usize },
}

/// Stream a single `\n`-terminated line from `reader` into `buf` without ever letting `buf`
/// grow beyond `max_bytes`.
///
/// If a line exceeds `max_bytes`, the remaining bytes through `\n` are drained directly from
/// `reader`'s internal buffer so the next call starts cleanly at the next line.
pub fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max_bytes: usize,
) -> io::Result<LineReadOutcome> {
    buf.clear();
    let cap = max_bytes.max(1);
    let mut total_bytes = 0usize;
    let mut truncated = false;

    loop {
        let avail = reader.fill_buf()?;
        if avail.is_empty() {
            break;
        }

        let newline_pos = avail.iter().position(|&b| b == b'\n');
        let chunk_len = newline_pos.map_or(avail.len(), |pos| pos + 1);
        total_bytes = total_bytes.saturating_add(chunk_len);

        if !truncated {
            let remaining = cap.saturating_sub(buf.len());
            if chunk_len <= remaining {
                buf.extend_from_slice(&avail[..chunk_len]);
            } else {
                if remaining > 0 {
                    buf.extend_from_slice(&avail[..remaining]);
                }
                truncated = true;
            }
        }

        reader.consume(chunk_len);
        if newline_pos.is_some() {
            break;
        }
    }

    if total_bytes == 0 {
        Ok(LineReadOutcome::Eof)
    } else if truncated {
        Ok(LineReadOutcome::Truncated { total_bytes })
    } else {
        Ok(LineReadOutcome::Complete)
    }
}

/// Return the longest valid UTF-8 prefix of `bytes`, stripping any trailing incomplete
/// multi-byte sequence without panicking on character boundaries.
pub fn utf8_safe_prefix(bytes: &[u8]) -> &str {
    match std::str::from_utf8(bytes) {
        Ok(valid) => valid,
        Err(err) => {
            let valid_len = err.valid_up_to();
            // SAFETY-FREE: `valid_len` is guaranteed by `std::str::from_utf8` to be valid UTF-8.
            std::str::from_utf8(&bytes[..valid_len]).unwrap_or("")
        }
    }
}
