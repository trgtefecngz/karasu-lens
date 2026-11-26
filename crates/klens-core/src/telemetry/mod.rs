//! Two-layer streaming telemetry engine for Karasu Lens (`klens-core::telemetry`).
//!
//! - **Layer 1 (Universal):** `~/.klens/metrics.jsonl` — records real `klens` tool
//!   invocations and estimated token savings across every AI client.
//! - **Layer 2 (Host Session Logs — Optional):** Streams Claude Code `.jsonl` logs
//!   via `BufReader` with a strict per-line RAM cap (never `fs::read`). When no host
//!   logs exist, reports `host_logs_connected: false` and `host_totals: null` instead
//!   of fabricating fake zeros.

pub mod host_logs;
pub mod metrics;
pub mod types;

use std::fmt::Write as _;

use crate::envelope::SCHEMA_VERSION;
use crate::error::KlensError;
use crate::time::now_unix_secs;

pub use host_logs::{extract_project_name_from_log_path, is_file_read_tool, is_klens_mcp_tool};
pub use metrics::append_metric_event;
pub use types::{
    BIG_FILE_READ_CHAR_THRESHOLD, DEFAULT_MAX_LINE_BYTES, DEFAULT_RECENT_SESSIONS_LIMIT,
    HostTotals, KlensMetricsSummary, LineReadOutcome, MetricEvent, ModelUsage, SessionSummary,
    StatsQuery, StatsRange, StatsReport, default_claude_projects_dir, default_metrics_path,
    read_bounded_line, utf8_safe_prefix,
};

/// Compute a unified 2-layer [`StatsReport`] over 100% of matching Layer 1 events and
/// Layer 2 host sessions.
pub fn compute_stats(query: &StatsQuery) -> Result<StatsReport, KlensError> {
    let now = query.now_unix_secs.unwrap_or_else(now_unix_secs);
    let cutoff = query.range.cutoff_unix_secs(now);

    let normalized_project_filter = query
        .project_filter
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("all"));

    let l1 = match &query.metrics_path {
        Some(path) => metrics::aggregate_layer1_metrics(
            path,
            cutoff,
            normalized_project_filter,
            query.project_id_filter.as_deref(),
            query.max_line_bytes,
        )?,
        None => metrics::Layer1Aggregate::default(),
    };

    let l2 = match &query.claude_projects_dir {
        Some(dir) => host_logs::aggregate_layer2_host_logs(
            dir,
            cutoff,
            normalized_project_filter,
            query.max_line_bytes,
            query.recent_limit,
        )?,
        None => host_logs::Layer2Aggregate::default(),
    };

    // Combine Layer 1 and Layer 2 `klens_calls` without double-counting Claude Code calls:
    // non-Claude Layer 1 clients add directly, while Claude Code uses max(L1, L2).
    let total_klens_calls = l1
        .non_claude_calls
        .saturating_add(l1.claude_calls.max(l2.host_klens_calls));

    let klens_metrics = KlensMetricsSummary {
        klens_calls: total_klens_calls,
        estimated_tokens_saved: l1.estimated_tokens_saved,
        runs_filtered: l1.runs_filtered,
        stale_memories_caught: l1.stale_memories_caught,
    };

    let project_filter_label = normalized_project_filter
        .or(query.project_id_filter.as_deref())
        .unwrap_or("all")
        .to_string();

    Ok(StatsReport {
        schema_version: SCHEMA_VERSION,
        range: query.range,
        project_filter: project_filter_label,
        host_logs_connected: l2.host_logs_connected,
        host_logs_source: if l2.host_logs_connected {
            Some("claude-code".to_string())
        } else {
            None
        },
        klens_metrics,
        host_totals: l2.host_totals,
        by_model: l2.by_model,
        recent_sessions: l2.recent_sessions,
    })
}

/// Format a [`StatsReport`] as concise, honest plain text for `klens stats`.
pub fn format_stats_text(report: &StatsReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[klens stats] range={} project={}",
        report.range.as_str(),
        report.project_filter
    );
    let _ = writeln!(
        out,
        "Layer 1 (klens): calls={} est_tokens_saved={} runs_filtered={} stale_memories_caught={}",
        report.klens_metrics.klens_calls,
        report.klens_metrics.estimated_tokens_saved,
        report.klens_metrics.runs_filtered,
        report.klens_metrics.stale_memories_caught
    );

    if report.host_logs_connected
        && let Some(host) = &report.host_totals
    {
        let src = report.host_logs_source.as_deref().unwrap_or("host");
        let _ = writeln!(
            out,
            "Layer 2 ({src}): sessions={} input_tokens={} (fresh={} cache_create={} cache_read={}) output_tokens={} peak_context={} big_file_reads={} repeated_overlapping_reads={}",
            host.sessions_count,
            host.total_input_tokens,
            host.fresh_input_tokens,
            host.cache_creation_tokens,
            host.cache_read_tokens,
            host.total_output_tokens,
            host.peak_context_tokens,
            host.big_file_reads,
            host.repeated_overlapping_reads
        );
        if !report.by_model.is_empty() {
            let _ = writeln!(out, "By model:");
            for m in &report.by_model {
                let _ = writeln!(
                    out,
                    "  - {}: sessions={} tokens={}",
                    m.model, m.sessions, m.tokens
                );
            }
        }
    } else {
        let _ = writeln!(
            out,
            "Layer 2 (host session logs): not connected (no host .jsonl logs found)"
        );
    }

    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::time::UtcParts;

    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "klens-telemetry-{label}-{}-{seq}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn write(&self, rel: &str, contents: &str) -> PathBuf {
            let full = self.path.join(rel);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&full, contents).unwrap();
            full
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn no_host_logs_reports_disconnected_without_fake_zeros() {
        let tmp = TempDir::new("disconnected");
        let metrics_file = tmp.path.join("metrics.jsonl");
        let ev = MetricEvent::new(
            "2026-11-22T18:00:00Z",
            "proj-1",
            Some("MyApp".into()),
            "antigravity",
            "1.0",
            "klens_read",
            1200,
            200,
            false,
        );
        append_metric_event(&metrics_file, &ev).unwrap();

        let report = compute_stats(&StatsQuery {
            range: StatsRange::All,
            metrics_path: Some(metrics_file),
            claude_projects_dir: Some(tmp.path.join("nonexistent-claude")),
            now_unix_secs: Some(1_795_372_200),
            ..StatsQuery::default()
        })
        .unwrap();

        assert!(!report.host_logs_connected);
        assert!(report.host_logs_source.is_none());
        assert!(report.host_totals.is_none());
        assert_eq!(report.klens_metrics.klens_calls, 1);
        assert_eq!(report.klens_metrics.estimated_tokens_saved, 1000);
        let text = format_stats_text(&report);
        assert!(text.contains("not connected"));
    }

    #[test]
    fn regression_locks_1_to_4_for_host_logs() {
        let tmp = TempDir::new("regressions");
        let big_bash_output = "x".repeat(25_000);
        let big_read_output = "y".repeat(25_000);

        let lines = vec![
            // 1. Bash tool_use + 25k output (must NOT count as big_file_reads)
            serde_json::json!({
                "type": "assistant",
                "timestamp": "2026-11-22T18:00:00Z",
                "sessionId": "sess-1",
                "message": {
                    "model": "claude-sonnet-4",
                    "usage": { "input_tokens": 1000, "cache_read_input_tokens": 5000, "output_tokens": 200 },
                    "content": [
                        { "type": "tool_use", "id": "t_bash", "name": "Bash", "input": { "command": "cat huge.log" } },
                        { "type": "tool_use", "id": "t_read_1", "name": "Read", "input": { "file_path": "src/app.rs", "offset": 1, "limit": 100 } },
                        { "type": "tool_use", "id": "t_read_2", "name": "Read", "input": { "file_path": "src/app.rs", "offset": 101, "limit": 100 } },
                        { "type": "tool_use", "id": "t_read_3", "name": "Read", "input": { "file_path": "src/app.rs", "offset": 50, "limit": 71 } },
                        { "type": "tool_use", "id": "t_klens", "name": "mcp__klens__klens_read", "input": { "path": "src/app.rs", "symbol": "main" } }
                    ]
                }
            }),
            serde_json::json!({
                "type": "user",
                "timestamp": "2026-11-22T18:00:05Z",
                "message": {
                    "content": [
                        { "type": "tool_result", "tool_use_id": "t_bash", "content": big_bash_output },
                        { "type": "tool_result", "tool_use_id": "t_read_1", "content": "small chunk" }
                    ]
                }
            }),
            // Confirm a genuine >20k Read tool_result DOES count as 1 big_file_read
            serde_json::json!({
                "type": "assistant",
                "timestamp": "2026-11-22T18:00:10Z",
                "message": {
                    "model": "claude-sonnet-4",
                    "usage": { "input_tokens": 2000, "cache_read_input_tokens": 10000, "output_tokens": 300 },
                    "content": [
                        { "type": "tool_use", "id": "t_big_read", "name": "Read", "input": { "file_path": "src/huge.rs", "offset": 1, "limit": 900 } }
                    ]
                }
            }),
            serde_json::json!({
                "type": "user",
                "timestamp": "2026-11-22T18:00:12Z",
                "message": {
                    "content": [
                        { "type": "tool_result", "tool_use_id": "t_big_read", "content": big_read_output }
                    ]
                }
            }),
        ];

        let content: String = lines
            .into_iter()
            .map(|v| format!("{}\n", serde_json::to_string(&v).unwrap()))
            .collect();

        // Lock 3: Subagent path -> project name must resolve to "MyApp", NEVER "subagents".
        let log_path = tmp.write("projects/MyApp/sess-1/subagents/agent-2.jsonl", &content);
        let (proj_name, is_sub) = extract_project_name_from_log_path(&log_path);
        assert_eq!(proj_name, "MyApp");
        assert!(is_sub);

        let report = compute_stats(&StatsQuery {
            range: StatsRange::All,
            metrics_path: Some(tmp.path.join("no-metrics.jsonl")),
            claude_projects_dir: Some(tmp.path.join("projects")),
            now_unix_secs: Some(1_795_372_200),
            ..StatsQuery::default()
        })
        .unwrap();

        assert!(report.host_logs_connected);
        let host = report.host_totals.expect("host_totals must be present");
        // Lock 1: Bash 25k ignored; only t_big_read counted -> 1
        assert_eq!(host.big_file_reads, 1);
        // Lock 2: L1-100 + L101-200 = 0 overlap; L50-120 overlaps -> 1
        assert_eq!(host.repeated_overlapping_reads, 1);
        assert_eq!(host.peak_context_tokens, 12_000);
        // Lock 3: session project resolved to "MyApp"
        assert_eq!(report.recent_sessions.len(), 1);
        assert_eq!(report.recent_sessions[0].project, "MyApp");
        assert!(report.recent_sessions[0].is_subagent);
        // Lock 4: mcp__klens__klens_read counted under klens_metrics.klens_calls
        assert_eq!(report.klens_metrics.klens_calls, 1);
    }

    #[test]
    fn sixty_sessions_consistency_and_date_filter() {
        let tmp = TempDir::new("sixty");
        let now = 1_795_372_200i64; // 2026-11-22T18:30:00Z

        for i in 0..60 {
            let ts = UtcParts::from_unix_secs(now - i * 3600, 0).to_iso8601();
            let model = if i % 2 == 0 {
                "claude-sonnet-4"
            } else {
                "claude-opus-4"
            };
            let line = serde_json::json!({
                "type": "assistant",
                "timestamp": ts,
                "sessionId": format!("sess-{i:03}"),
                "message": {
                    "model": model,
                    "usage": { "input_tokens": 1000, "output_tokens": 100 },
                    "content": [
                        { "type": "tool_use", "id": "k1", "name": "mcp__klens__klens_map", "input": {} }
                    ]
                }
            });
            tmp.write(
                &format!("projects/Demo/sess-{i:03}.jsonl"),
                &format!("{}\n", serde_json::to_string(&line).unwrap()),
            );
        }

        let report = compute_stats(&StatsQuery {
            range: StatsRange::All,
            metrics_path: None,
            claude_projects_dir: Some(tmp.path.join("projects")),
            recent_limit: 50,
            now_unix_secs: Some(now),
            ..StatsQuery::default()
        })
        .unwrap();

        // Display list is capped at 50, while totals cover 100% (all 60 sessions).
        assert_eq!(report.recent_sessions.len(), 50);
        let host = report.host_totals.unwrap();
        assert_eq!(host.sessions_count, 60);
        assert_eq!(host.total_input_tokens, 60_000);
        assert_eq!(host.total_output_tokens, 6_000);
        assert_eq!(report.klens_metrics.klens_calls, 60);
        assert_eq!(report.by_model.len(), 2);
        assert_eq!(
            report.by_model[0].sessions + report.by_model[1].sessions,
            60
        );

        // `today` filter: 2026-11-22T00:00:00Z..=18:30:00Z -> i = 0..=18 (19 sessions).
        let today_report = compute_stats(&StatsQuery {
            range: StatsRange::Today,
            metrics_path: None,
            claude_projects_dir: Some(tmp.path.join("projects")),
            now_unix_secs: Some(now),
            ..StatsQuery::default()
        })
        .unwrap();
        assert_eq!(today_report.host_totals.unwrap().sessions_count, 19);
    }

    #[test]
    fn huge_multibyte_utf8_line_streams_without_oom_or_char_boundary_panic() {
        let tmp = TempDir::new("utf8-huge");
        // Build a line > 4096 bytes full of multi-byte Turkish + emoji chars so a naive byte
        // cap splits right in the middle of a multi-byte UTF-8 sequence.
        let huge_payload = "ğüşiöç🚀".repeat(1500); // ~18 KB
        let huge_line = format!(
            "{{\"type\":\"user\",\"timestamp\":\"2026-11-22T18:00:00Z\",\"blob\":\"{huge_payload}\"}}\n"
        );
        let next_valid_line = serde_json::json!({
            "type": "assistant",
            "timestamp": "2026-11-22T18:01:00Z",
            "sessionId": "utf8-sess",
            "message": {
                "model": "claude-sonnet-4",
                "usage": { "input_tokens": 777, "output_tokens": 33 },
                "content": [
                    { "type": "tool_use", "id": "u1", "name": "mcp__klens__klens_find", "input": { "query": "ğüşiöç" } }
                ]
            }
        });

        let full = format!(
            "{huge_line}{}\n",
            serde_json::to_string(&next_valid_line).unwrap()
        );
        tmp.write("projects/TurkceProje/utf8-sess.jsonl", &full);

        // Enforce a tiny 513-byte per-line cap (odd byte count forces split inside UTF-8 char!).
        let report = compute_stats(&StatsQuery {
            range: StatsRange::All,
            metrics_path: None,
            claude_projects_dir: Some(tmp.path.join("projects")),
            max_line_bytes: 513,
            now_unix_secs: Some(1_795_372_200),
            ..StatsQuery::default()
        })
        .unwrap();

        let host = report.host_totals.unwrap();
        assert_eq!(host.sessions_count, 1);
        assert_eq!(host.total_input_tokens, 777);
        assert_eq!(host.total_output_tokens, 33);
        assert_eq!(report.klens_metrics.klens_calls, 1);
        assert_eq!(report.recent_sessions[0].project, "TurkceProje");
    }

    #[test]
    fn subagent_path_extractor_handles_relative_and_windows_paths() {
        assert_eq!(
            extract_project_name_from_log_path(Path::new(
                "projects/MyApp/sess-1/subagents/agent-2.jsonl"
            )),
            ("MyApp".to_string(), true)
        );
        assert_eq!(
            extract_project_name_from_log_path(Path::new("projects/MyApp/sess-1.jsonl")),
            ("MyApp".to_string(), false)
        );
        assert_eq!(
            extract_project_name_from_log_path(Path::new("MyApp/sess-1/subagents/agent-9.jsonl")),
            ("MyApp".to_string(), true)
        );
    }

    #[test]
    fn project_id_filter_isolates_same_folder_name_projects() {
        let tmp = TempDir::new("proj-id-isolation");
        let metrics_file = tmp.path.join("metrics.jsonl");

        // Two distinct projects that happen to share the exact same folder name `"app"`:
        // e.g. `C:\work\app` (`proj-id-work`) vs `D:\backup\app` (`proj-id-backup`).
        append_metric_event(
            &metrics_file,
            &MetricEvent::new(
                "2026-11-22T18:00:00Z",
                "proj-id-work",
                Some("app".into()),
                "antigravity",
                "1.0",
                "klens_read",
                1000,
                200,
                false,
            ),
        )
        .unwrap();
        append_metric_event(
            &metrics_file,
            &MetricEvent::new(
                "2026-11-22T18:05:00Z",
                "proj-id-backup",
                Some("app".into()),
                "antigravity",
                "1.0",
                "klens_run",
                5000,
                500,
                true,
            ),
        )
        .unwrap();

        // Filtering with `project_id_filter = Some("proj-id-work")` AND `project_filter = Some("app")`
        // MUST strictly include ONLY `proj-id-work` and NEVER leak `proj-id-backup` via `project_name`.
        let report = compute_stats(&StatsQuery {
            range: StatsRange::All,
            project_filter: Some("app".into()),
            project_id_filter: Some("proj-id-work".into()),
            metrics_path: Some(metrics_file),
            claude_projects_dir: Some(tmp.path.join("no-claude")),
            now_unix_secs: Some(1_795_372_200),
            ..StatsQuery::default()
        })
        .unwrap();

        assert_eq!(report.klens_metrics.klens_calls, 1);
        assert_eq!(report.klens_metrics.estimated_tokens_saved, 800);
        assert_eq!(report.klens_metrics.runs_filtered, 0);
    }

    #[test]
    fn streaming_message_id_dedup_fresh_vs_cache_and_synthetic_model_filter() {
        let tmp = TempDir::new("dedup-synthetic");

        // 4 streaming lines sharing the exact same `message.id` ("msg_stream_01") must be
        // counted ONCE (1x, not 4x), taking the highest/final usage values.
        let lines = vec![
            serde_json::json!({
                "type": "assistant",
                "timestamp": "2026-11-23T10:00:01Z",
                "sessionId": "sess-dedup",
                "message": {
                    "id": "msg_stream_01",
                    "model": "claude-sonnet-4",
                    "usage": {
                        "input_tokens": 200,
                        "cache_creation_input_tokens": 1000,
                        "cache_read_input_tokens": 8000,
                        "output_tokens": 10
                    },
                    "content": [{ "type": "thinking", "thinking": "planning..." }]
                }
            }),
            serde_json::json!({
                "type": "assistant",
                "timestamp": "2026-11-23T10:00:02Z",
                "sessionId": "sess-dedup",
                "message": {
                    "id": "msg_stream_01",
                    "model": "claude-sonnet-4",
                    "usage": {
                        "input_tokens": 200,
                        "cache_creation_input_tokens": 1000,
                        "cache_read_input_tokens": 8000,
                        "output_tokens": 80
                    },
                    "content": [{ "type": "text", "text": "Checking files..." }]
                }
            }),
            serde_json::json!({
                "type": "assistant",
                "timestamp": "2026-11-23T10:00:03Z",
                "sessionId": "sess-dedup",
                "message": {
                    "id": "msg_stream_01",
                    "model": "claude-sonnet-4",
                    "usage": {
                        "input_tokens": 200,
                        "cache_creation_input_tokens": 1000,
                        "cache_read_input_tokens": 8000,
                        "output_tokens": 160
                    },
                    "content": [
                        { "type": "tool_use", "id": "t1", "name": "mcp__klens__klens_map", "input": {} }
                    ]
                }
            }),
            serde_json::json!({
                "type": "assistant",
                "timestamp": "2026-11-23T10:00:04Z",
                "sessionId": "sess-dedup",
                "message": {
                    "id": "msg_stream_01",
                    "model": "claude-sonnet-4",
                    "usage": {
                        "input_tokens": 200,
                        "cache_creation_input_tokens": 1000,
                        "cache_read_input_tokens": 8000,
                        "output_tokens": 250
                    },
                    "content": [{ "type": "text", "text": "Done." }]
                }
            }),
            // Legacy line without `message.id` must still be counted directly.
            serde_json::json!({
                "type": "assistant",
                "timestamp": "2026-11-23T10:00:10Z",
                "sessionId": "sess-dedup",
                "message": {
                    "model": "claude-sonnet-4",
                    "usage": {
                        "input_tokens": 50,
                        "cache_creation_input_tokens": 100,
                        "cache_read_input_tokens": 500,
                        "output_tokens": 40
                    }
                }
            }),
            // `<synthetic>` and `SYNTHETIC` models must NEVER enter `by_model` or `primary_model`.
            serde_json::json!({
                "type": "assistant",
                "timestamp": "2026-11-23T10:00:15Z",
                "sessionId": "sess-dedup",
                "message": {
                    "id": "msg_synth_01",
                    "model": "<synthetic>",
                    "usage": {
                        "input_tokens": 0,
                        "cache_creation_input_tokens": 0,
                        "cache_read_input_tokens": 0,
                        "output_tokens": 0
                    }
                }
            }),
        ];

        let synth_only_line = serde_json::json!({
            "type": "assistant",
            "timestamp": "2026-11-23T10:01:00Z",
            "sessionId": "sess-synth-only",
            "message": {
                "id": "msg_synth_only",
                "model": "SYNTHETIC",
                "usage": { "input_tokens": 10, "output_tokens": 5 }
            }
        });

        let content: String = lines
            .into_iter()
            .map(|v| format!("{}\n", serde_json::to_string(&v).unwrap()))
            .collect();
        tmp.write("projects/C--Users-dev-MyProj/sess-dedup.jsonl", &content);
        tmp.write(
            "projects/C--Users-dev-MyProj/sess-synth-only.jsonl",
            &format!("{}\n", serde_json::to_string(&synth_only_line).unwrap()),
        );

        let report = compute_stats(&StatsQuery {
            range: StatsRange::All,
            metrics_path: None,
            claude_projects_dir: Some(tmp.path.join("projects")),
            now_unix_secs: Some(1_795_400_000),
            ..StatsQuery::default()
        })
        .unwrap();

        let host = report.host_totals.expect("host_totals must be present");
        assert_eq!(host.sessions_count, 2);
        // msg_stream_01 (1x: 200+1000+8000=9200) + legacy (50+100+500=650) + synth_only (10)
        assert_eq!(host.fresh_input_tokens, 260);
        assert_eq!(host.cache_creation_tokens, 1_100);
        assert_eq!(host.cache_read_tokens, 8_500);
        assert_eq!(
            host.total_input_tokens,
            host.fresh_input_tokens + host.cache_creation_tokens + host.cache_read_tokens
        );
        assert_eq!(host.total_input_tokens, 9_860);
        // output: 250 (max of 4 streaming chunks, NOT 10+80+160+250) + 40 + 5 = 295
        assert_eq!(host.total_output_tokens, 295);
        assert_eq!(host.peak_context_tokens, 9_200);
        // Tool use inside streaming chunk 3 still counted.
        assert_eq!(report.klens_metrics.klens_calls, 1);

        // `<synthetic>` and `SYNTHETIC` must be excluded from `by_model` and `primary_model`.
        assert_eq!(report.by_model.len(), 1);
        assert_eq!(report.by_model[0].model, "claude-sonnet-4");
        assert_eq!(report.by_model[0].tokens, 9_850 + 290);

        let synth_sess = report
            .recent_sessions
            .iter()
            .find(|s| s.session_id == "sess-synth-only")
            .expect("synth session present");
        assert!(synth_sess.model.is_none());

        // Backward-compatible HostTotals deserialization (missing new fields default to 0).
        let legacy_json = r#"{"sessions_count":1,"total_input_tokens":500,"total_output_tokens":50,"peak_context_tokens":500,"big_file_reads":0,"repeated_overlapping_reads":0}"#;
        let parsed: HostTotals = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(parsed.fresh_input_tokens, 0);
        assert_eq!(parsed.cache_creation_tokens, 0);
        assert_eq!(parsed.cache_read_tokens, 0);
    }
}
