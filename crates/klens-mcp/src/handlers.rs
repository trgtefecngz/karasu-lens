//! Execution handlers for the 8 Phase 3A–5A MCP tools.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::time::Duration;

use klens_code::{
    DEFAULT_FIND_LIMIT, DEFAULT_MAP_BUDGET_TOKENS, DiffCheckOptions, ImpactOutputLimits, LineRange,
    ReadInclude, ReadTarget, analyze_impact, attach_code_context_to_batch,
    attach_code_context_to_read, bound_impact_payload, build_project_map_focused,
    find_in_workspace, format_batch_read_text, format_diff_check_text, format_find_text,
    format_impact_text_with, format_map_text, format_outline_text, format_read_text, outline_path,
    read_batch, read_lines, read_symbol, run_diff_check_with_options,
};
use klens_core::{ProjectRoot, RelPath, SymbolInfo, estimate_tokens, estimate_tokens_from_bytes};
use klens_exec::{
    ErrorSourceContext, RunOptions, enrich_error_context_symbols, execute_command, format_run_text,
};
use serde_json::Value;

use crate::blueprint_handler::handle_blueprint;
use crate::error::McpError;
pub(crate) use crate::handler_common::{
    OutputFormat, ToolContext, ToolExecution, open_index, parse_format, parse_optional_bool,
    parse_optional_string, parse_optional_usize,
};
use crate::memory_handler::{
    attach_bugfix_matches_to_run, attach_memory_context_to_batch, attach_memory_context_to_read,
    attach_stale_memory_alerts_to_diff, handle_memory,
};
use crate::protocol::CallToolResult;

/// Dispatch an authorized MCP tool call to its deterministic implementation.
pub(crate) fn execute_tool(
    ctx: &ToolContext<'_>,
    tool_name: &str,
    args: &Value,
) -> Result<ToolExecution, McpError> {
    match tool_name {
        "klens_map" => handle_map(ctx, args),
        "klens_find" => handle_find(ctx, args),
        "klens_outline" => handle_outline(ctx, args),
        "klens_read" => handle_read(ctx, args),
        "klens_impact" => handle_impact(ctx, args),
        "klens_run" => handle_run(ctx, args),
        "klens_memory" => handle_memory(ctx, args),
        "klens_blueprint" => handle_blueprint(ctx, args),
        other => Err(McpError::UnknownTool(other.to_string())),
    }
}

fn raw_tokens_for_rel_paths<'a, I>(project_root: &ProjectRoot, paths: I) -> u64
where
    I: IntoIterator<Item = &'a str>,
{
    let unique: BTreeSet<&str> = paths.into_iter().collect();
    let mut total_bytes: usize = 0;
    for rel in unique {
        if let Ok((abs, _)) = project_root.resolve_existing(rel)
            && let Ok(meta) = fs::metadata(&abs)
        {
            total_bytes = total_bytes.saturating_add(meta.len() as usize);
        }
    }
    estimate_tokens_from_bytes(total_bytes) as u64
}

/// Lines shown when `klens_read` gets a `path` without `symbol`/`lines`.
const DEFAULT_READ_HEAD_LINES: usize = 200;

/// First [`DEFAULT_READ_HEAD_LINES`] lines of a file, with a hint when the file is longer.
fn read_file_head(
    index: &klens_code::index::CodeIndex,
    rel: &RelPath,
) -> Result<klens_core::ProvenanceEnvelope<klens_code::read::ReadResultData>, McpError> {
    let range = LineRange::new(1, DEFAULT_READ_HEAD_LINES)?;
    let mut envelope = read_lines(index, rel, range)?;
    envelope
        .warnings
        .retain(|w| !w.starts_with("requested end line"));
    if let Some(total) = envelope.data.total_lines
        && total > DEFAULT_READ_HEAD_LINES
    {
        envelope.warnings.push(format!(
            "showing L1-L{DEFAULT_READ_HEAD_LINES} of {total} lines; use `klens_outline` and \
             read a `symbol`, or pass `lines` for another range"
        ));
    }
    // Also cap by bytes: a single minified line can be megabytes.
    if let Some(content) = envelope.data.content.as_mut()
        && content.len() > DEFAULT_READ_HEAD_BYTES
    {
        let full = content.len();
        let mut cut = DEFAULT_READ_HEAD_BYTES;
        while !content.is_char_boundary(cut) {
            cut -= 1;
        }
        content.truncate(cut);
        envelope.warnings.push(format!(
            "showing the first {cut} of {full} bytes (very long lines); pass `lines` for a \
             smaller range or use `klens_find` to locate what you need"
        ));
    }
    Ok(envelope)
}

/// Bytes shown when `klens_read` gets a `path` without `symbol`/`lines`.
const DEFAULT_READ_HEAD_BYTES: usize = 32 * 1024;

fn parse_map_focus(root: &ProjectRoot, args: &Value) -> Result<Option<RelPath>, McpError> {
    let parse_opt = |field: &str| -> Result<Option<Option<RelPath>>, McpError> {
        match parse_optional_string(args, field)? {
            None => Ok(None),
            Some(raw) => Ok(Some(root.relative_input_or_root(&raw)?)),
        }
    };

    match (parse_opt("path")?, parse_opt("focus")?) {
        (Some(p), Some(f)) if p != f => Err(McpError::InvalidParams(
            "`path` and `focus` conflict; specify only one or identical values".to_string(),
        )),
        (Some(p), _) => Ok(p),
        (None, Some(f)) => Ok(f),
        (None, None) => Ok(None),
    }
}

fn handle_map(ctx: &ToolContext<'_>, args: &Value) -> Result<ToolExecution, McpError> {
    let format = parse_format(args)?;
    let budget = parse_optional_usize(args, "budget")?.unwrap_or(DEFAULT_MAP_BUDGET_TOKENS);
    let focus = parse_map_focus(ctx.project_root, args)?;

    let mut index = open_index(ctx)?;
    let envelope = build_project_map_focused(&mut index, budget, focus.as_ref())?;

    let text = match format {
        OutputFormat::Text => format_map_text(&envelope).trim_end().to_string(),
        OutputFormat::Json => envelope.to_deterministic_json()?,
    };
    let filtered_est = estimate_tokens(&text) as u64;
    let raw_est = raw_tokens_for_rel_paths(
        ctx.project_root,
        envelope.data.files.iter().map(|f| f.path.as_str()),
    )
    .max(filtered_est);

    Ok(ToolExecution {
        result: CallToolResult::text(text),
        raw_est_tokens: raw_est,
        filtered_est_tokens: filtered_est,
        is_run_filtered: false,
        stale_memories_caught: 0,
    })
}

fn handle_find(ctx: &ToolContext<'_>, args: &Value) -> Result<ToolExecution, McpError> {
    let format = parse_format(args)?;
    let query = args
        .get("query")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| McpError::InvalidParams("`query` must be a non-empty string".to_string()))?;
    let limit = parse_optional_usize(args, "limit")?.unwrap_or(DEFAULT_FIND_LIMIT);

    let mut index = open_index(ctx)?;
    let envelope = find_in_workspace(&mut index, query, limit)?;

    let text = match format {
        OutputFormat::Text => format_find_text(&envelope).trim_end().to_string(),
        OutputFormat::Json => envelope.to_deterministic_json()?,
    };
    let filtered_est = estimate_tokens(&text) as u64;
    let raw_est = raw_tokens_for_rel_paths(
        ctx.project_root,
        envelope.data.matches.iter().map(|m| m.path.as_str()),
    )
    .max(filtered_est);

    Ok(ToolExecution {
        result: CallToolResult::text(text),
        raw_est_tokens: raw_est,
        filtered_est_tokens: filtered_est,
        is_run_filtered: false,
        stale_memories_caught: 0,
    })
}

fn handle_outline(ctx: &ToolContext<'_>, args: &Value) -> Result<ToolExecution, McpError> {
    let format = parse_format(args)?;
    let raw_path = args
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .ok_or_else(|| McpError::InvalidParams("`path` must be a string".to_string()))?;
    let budget = parse_optional_usize(args, "budget")?;

    let rel_opt = ctx.project_root.relative_input_or_root(raw_path)?;

    let mut index = open_index(ctx)?;
    let envelope = outline_path(&mut index, rel_opt.as_ref(), budget)?;

    let text = match format {
        OutputFormat::Text => format_outline_text(&envelope).trim_end().to_string(),
        OutputFormat::Json => envelope.to_deterministic_json()?,
    };
    let filtered_est = estimate_tokens(&text) as u64;
    let raw_est = raw_tokens_for_rel_paths(
        ctx.project_root,
        envelope.data.files.iter().map(|f| f.path.as_str()),
    )
    .max(filtered_est);

    Ok(ToolExecution {
        result: CallToolResult::text(text),
        raw_est_tokens: raw_est,
        filtered_est_tokens: filtered_est,
        is_run_filtered: false,
        stale_memories_caught: 0,
    })
}

fn parse_read_includes(args: &Value) -> Result<Vec<ReadInclude>, McpError> {
    let Some(val) = args.get("include") else {
        return Ok(Vec::new());
    };
    if val.is_null() {
        return Ok(Vec::new());
    }
    let arr = val.as_array().ok_or_else(|| {
        McpError::InvalidParams(
            "`include` must be an array of strings (`imports`, `memory`, `impact`)".to_string(),
        )
    })?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item.as_str().ok_or_else(|| {
            McpError::InvalidParams(
                "`include` elements must all be strings (`imports`, `memory`, `impact`)"
                    .to_string(),
            )
        })?;
        let inc = ReadInclude::parse(s).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        if !out.contains(&inc) {
            out.push(inc);
        }
    }
    Ok(out)
}

fn handle_read(ctx: &ToolContext<'_>, args: &Value) -> Result<ToolExecution, McpError> {
    let format = parse_format(args)?;
    let includes = parse_read_includes(args)?;

    // Batch mode: `targets: [...]`
    if let Some(targets_val) = args.get("targets")
        && !targets_val.is_null()
    {
        let arr = targets_val
            .as_array()
            .ok_or_else(|| McpError::InvalidParams("`targets` must be an array".to_string()))?;
        if arr.is_empty() {
            return Err(McpError::InvalidParams(
                "`targets` array cannot be empty".to_string(),
            ));
        }
        let mut parsed_targets = Vec::with_capacity(arr.len());
        let mut path_list = Vec::with_capacity(arr.len());
        for item in arr {
            let path = item
                .get("path")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    McpError::InvalidParams("each target requires a non-empty `path`".to_string())
                })?;
            let rel_path = ctx.project_root.relative_input(path)?;
            let path = rel_path.as_str();
            let symbol = parse_optional_string(item, "symbol")?
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let lines = parse_optional_string(item, "lines")?
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            let target = match (symbol.as_deref(), lines.as_deref()) {
                (Some(sym), None) => ReadTarget::symbol(path, sym),
                (None, Some(spec)) => ReadTarget::lines(path, LineRange::parse(spec)?),
                _ => {
                    return Err(McpError::InvalidParams(format!(
                        "target `{path}` must specify exactly one of `symbol` or `lines`"
                    )));
                }
            };
            path_list.push(path.to_string());
            parsed_targets.push(target);
        }

        let mut index = open_index(ctx)?;
        let mut envelope = read_batch(&mut index, &parsed_targets)?;
        if !includes.is_empty() {
            attach_code_context_to_batch(&mut index, &mut envelope, &includes)?;
        }
        drop(index);
        let stale_caught = if includes.contains(&ReadInclude::Memory) {
            attach_memory_context_to_batch(ctx, &mut envelope)
        } else {
            0
        };
        let text = match format {
            OutputFormat::Text => format_batch_read_text(&envelope).trim_end().to_string(),
            OutputFormat::Json => envelope.to_deterministic_json()?,
        };
        let filtered_est = estimate_tokens(&text) as u64;
        let raw_est =
            raw_tokens_for_rel_paths(ctx.project_root, path_list.iter().map(String::as_str))
                .max(filtered_est);

        return Ok(ToolExecution {
            result: CallToolResult::text(text),
            raw_est_tokens: raw_est,
            filtered_est_tokens: filtered_est,
            is_run_filtered: false,
            stale_memories_caught: stale_caught,
        });
    }

    // Single-target mode: `path` + (`symbol` | `lines`)
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            McpError::InvalidParams(
                "`klens_read` requires `path` (with `symbol` or `lines`) or `targets`".to_string(),
            )
        })?;
    let rel = ctx.project_root.relative_input(path)?;

    let symbol = parse_optional_string(args, "symbol")?
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let lines = parse_optional_string(args, "lines")?
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let mut index = open_index(ctx)?;
    let mut envelope = match (symbol.as_deref(), lines.as_deref()) {
        (Some(sym), None) => read_symbol(&mut index, &rel, sym)?,
        (None, Some(spec)) => {
            let range = LineRange::parse(spec)?;
            read_lines(&index, &rel, range)?
        }
        // Path only (a very common first call): show the start of the file instead of failing.
        (None, None) => read_file_head(&index, &rel)?,
        (Some(_), Some(_)) => {
            return Err(McpError::InvalidParams(
                "`klens_read` takes `symbol` or `lines`, not both".to_string(),
            ));
        }
    };
    if !includes.is_empty() {
        attach_code_context_to_read(&mut index, &mut envelope, &includes)?;
    }
    drop(index);
    let stale_caught = if includes.contains(&ReadInclude::Memory) {
        attach_memory_context_to_read(ctx, &mut envelope)
    } else {
        0
    };

    let text = match format {
        OutputFormat::Text => format_read_text(&envelope).trim_end().to_string(),
        OutputFormat::Json => envelope.to_deterministic_json()?,
    };
    let filtered_est = estimate_tokens(&text) as u64;
    let raw_est = raw_tokens_for_rel_paths(ctx.project_root, [rel.as_str()]).max(filtered_est);

    Ok(ToolExecution {
        result: CallToolResult::text(text),
        raw_est_tokens: raw_est,
        filtered_est_tokens: filtered_est,
        is_run_filtered: false,
        stale_memories_caught: stale_caught,
    })
}

fn handle_impact(ctx: &ToolContext<'_>, args: &Value) -> Result<ToolExecution, McpError> {
    let format = parse_format(args)?;
    let target = args
        .get("target")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            McpError::InvalidParams("`target` must be a non-empty string".to_string())
        })?;

    if target == "diff" || target == "diff:staged" {
        let staged_only = target == "diff:staged";
        let mut index = open_index(ctx)?;
        let mut envelope =
            run_diff_check_with_options(&mut index, DiffCheckOptions { staged_only })?;
        drop(index);
        let stale_caught = attach_stale_memory_alerts_to_diff(ctx, &mut envelope);

        let text = match format {
            OutputFormat::Text => format_diff_check_text(&envelope).trim_end().to_string(),
            OutputFormat::Json => envelope.to_deterministic_json()?,
        };
        let filtered_est = estimate_tokens(&text) as u64;
        let raw_est = raw_tokens_for_rel_paths(
            ctx.project_root,
            envelope.data.changed_files.iter().map(|f| f.path.as_str()),
        )
        .max(filtered_est);

        return Ok(ToolExecution {
            result: CallToolResult::text(text),
            raw_est_tokens: raw_est,
            filtered_est_tokens: filtered_est,
            is_run_filtered: false,
            stale_memories_caught: stale_caught,
        });
    }

    // Only `budget` is advertised (the tools/list token lock); a file cap is CLI `--limit`.
    let budget = parse_optional_usize(args, "budget")?;
    let limits = ImpactOutputLimits::from_request(budget, None);

    let mut index = open_index(ctx)?;
    let mut envelope = analyze_impact(&mut index, target)?;

    let text = match format {
        OutputFormat::Text => format_impact_text_with(&envelope, limits)
            .trim_end()
            .to_string(),
        OutputFormat::Json => {
            // JSON is the full list unless the caller asked for a cap explicitly.
            if budget.is_some() {
                bound_impact_payload(&mut envelope.data, limits);
            }
            envelope.to_deterministic_json()?
        }
    };
    let filtered_est = estimate_tokens(&text) as u64;
    let raw_est = raw_tokens_for_rel_paths(
        ctx.project_root,
        envelope.data.hits.iter().map(|h| h.path.as_str()),
    )
    .max(filtered_est);

    Ok(ToolExecution {
        result: CallToolResult::text(text),
        raw_est_tokens: raw_est,
        filtered_est_tokens: filtered_est,
        is_run_filtered: false,
        stale_memories_caught: 0,
    })
}

fn parse_optional_u64(args: &Value, field: &str) -> Result<Option<u64>, McpError> {
    match args.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(val) => val.as_u64().map(Some).ok_or_else(|| {
            McpError::InvalidParams(format!("`{field}` must be a non-negative integer"))
        }),
    }
}

/// Default `klens_run` timeout when the agent does not pass `timeout_secs` (v0.3.3+).
///
/// The MCP server handles one request at a time, so a command that never exits (dev server,
/// watcher, interactive prompt) would otherwise block every later tool call forever.
pub(crate) const DEFAULT_MCP_RUN_TIMEOUT_SECS: u64 = 600;

/// Resolve the effective `klens_run` timeout (default [`DEFAULT_MCP_RUN_TIMEOUT_SECS`]; `0` is
/// rejected because it would kill every command instantly).
pub(crate) fn effective_run_timeout(timeout_secs: Option<u64>) -> Result<Duration, McpError> {
    match timeout_secs {
        Some(0) => Err(McpError::InvalidParams(
            "`timeout_secs` must be at least 1".to_string(),
        )),
        Some(secs) => Ok(Duration::from_secs(secs)),
        None => Ok(Duration::from_secs(DEFAULT_MCP_RUN_TIMEOUT_SECS)),
    }
}

fn handle_run(ctx: &ToolContext<'_>, args: &Value) -> Result<ToolExecution, McpError> {
    let format = parse_format(args)?;
    let command = parse_command_args(args)?;
    let timeout = effective_run_timeout(parse_optional_u64(args, "timeout_secs")?)?;
    let raw = parse_optional_bool(args, "raw")?.unwrap_or(false);
    let auto_context = parse_optional_bool(args, "auto_context")?.unwrap_or(true);

    let options = RunOptions {
        cwd: Some(ctx.project_root.root().to_path_buf()),
        timeout: Some(timeout),
        raw,
        auto_context,
        ..RunOptions::default()
    };

    let mut envelope = execute_command(ctx.project_root, &command, &options)?;
    if !envelope.data.error_contexts.is_empty() {
        attach_error_context_symbols(ctx, &mut envelope.data.error_contexts);
    }
    let stale_caught = attach_bugfix_matches_to_run(ctx, &mut envelope);
    let raw_est = envelope.data.meta.est_raw_tokens as u64;
    let filtered_est = if raw {
        raw_est
    } else {
        envelope.data.meta.est_filtered_tokens as u64
    };

    let text = match format {
        OutputFormat::Text => format_run_text(&envelope).trim_end().to_string(),
        OutputFormat::Json => envelope.to_deterministic_json()?,
    };

    Ok(ToolExecution {
        result: CallToolResult::text(text),
        raw_est_tokens: raw_est,
        filtered_est_tokens: filtered_est,
        is_run_filtered: !raw,
        stale_memories_caught: stale_caught,
    })
}

fn attach_error_context_symbols(ctx: &ToolContext<'_>, contexts: &mut [ErrorSourceContext]) {
    let Ok(mut index) = open_index(ctx) else {
        return;
    };
    let mut cache: BTreeMap<RelPath, Vec<SymbolInfo>> = BTreeMap::new();
    enrich_error_context_symbols(contexts, |rel, line| {
        let symbols = cache.entry(rel.clone()).or_insert_with(|| {
            if index.sync_file(rel).is_err() {
                return Vec::new();
            }
            index.store().get_symbols_for_file(rel).unwrap_or_default()
        });
        symbols
            .iter()
            .filter(|s| s.start_line <= line && line <= s.end_line)
            .min_by(|a, b| {
                a.end_line
                    .saturating_sub(a.start_line)
                    .cmp(&b.end_line.saturating_sub(b.start_line))
                    .then_with(|| b.start_line.cmp(&a.start_line))
                    .then_with(|| a.qualified_name.cmp(&b.qualified_name))
            })
            .map(|s| s.qualified_name.clone())
    });
}

fn parse_command_args(args: &Value) -> Result<Vec<String>, McpError> {
    let Some(cmd_val) = args.get("command") else {
        return Err(McpError::InvalidParams(
            "`command` is required (array of program and arguments)".to_string(),
        ));
    };

    if let Some(arr) = cmd_val.as_array() {
        let mut out = Vec::with_capacity(arr.len());
        for item in arr {
            let s = item.as_str().ok_or_else(|| {
                McpError::InvalidParams("`command` elements must all be strings".to_string())
            })?;
            out.push(s.to_string());
        }
        if out.is_empty() || out[0].trim().is_empty() {
            return Err(McpError::InvalidParams(
                "`command` cannot be empty".to_string(),
            ));
        }
        return Ok(out);
    }

    Err(McpError::InvalidParams(
        "`command` must be a non-empty array of strings".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn klens_run_always_has_a_timeout_and_rejects_zero() {
        assert_eq!(
            effective_run_timeout(None).unwrap(),
            Duration::from_secs(DEFAULT_MCP_RUN_TIMEOUT_SECS)
        );
        assert_eq!(
            effective_run_timeout(Some(30)).unwrap(),
            Duration::from_secs(30)
        );
        assert!(matches!(
            effective_run_timeout(Some(0)),
            Err(McpError::InvalidParams(_))
        ));
    }
}
