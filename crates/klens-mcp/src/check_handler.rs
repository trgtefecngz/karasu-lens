//! `klens_check` handler: syntax-check files right after an edit (read-only).

use std::fs;

use klens_code::{
    CheckTarget, DiffCheckOptions, check_files, format_check_text, format_diff_check_text,
    run_diff_check_with_options,
};
use klens_core::{estimate_tokens, estimate_tokens_from_bytes};
use serde_json::{Value, json};

use crate::error::McpError;
use crate::handler_common::{
    OutputFormat, ToolContext, ToolExecution, open_index, parse_format, parse_optional_bool,
};
use crate::memory_handler::attach_stale_memory_alerts_to_diff;
use crate::protocol::CallToolResult;

/// Read `paths` as an array of strings (a single string is accepted too).
fn parse_paths(args: &Value) -> Result<Vec<String>, McpError> {
    match args.get("paths") {
        Some(Value::String(s)) => Ok(vec![s.clone()]),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str().map(str::to_string).ok_or_else(|| {
                    McpError::InvalidParams("`paths` must contain only strings".to_string())
                })
            })
            .collect(),
        _ => Err(McpError::InvalidParams(
            "`paths` must be an array of file paths, or [\"diff\"] / [\"diff:staged\"]".to_string(),
        )),
    }
}

pub(crate) fn handle_check(ctx: &ToolContext<'_>, args: &Value) -> Result<ToolExecution, McpError> {
    let format = parse_format(args)?;
    let inputs = parse_paths(args)?;
    let target = CheckTarget::from_inputs(&inputs).map_err(McpError::InvalidParams)?;
    let with_diff_check = parse_optional_bool(args, "diff_check")?.unwrap_or(false);

    let mut index = open_index(ctx)?;
    let envelope = check_files(&mut index, &target)?;
    let diff_envelope = if with_diff_check {
        let staged_only = matches!(target, CheckTarget::Diff { staged: true });
        Some(run_diff_check_with_options(
            &mut index,
            DiffCheckOptions { staged_only },
        )?)
    } else {
        None
    };
    drop(index);

    let mut stale_caught = 0;
    let diff_envelope = diff_envelope.map(|mut env| {
        stale_caught = attach_stale_memory_alerts_to_diff(ctx, &mut env);
        env
    });

    let text = match (format, &diff_envelope) {
        (OutputFormat::Text, None) => format_check_text(&envelope).trim_end().to_string(),
        (OutputFormat::Text, Some(diff)) => format!(
            "{}\n\n{}",
            format_check_text(&envelope).trim_end(),
            format_diff_check_text(diff).trim_end()
        ),
        (OutputFormat::Json, None) => envelope.to_deterministic_json()?,
        (OutputFormat::Json, Some(diff)) => {
            let check: Value = serde_json::from_str(&envelope.to_deterministic_json()?)
                .map_err(|e| McpError::InvalidParams(e.to_string()))?;
            let diff: Value = serde_json::from_str(&diff.to_deterministic_json()?)
                .map_err(|e| McpError::InvalidParams(e.to_string()))?;
            json!({ "check": check, "diff_check": diff }).to_string()
        }
    };

    // Raw equivalent: reading every checked file in full.
    let mut raw_bytes = 0usize;
    for file in &envelope.data.files {
        if let Ok((abs, _)) = ctx.project_root.resolve_existing(&file.path)
            && let Ok(meta) = fs::metadata(&abs)
        {
            raw_bytes = raw_bytes.saturating_add(meta.len() as usize);
        }
    }
    let filtered_est = estimate_tokens(&text) as u64;
    let raw_est = (estimate_tokens_from_bytes(raw_bytes) as u64).max(filtered_est);

    Ok(ToolExecution {
        result: CallToolResult::text(text),
        raw_est_tokens: raw_est,
        filtered_est_tokens: filtered_est,
        is_run_filtered: false,
        stale_memories_caught: stale_caught,
    })
}
