//! Shared leaf context and argument parsing helpers for `klens-mcp` tool handlers.

use std::path::Path;

use klens_code::CodeIndex;
use klens_core::{ProjectMode, ProjectRoot};
use serde_json::Value;

use crate::error::McpError;
use crate::protocol::CallToolResult;

/// Context provided to every MCP tool invocation.
pub(crate) struct ToolContext<'a> {
    pub project_root: &'a ProjectRoot,
    pub mode: ProjectMode,
    pub readonly_cache_dir: Option<&'a Path>,
}

/// Result of executing one MCP tool, paired with honest token measurements for Layer 1 telemetry.
pub(crate) struct ToolExecution {
    pub result: CallToolResult,
    pub raw_est_tokens: u64,
    pub filtered_est_tokens: u64,
    pub is_run_filtered: bool,
    pub stale_memories_caught: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputFormat {
    Text,
    Json,
}

pub(crate) fn open_index(ctx: &ToolContext<'_>) -> Result<CodeIndex, McpError> {
    let read_only = ctx.mode == ProjectMode::ReadOnly;
    let index = match ctx.readonly_cache_dir {
        Some(dir) => {
            CodeIndex::open_with_readonly_cache_dir(ctx.project_root.clone(), read_only, dir)?
        }
        None => CodeIndex::open(ctx.project_root.clone(), read_only)?,
    };
    Ok(index)
}

pub(crate) fn parse_format(args: &Value) -> Result<OutputFormat, McpError> {
    match args.get("format") {
        None | Some(Value::Null) => Ok(OutputFormat::Text),
        Some(val) => match val.as_str() {
            Some("text") => Ok(OutputFormat::Text),
            Some("json") => Ok(OutputFormat::Json),
            Some(other) => Err(McpError::InvalidParams(format!(
                "unsupported format `{other}`; expected `text` or `json`"
            ))),
            None => Err(McpError::InvalidParams(
                "`format` must be a string (`text` or `json`)".to_string(),
            )),
        },
    }
}

pub(crate) fn parse_optional_usize(args: &Value, field: &str) -> Result<Option<usize>, McpError> {
    match args.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(val) => {
            let n = val.as_u64().ok_or_else(|| {
                McpError::InvalidParams(format!("`{field}` must be a positive integer"))
            })?;
            usize::try_from(n)
                .map(Some)
                .map_err(|_| McpError::InvalidParams(format!("`{field}` is out of range")))
        }
    }
}

pub(crate) fn parse_optional_bool(args: &Value, field: &str) -> Result<Option<bool>, McpError> {
    match args.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(val) => val
            .as_bool()
            .map(Some)
            .ok_or_else(|| McpError::InvalidParams(format!("`{field}` must be a boolean"))),
    }
}

pub(crate) fn parse_optional_string(args: &Value, field: &str) -> Result<Option<String>, McpError> {
    match args.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(val) => val
            .as_str()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| McpError::InvalidParams(format!("`{field}` must be a string"))),
    }
}
