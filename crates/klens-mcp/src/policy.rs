//! Per-project access policy enforcement for `klens-mcp`.
//!
//! Before every `tools/call`, inspects `.klens/config.toml` (`mode` and `allowed_clients`)
//! and denies unauthorized calls with `PROJECT_ACCESS_RESTRICTED`.

use klens_core::{ProjectConfig, ProjectMode, ProjectRoot};
use serde_json::Value;

/// Canonical error code returned when project access policy blocks a tool call.
pub const PROJECT_ACCESS_RESTRICTED: &str = "PROJECT_ACCESS_RESTRICTED";

/// Reason why a tool call was denied by `.klens/config.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDenial {
    pub code: &'static str,
    pub reason: String,
}

/// Returns `true` if `tool_name` is a strictly read-only analysis tool allowed in `read_only` mode.
pub fn is_read_only_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "klens_map" | "klens_find" | "klens_outline" | "klens_read" | "klens_impact"
    )
}

/// Returns `true` if a specific `(tool_name, arguments)` invocation is strictly read-only.
///
/// For `klens_memory`, `index`, `list`, `get`, `search`, and `verify` are strictly read-only,
/// while `add`, `update`, `delete`, and `refresh` mutate `.klens/memory/` and are blocked in `read_only`.
pub fn is_read_only_tool_call(tool_name: &str, arguments: &Value) -> bool {
    if is_read_only_tool(tool_name) {
        return true;
    }
    if tool_name == "klens_memory" {
        return matches!(
            arguments
                .get("action")
                .and_then(Value::as_str)
                .map(str::trim),
            Some("index" | "list" | "get" | "search" | "verify")
        );
    }
    if tool_name == "klens_blueprint" {
        return matches!(
            arguments
                .get("action")
                .and_then(Value::as_str)
                .map(str::trim),
            Some("status" | "check" | "next_task" | "handoff")
        );
    }
    false
}

/// Evaluate `.klens/config.toml` access rules for `(client_name, tool_name)`.
///
/// Rules:
/// 1. If `config.allowed_clients` is non-empty, the connecting MCP client's `clientInfo.name`
///    MUST match one of the entries (case-insensitive). Missing/unknown client names are denied.
/// 2. If `config.mode == ProjectMode::Paused`, ALL tool calls are denied.
/// 3. If `config.mode == ProjectMode::ReadOnly`, only read-only tools are permitted;
///    mutating/execution tools like `klens_run` are denied.
/// 4. If `config.mode == ProjectMode::Active`, all tools are permitted.
pub fn check_tool_access(
    project_root: &ProjectRoot,
    client_name: Option<&str>,
    tool_name: &str,
) -> Result<ProjectConfig, PolicyDenial> {
    check_tool_call_access(project_root, client_name, tool_name, &Value::Null)
}

/// Evaluate `.klens/config.toml` access rules for `(client_name, tool_name, arguments)`.
pub fn check_tool_call_access(
    project_root: &ProjectRoot,
    client_name: Option<&str>,
    tool_name: &str,
    arguments: &Value,
) -> Result<ProjectConfig, PolicyDenial> {
    let cfg_path = project_root.root().join(".klens").join("config.toml");
    let config = ProjectConfig::load_or_default(&cfg_path).map_err(|err| PolicyDenial {
        code: PROJECT_ACCESS_RESTRICTED,
        reason: format!("failed to load project policy `.klens/config.toml`: {err}"),
    })?;

    evaluate_policy_for_call(&config, client_name, tool_name, arguments)?;
    Ok(config)
}

/// Pure policy check against an already-loaded [`ProjectConfig`].
pub fn evaluate_policy(
    config: &ProjectConfig,
    client_name: Option<&str>,
    tool_name: &str,
) -> Result<(), PolicyDenial> {
    evaluate_policy_for_call(config, client_name, tool_name, &Value::Null)
}

/// Pure policy check inspecting both tool name and action arguments.
pub fn evaluate_policy_for_call(
    config: &ProjectConfig,
    client_name: Option<&str>,
    tool_name: &str,
    arguments: &Value,
) -> Result<(), PolicyDenial> {
    if !config.allowed_clients.is_empty() {
        let caller = client_name.map(str::trim).filter(|s| !s.is_empty());
        let allowed = caller.is_some_and(|name| {
            config
                .allowed_clients
                .iter()
                .any(|entry| entry.trim().eq_ignore_ascii_case(name))
        });
        if !allowed {
            let caller_label = caller.unwrap_or("<unidentified>");
            return Err(PolicyDenial {
                code: PROJECT_ACCESS_RESTRICTED,
                reason: format!(
                    "client `{caller_label}` is not in project `allowed_clients` ({:?})",
                    config.allowed_clients
                ),
            });
        }
    }

    match config.mode {
        ProjectMode::Paused => Err(PolicyDenial {
            code: PROJECT_ACCESS_RESTRICTED,
            reason: format!("project mode is `paused`; tool `{tool_name}` is blocked"),
        }),
        ProjectMode::ReadOnly if !is_read_only_tool_call(tool_name, arguments) => {
            Err(PolicyDenial {
                code: PROJECT_ACCESS_RESTRICTED,
                reason: format!(
                    "project mode is `read_only`; execution/write tool `{tool_name}` is blocked"
                ),
            })
        }
        ProjectMode::ReadOnly | ProjectMode::Active => Ok(()),
    }
}
