//! Ultra-lightweight MCP tool schema definitions for Phase 3A.
//!
//! Constitutional token budget lock:
//! - Total `tools/list` response across all future phases MUST stay `< 1,200` tokens.
//! - Phase 3A's first 6 tools target `<= 850` tokens to preserve generous headroom for
//!   Phase 4 (`klens_memory`) and Phase 5A (`klens_blueprint`).

use serde::Serialize;
use serde_json::{Value, json};

/// Hard constitutional ceiling for the full `tools/list` JSON response.
pub const MAX_TOOLS_LIST_TOKENS: usize = 1_200;

/// Phase 3A target ceiling for the first 6 tools so Phase 4 & 5A fit comfortably.
pub const PHASE3A_TOOLS_LIST_TARGET_TOKENS: usize = 850;

/// Phase 4 target ceiling for 7 tools (preserving headroom for Phase 5A's `klens_blueprint` under `< 1,200`).
pub const PHASE4_TOOLS_LIST_TARGET_TOKENS: usize = 1_000;

/// MCP tool behavioral hints (`ToolAnnotations`) returned by `tools/list`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolAnnotations {
    pub read_only_hint: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destructive_hint: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotent_hint: Option<bool>,
    pub open_world_hint: bool,
}

impl ToolAnnotations {
    const fn read_only() -> Self {
        Self {
            read_only_hint: true,
            destructive_hint: Some(false),
            idempotent_hint: Some(true),
            open_world_hint: false,
        }
    }

    const fn mutating() -> Self {
        Self {
            read_only_hint: false,
            destructive_hint: None,
            idempotent_hint: None,
            open_world_hint: false,
        }
    }
}

/// Compact MCP tool descriptor returned by `tools/list`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDefinition {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
    pub annotations: ToolAnnotations,
}

/// Return the deterministic, ultra-compact list of MCP tools.
pub fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "klens_map",
            description: "PageRank project map and dependency summary within token budget.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Focus subdir/file" },
                    "budget": { "type": "integer", "description": "Max tokens (default 2000)" },
                    "format": { "type": "string", "enum": ["text", "json"] }
                }
            }),
            annotations: ToolAnnotations::read_only(),
        },
        ToolDefinition {
            name: "klens_find",
            description: "Gitignore-aware FTS5 symbol and text search with exact line numbers.",
            input_schema: json!({
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": { "type": "string" },
                    "limit": { "type": "integer", "description": "Max hits (default 20)" },
                    "format": { "type": "string", "enum": ["text", "json"] }
                }
            }),
            annotations: ToolAnnotations::read_only(),
        },
        ToolDefinition {
            name: "klens_outline",
            description: "AST symbol outline with line ranges for a file or directory.",
            input_schema: json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string" },
                    "budget": { "type": "integer" },
                    "format": { "type": "string", "enum": ["text", "json"] }
                }
            }),
            annotations: ToolAnnotations::read_only(),
        },
        ToolDefinition {
            name: "klens_read",
            description: "Read qualified symbol, line range (start:end), or batch targets with line numbers.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "symbol": { "type": "string" },
                    "lines": { "type": "string", "description": "start:end" },
                    "targets": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["path"],
                            "properties": {
                                "path": { "type": "string" },
                                "symbol": { "type": "string" },
                                "lines": { "type": "string" }
                            }
                        }
                    },
                    "include": { "type": "array", "items": { "type": "string", "enum": ["imports", "memory", "impact"] } },
                    "format": { "type": "string", "enum": ["text", "json"] }
                }
            }),
            annotations: ToolAnnotations::read_only(),
        },
        ToolDefinition {
            name: "klens_impact",
            description: "Before edits: dependents of a file, symbol, or diff.",
            input_schema: json!({
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": { "type": "string", "description": "path, symbol, path#symbol, diff, or diff:staged" },
                    "budget": { "type": "integer" },
                    "format": { "type": "string", "enum": ["text", "json"] }
                }
            }),
            annotations: ToolAnnotations::read_only(),
        },
        ToolDefinition {
            name: "klens_run",
            description: "Run command with ANSI-clean filter, zero error loss, and raw log path.",
            input_schema: json!({
                "type": "object",
                "required": ["command"],
                "properties": {
                    "command": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Program and args"
                    },
                    "timeout_secs": { "type": "integer", "description": "Default 600" },
                    "raw": { "type": "boolean" },
                    "auto_context": { "type": "boolean" },
                    "format": { "type": "string", "enum": ["text", "json"] }
                }
            }),
            annotations: ToolAnnotations::mutating(),
        },
        ToolDefinition {
            name: "klens_memory",
            description: "Progressive memory index, BLAKE3-verified get/search/verify, and note CRUD.",
            input_schema: json!({
                "type": "object",
                "required": ["action"],
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["index", "get", "search", "add", "update", "delete", "verify", "refresh"]
                    },
                    "id": { "type": "string" },
                    "query": { "type": "string" },
                    "title": { "type": "string" },
                    "kind": { "type": "string", "enum": ["decision", "bugfix", "architecture", "feedback", "constraint"] },
                    "body": { "type": "string" },
                    "anchors": { "type": "array", "items": { "type": "string" }, "description": "path or path#symbol" },
                    "tags": { "type": "array", "items": { "type": "string" } },
                    "limit": { "type": "integer" },
                    "format": { "type": "string", "enum": ["text", "json"] }
                }
            }),
            annotations: ToolAnnotations::mutating(),
        },
        ToolDefinition {
            name: "klens_blueprint",
            description: "Blueprint status/propose/select/check/lock, task queue, and session handoff.",
            input_schema: json!({
                "type": "object",
                "required": ["action"],
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["status", "check", "propose", "select", "lock", "next_task", "complete_task", "handoff"]
                    },
                    "blueprint": { "type": "object" },
                    "bubble_id": { "type": "string" },
                    "option_id": { "type": "string" },
                    "vision_note": { "type": "string" },
                    "confirm": { "type": "boolean" },
                    "task_id": { "type": "string" },
                    "create_scaffold": { "type": "boolean" },
                    "budget": { "type": "integer" },
                    "format": { "type": "string", "enum": ["text", "json"] }
                }
            }),
            annotations: ToolAnnotations::mutating(),
        },
    ]
}
