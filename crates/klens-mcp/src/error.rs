//! Error types for the Karasu Lens MCP server (`klens-mcp`).

use thiserror::Error;

/// Top-level error type for `klens-mcp`.
#[derive(Debug, Error)]
pub enum McpError {
    #[error(transparent)]
    Core(#[from] klens_core::KlensError),

    #[error(transparent)]
    Path(#[from] klens_core::PathError),

    #[error(transparent)]
    Code(#[from] klens_code::CodeError),

    #[error(transparent)]
    Exec(#[from] klens_exec::ExecError),

    #[error(transparent)]
    Memory(#[from] klens_memory::MemoryError),

    #[error(transparent)]
    Blueprint(#[from] klens_blueprint::BlueprintError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid tool parameters: {0}")]
    InvalidParams(String),

    #[error("unknown MCP tool: {0}")]
    UnknownTool(String),
}
