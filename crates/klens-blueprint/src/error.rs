//! Error types for the Karasu Lens Blueprint engine (`klens-blueprint`).

use std::path::PathBuf;

use thiserror::Error;

/// Top-level error type for `klens-blueprint`.
#[derive(Debug, Error)]
pub enum BlueprintError {
    #[error(transparent)]
    Core(#[from] klens_core::KlensError),

    #[error(transparent)]
    Path(#[from] klens_core::PathError),

    #[error("I/O error at `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("blueprint artifact not found: {0}")]
    NotFound(String),

    #[error("invalid identifier `{0}`")]
    InvalidId(String),

    #[error("invalid schema_version {found}; expected {expected}")]
    InvalidSchemaVersion { expected: u32, found: u32 },

    #[error("blueprint validation failed: {0}")]
    ValidationFailed(String),

    #[error("cannot lock blueprint: {error_count} error-level conflict(s) detected — {summary}")]
    ConflictsPresent { error_count: usize, summary: String },

    #[error("task `{0}` not found in `.klens/blueprint/tasks.jsonl`")]
    TaskNotFound(String),

    #[error("task `{id}` cannot be completed while blocked by incomplete tasks: {blocked_by}")]
    TaskBlocked { id: String, blocked_by: String },

    #[error("bubble `{0}` not found in `.klens/blueprint/blueprint.json`")]
    BubbleNotFound(String),

    #[error("option `{option_id}` not found in bubble `{bubble_id}`")]
    OptionNotFound {
        bubble_id: String,
        option_id: String,
    },
}
