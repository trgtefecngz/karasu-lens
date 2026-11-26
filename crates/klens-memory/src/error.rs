//! Error types for the Karasu Lens verifiable memory vault (`klens-memory`).

use std::path::PathBuf;

use thiserror::Error;

/// Top-level error type for `klens-memory`.
#[derive(Debug, Error)]
pub enum MemoryError {
    #[error(transparent)]
    Core(#[from] klens_core::KlensError),

    #[error(transparent)]
    Path(#[from] klens_core::PathError),

    #[error("SQLite FTS5 error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("I/O error at `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid memory note id `{0}`")]
    InvalidId(String),

    #[error(
        "invalid memory note kind `{0}` (expected decision|bugfix|architecture|feedback|constraint)"
    )]
    InvalidKind(String),

    #[error("invalid memory note status `{0}` (expected active|stale|archived)")]
    InvalidStatus(String),

    #[error("invalid memory export format `{0}` (expected md|markdown|json)")]
    InvalidExportFormat(String),

    #[error("memory note not found: `{0}`")]
    NotFound(String),

    #[error("memory note already exists: `{0}`")]
    AlreadyExists(String),

    #[error("malformed YAML frontmatter in `{path}`: {reason}")]
    FrontmatterParse { path: String, reason: String },

    #[error("failed to resolve anchor `{path}`{}: {reason}", symbol.as_deref().map(|s| format!("#{s}")).unwrap_or_default())]
    AnchorResolveFailed {
        path: String,
        symbol: Option<String>,
        reason: String,
    },
}
