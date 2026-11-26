use std::path::PathBuf;

use klens_core::{KlensError, PathError};
use thiserror::Error;

/// Errors returned by `klens-code` indexing, storage, parsing, and surgical reading.
#[derive(Debug, Error)]
pub enum CodeError {
    #[error(transparent)]
    Core(#[from] KlensError),

    #[error(transparent)]
    Path(#[from] PathError),

    #[error("SQLite index error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("I/O error at `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("tree-sitter ABI mismatch for `{language}`: {reason}")]
    TreeSitterAbi { language: String, reason: String },

    #[error("invalid line range `{spec}`: {reason}")]
    InvalidLineRange { spec: String, reason: String },

    #[error("target path is not a regular file: {0}")]
    NotAFile(String),

    #[error("path not found in indexed workspace: {0}")]
    PathNotFound(String),

    #[error("cannot resolve home directory for read-only cache")]
    MissingHomeDir,

    #[error("read target must specify either `--symbol` or `--lines` (not both or neither)")]
    InvalidReadTarget,

    #[error("invalid read include `{0}`; expected one of `imports`, `memory`, `impact`")]
    InvalidReadInclude(String),

    #[error("file is binary and cannot be read as UTF-8 source: {0}")]
    BinaryFile(String),
}
