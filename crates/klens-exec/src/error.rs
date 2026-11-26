use std::path::PathBuf;

use thiserror::Error;

/// Errors produced by `klens-exec` (command execution, run storage, and git checkpoints).
#[derive(Debug, Error)]
pub enum ExecError {
    #[error(transparent)]
    Core(#[from] klens_core::KlensError),

    #[error(transparent)]
    Path(#[from] klens_core::PathError),

    #[error("command cannot be empty")]
    EmptyCommand,

    #[error("failed to spawn `{program}`: {source}")]
    SpawnFailed {
        program: String,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid run id `{0}`")]
    InvalidRunId(String),

    #[error("run not found: `{0}`")]
    RunNotFound(String),

    #[error("checkpoint operation requires a git repository at `{0}`")]
    NotAGitRepository(PathBuf),

    #[error("invalid checkpoint id `{0}`")]
    InvalidCheckpointId(String),

    #[error("checkpoint not found: `{0}`")]
    CheckpointNotFound(String),

    #[error("ambiguous checkpoint prefix `{query}`; matches: {candidates}")]
    AmbiguousCheckpoint { query: String, candidates: String },

    #[error("git command `{args}` failed (exit {code:?}): {stderr}")]
    GitCommandFailed {
        args: String,
        code: Option<i32>,
        stderr: String,
    },

    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("I/O error at `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}
