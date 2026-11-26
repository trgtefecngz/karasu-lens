use std::path::PathBuf;
use thiserror::Error;

/// Errors returned when validating or confining file system paths.
#[derive(Debug, Error)]
pub enum PathError {
    #[error("path cannot be empty")]
    EmptyPath,

    #[error("path traversal (`..`) is forbidden: {0}")]
    TraversalAttempt(String),

    #[error("absolute path or drive prefix is not allowed where a relative path is required: {0}")]
    AbsolutePathNotAllowed(String),

    #[error("invalid path segment ({reason}): {path}")]
    InvalidSegment { path: String, reason: &'static str },

    #[error("path escapes the project root (possibly via symlink): {0}")]
    EscapesRoot(String),

    #[error("project root is not a valid directory: {0}")]
    InvalidRoot(PathBuf),

    #[error(
        "refusing to use `{path}` as a project root because {reason}; choose a specific project folder instead (for example the folder that contains `.git`), or pass `--root <project>` / `--project <project>`"
    )]
    UnsafeProjectRoot { path: PathBuf, reason: &'static str },

    #[error(
        "`{path}` is a symbolic link or junction; klens keeps its state only in a real `.klens` folder inside the project. Remove the link and try again"
    )]
    LinkedStateEntry { path: PathBuf },

    #[error("access denied to sensitive file: {0}")]
    SensitiveFileBlocked(String),

    #[error("path contains non-UTF-8 characters: {0:?}")]
    NonUtf8Path(PathBuf),

    #[error("I/O error while accessing path `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Top-level error type for `klens-core`.
#[derive(Debug, Error)]
pub enum KlensError {
    #[error(transparent)]
    Path(#[from] PathError),

    #[error("invalid schema_version: expected {expected}, found {found}")]
    InvalidSchemaVersion { expected: u32, found: u32 },

    #[error("invalid or unknown extension id `{id}` (known extensions: {known})")]
    InvalidExtensionId { id: String, known: String },

    #[error(
        "language parser `{id}` runs an external program and can only be enabled globally (`klens ext enable {id} --global`); project-level enablement is ignored for security"
    )]
    ProjectScopedLanguageParser { id: String },

    #[error("configuration parse error: {0}")]
    ConfigParse(String),

    #[error("configuration serialization error: {0}")]
    ConfigSerialize(#[from] toml::ser::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
