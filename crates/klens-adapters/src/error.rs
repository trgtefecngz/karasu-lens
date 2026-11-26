use std::path::PathBuf;

use klens_core::KlensError;
use thiserror::Error;

/// Errors returned by `klens-adapters` operations.
#[derive(Debug, Error)]
pub enum AdapterError {
    #[error(transparent)]
    Core(#[from] KlensError),

    #[error("could not determine user home directory (`USERPROFILE` / `HOME` not set)")]
    HomeDirUnavailable,

    #[error(
        "unknown host adapter `{0}`; expected one of: auto, antigravity, claude-code, codex, generic, all"
    )]
    UnknownHost(String),

    #[error("file `{path}` is not valid UTF-8: {reason}")]
    InvalidUtf8 { path: PathBuf, reason: String },

    #[error("malformed klens marker block in `{path}`: {reason}")]
    MalformedMarkerBlock { path: PathBuf, reason: String },

    #[error("invalid JSON configuration in `{path}`: {reason}")]
    InvalidJsonConfig { path: PathBuf, reason: String },

    #[error("invalid TOML configuration in `{path}`: {reason}")]
    InvalidTomlConfig { path: PathBuf, reason: String },

    #[error(
        "`{path}` kept changing while klens was updating it (another program is writing it); nothing was written, run the command again"
    )]
    ConfigChangedDuringUpdate { path: PathBuf },

    #[error(
        "the repository's own `core.hooksPath` points outside the repository (`{path}`); refusing to install the pre-commit hook there"
    )]
    UntrustedHooksPath { path: PathBuf },

    #[error(
        "`{path}` is a symbolic link or junction; refusing to write AI host files through it (remove the link and try again)"
    )]
    LinkedProjectPath { path: PathBuf },

    #[error("refusing to uninstall without explicit `--all` confirmation flag")]
    UninstallRequiresAllFlag,

    #[error("scan target is not a valid directory: {0}")]
    InvalidScanDir(PathBuf),

    #[error("target project is not a git repository: {0}")]
    NotAGitRepo(PathBuf),

    #[error("I/O error at `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl From<AdapterError> for KlensError {
    fn from(err: AdapterError) -> Self {
        match err {
            AdapterError::Core(core) => core,
            AdapterError::Io { source, .. } => KlensError::Io(source),
            other => KlensError::Io(std::io::Error::other(other.to_string())),
        }
    }
}
