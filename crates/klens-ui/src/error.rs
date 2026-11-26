//! Error types and deterministic HTTP status mapping for `klens-ui`.

use klens_adapters::AdapterError;
use klens_blueprint::BlueprintError;
use klens_code::CodeError;
use klens_core::{KlensError, PathError};
use klens_exec::ExecError;
use klens_memory::MemoryError;
use thiserror::Error;

/// Unified error type returned by `klens-ui` server and API handlers.
#[derive(Debug, Error)]
pub enum UiError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("method not allowed: {0}")]
    MethodNotAllowed(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("read-only mode is active; write operation `{0}` is forbidden")]
    ReadOnlyForbidden(String),

    #[error("no active project selected")]
    NoActiveProject,

    #[error("failed to bind local UI server on 127.0.0.1:{port}: {reason}")]
    BindFailed { port: u16, reason: String },

    #[error("failed to launch browser: {0}")]
    BrowserLaunch(String),

    #[error(transparent)]
    Core(#[from] KlensError),

    #[error(transparent)]
    Path(#[from] PathError),

    #[error(transparent)]
    Code(#[from] CodeError),

    #[error(transparent)]
    Exec(#[from] ExecError),

    #[error(transparent)]
    Memory(#[from] MemoryError),

    #[error(transparent)]
    Blueprint(#[from] BlueprintError),

    #[error(transparent)]
    Adapter(#[from] AdapterError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl UiError {
    /// Map this error to an accurate HTTP status code and machine-readable error code.
    pub fn http_status(&self) -> (u16, &'static str) {
        match self {
            Self::BadRequest(_) | Self::Json(_) => (400, "bad_request"),
            Self::Core(KlensError::InvalidExtensionId { .. }) => (400, "invalid_extension_id"),
            Self::Core(KlensError::ProjectScopedLanguageParser { .. }) => {
                (403, "project_scoped_language_parser")
            }
            Self::Unauthorized(_) => (401, "unauthorized"),
            Self::Forbidden(_) | Self::ReadOnlyForbidden(_) => (403, "forbidden"),
            Self::NotFound(_) => (404, "not_found"),
            Self::MethodNotAllowed(_) => (405, "method_not_allowed"),
            Self::Conflict(_) => (409, "conflict"),
            Self::NoActiveProject => (409, "no_active_project"),
            Self::Path(err)
            | Self::Core(KlensError::Path(err))
            | Self::Code(CodeError::Path(err) | CodeError::Core(KlensError::Path(err)))
            | Self::Memory(MemoryError::Path(err) | MemoryError::Core(KlensError::Path(err)))
            | Self::Blueprint(
                BlueprintError::Path(err) | BlueprintError::Core(KlensError::Path(err)),
            )
            | Self::Exec(ExecError::Path(err) | ExecError::Core(KlensError::Path(err)))
            | Self::Adapter(AdapterError::Core(KlensError::Path(err))) => map_path_error(err),
            Self::Blueprint(
                BlueprintError::NotFound(_)
                | BlueprintError::BubbleNotFound(_)
                | BlueprintError::TaskNotFound(_),
            ) => (404, "not_found"),
            Self::Blueprint(
                BlueprintError::ConflictsPresent { .. } | BlueprintError::TaskBlocked { .. },
            ) => (409, "conflicts_present"),
            Self::Blueprint(
                BlueprintError::ValidationFailed(_)
                | BlueprintError::InvalidId(_)
                | BlueprintError::OptionNotFound { .. }
                | BlueprintError::InvalidSchemaVersion { .. },
            ) => (400, "invalid_blueprint"),
            Self::Memory(MemoryError::NotFound(_)) => (404, "not_found"),
            Self::Memory(MemoryError::AlreadyExists(_)) => (409, "already_exists"),
            Self::Memory(
                MemoryError::InvalidId(_)
                | MemoryError::InvalidKind(_)
                | MemoryError::InvalidStatus(_)
                | MemoryError::InvalidExportFormat(_)
                | MemoryError::FrontmatterParse { .. }
                | MemoryError::AnchorResolveFailed { .. },
            ) => (400, "invalid_memory_request"),
            Self::Code(
                CodeError::InvalidLineRange { .. }
                | CodeError::InvalidReadTarget
                | CodeError::NotAFile(_)
                | CodeError::BinaryFile(_),
            ) => (400, "invalid_code_request"),
            Self::Exec(ExecError::RunNotFound(_) | ExecError::CheckpointNotFound(_)) => {
                (404, "not_found")
            }
            Self::Exec(
                ExecError::InvalidRunId(_)
                | ExecError::InvalidCheckpointId(_)
                | ExecError::AmbiguousCheckpoint { .. }
                | ExecError::NotAGitRepository(_),
            ) => (400, "invalid_exec_request"),
            Self::Adapter(AdapterError::InvalidScanDir(_)) => (400, "invalid_scan_dir"),
            _ => (500, "internal_error"),
        }
    }
}

fn map_path_error(err: &PathError) -> (u16, &'static str) {
    match err {
        PathError::SensitiveFileBlocked(_) | PathError::EscapesRoot(_) => (403, "path_forbidden"),
        PathError::UnsafeProjectRoot { .. } => (400, "unsafe_project_root"),
        _ => (400, "invalid_path"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_path_errors_never_fall_through_to_500() {
        let forbidden_cases: Vec<UiError> = vec![
            UiError::Path(PathError::EscapesRoot("../x".into())),
            UiError::Core(KlensError::Path(PathError::SensitiveFileBlocked(
                ".env".into(),
            ))),
            UiError::Memory(MemoryError::Path(PathError::EscapesRoot("../x".into()))),
            UiError::Blueprint(BlueprintError::Path(PathError::SensitiveFileBlocked(
                ".env".into(),
            ))),
            UiError::Exec(ExecError::Path(PathError::EscapesRoot("../x".into()))),
            UiError::Code(CodeError::Path(PathError::SensitiveFileBlocked(
                ".env".into(),
            ))),
            UiError::Adapter(AdapterError::Core(KlensError::Path(
                PathError::EscapesRoot("../x".into()),
            ))),
        ];
        for err in forbidden_cases {
            assert_eq!(err.http_status(), (403, "path_forbidden"));
        }

        let invalid_cases: Vec<UiError> = vec![
            UiError::Path(PathError::TraversalAttempt("../escape.rs".into())),
            UiError::Core(KlensError::Path(PathError::TraversalAttempt(
                "../escape.rs".into(),
            ))),
            UiError::Memory(MemoryError::Path(PathError::TraversalAttempt(
                "../escape.rs".into(),
            ))),
            UiError::Blueprint(BlueprintError::Path(PathError::TraversalAttempt(
                "../escape.rs".into(),
            ))),
            UiError::Exec(ExecError::Path(PathError::TraversalAttempt(
                "../escape.rs".into(),
            ))),
            UiError::Code(CodeError::Path(PathError::TraversalAttempt(
                "../escape.rs".into(),
            ))),
        ];
        for err in invalid_cases {
            assert_eq!(err.http_status(), (400, "invalid_path"));
        }
    }
}
