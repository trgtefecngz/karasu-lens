//! Blueprint board data model (`blueprint.json`, `tasks.jsonl`, `PROJECT_CONTRACT.md`)
//! and confined atomic filesystem persistence (`klens_core::write_atomic`).

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use klens_core::{ProjectRoot, SCHEMA_VERSION, write_atomic};
use serde::{Deserialize, Serialize};

use crate::error::BlueprintError;

/// Relative directory storing persistent Blueprint artifacts (tracked in Git).
pub const BLUEPRINT_DIR_REL: &str = ".klens/blueprint";

/// Relative path to the Blueprint decision graph JSON file.
pub const BLUEPRINT_JSON_REL: &str = ".klens/blueprint/blueprint.json";

/// Relative path to the compiled `USER_LOCKED` architectural contract.
pub const PROJECT_CONTRACT_REL: &str = ".klens/blueprint/PROJECT_CONTRACT.md";

/// Relative path to the compiled dependency-aware task queue (`JSONL`).
pub const TASKS_JSONL_REL: &str = ".klens/blueprint/tasks.jsonl";

const fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

/// Confirmation status of a decision bubble on the Blueprint board.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum BubbleStatus {
    #[default]
    Pending,
    UserConfirmed,
    Skipped,
}

impl BubbleStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::UserConfirmed => "user_confirmed",
            Self::Skipped => "skipped",
        }
    }
}

/// One candidate architectural option inside a [`BlueprintBubble`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlueprintOption {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub pros: String,
    #[serde(default)]
    pub cons: String,
    #[serde(default)]
    pub recommended: bool,
    #[serde(default)]
    pub provides: Vec<String>,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub conflicts_with: Vec<String>,
}

/// One decision bubble on the Blueprint board (`docs/02-DATA-SCHEMAS.md` §6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlueprintBubble {
    pub id: String,
    pub category: String,
    pub title: String,
    #[serde(default)]
    pub plain_explanation: String,
    #[serde(default)]
    pub options: Vec<BlueprintOption>,
    #[serde(default)]
    pub selected_option: Option<String>,
    #[serde(default)]
    pub user_vision_note: String,
    #[serde(default)]
    pub status: BubbleStatus,
    #[serde(default)]
    pub depends_on: Vec<String>,
}

impl BlueprintBubble {
    /// Look up the currently selected [`BlueprintOption`], if any matches `selected_option`.
    pub fn selected_option_ref(&self) -> Option<&BlueprintOption> {
        let target = self.selected_option.as_deref()?;
        self.options.iter().find(|opt| opt.id == target)
    }
}

/// Severity classification for deterministic Blueprint conflict diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictSeverity {
    Error,
    Warning,
}

impl ConflictSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
        }
    }
}

/// Machine-readable category of a deterministic conflict check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    TagConflict,
    MissingRequirement,
    DependencyCycle,
    PendingDecision,
    InvalidSelection,
    UnknownDependency,
    DuplicateBubbleId,
    EmptyBlueprint,
}

/// A single conflict or diagnostic emitted by the deterministic conflict engine.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlueprintConflict {
    pub severity: ConflictSeverity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<ConflictKind>,
    pub bubble_ids: Vec<String>,
    pub message: String,
}

/// Optional directory or starter file entry materialized during `lock_and_execute`.
///
/// Materialization is strictly non-destructive: existing files are NEVER overwritten.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ScaffoldEntry {
    pub path: String,
    #[serde(default)]
    pub is_dir: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

impl ScaffoldEntry {
    /// Convenience constructor for a scaffold directory entry.
    pub fn dir(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            is_dir: true,
            content: None,
        }
    }

    /// Convenience constructor for a scaffold file entry (never overwrites existing files).
    pub fn file(path: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            is_dir: false,
            content: Some(content.into()),
        }
    }
}

/// Root persistent schema for `.klens/blueprint/blueprint.json` (`docs/02-DATA-SCHEMAS.md` §6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blueprint {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub project_name: String,
    pub goal: String,
    #[serde(default)]
    pub locked: bool,
    #[serde(default)]
    pub locked_at: Option<String>,
    #[serde(default)]
    pub bubbles: Vec<BlueprintBubble>,
    #[serde(default)]
    pub conflicts: Vec<BlueprintConflict>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scaffold: Vec<ScaffoldEntry>,
}

impl Blueprint {
    /// Create a fresh unlocked Blueprint pinned to `schema_version = 1`.
    pub fn new(project_name: impl Into<String>, goal: impl Into<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            project_name: project_name.into(),
            goal: goal.into(),
            locked: false,
            locked_at: None,
            bubbles: Vec::new(),
            conflicts: Vec::new(),
            scaffold: Vec::new(),
        }
    }

    /// Validate top-level structural invariants (`schema_version == 1`, non-empty IDs).
    pub fn validate_schema(&self) -> Result<(), BlueprintError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BlueprintError::InvalidSchemaVersion {
                expected: SCHEMA_VERSION,
                found: self.schema_version,
            });
        }
        if self.project_name.trim().is_empty() {
            return Err(BlueprintError::ValidationFailed(
                "`project_name` cannot be empty".to_string(),
            ));
        }
        for bubble in &self.bubbles {
            validate_identifier(&bubble.id)?;
            let mut seen_option_ids: BTreeSet<&str> = BTreeSet::new();
            for opt in &bubble.options {
                validate_identifier(&opt.id)?;
                if !seen_option_ids.insert(opt.id.as_str()) {
                    return Err(BlueprintError::ValidationFailed(format!(
                        "duplicate option id `{}` in bubble `{}`",
                        opt.id, bubble.id
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Lifecycle state of a single compiled task in `.klens/blueprint/tasks.jsonl`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    #[default]
    Pending,
    InProgress,
    Done,
}

impl TaskStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::InProgress => "in_progress",
            Self::Done => "done",
        }
    }
}

/// Single dependency-aware task stored as one line in `.klens/blueprint/tasks.jsonl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlueprintTask {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub blocked_by: Vec<String>,
    #[serde(default)]
    pub expected_files: Vec<String>,
    #[serde(default)]
    pub verification_cmd: Option<String>,
    #[serde(default)]
    pub status: TaskStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bubble_id: Option<String>,
}

/// Validate a safe non-empty ASCII/UTF-8 identifier without whitespace or path separators.
pub fn validate_identifier(id: &str) -> Result<(), BlueprintError> {
    let trimmed = id.trim();
    if trimmed.is_empty()
        || trimmed != id
        || trimmed.len() > 128
        || trimmed
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '/' || c == '\\')
    {
        return Err(BlueprintError::InvalidId(id.to_string()));
    }
    Ok(())
}

/// Load `.klens/blueprint/blueprint.json` under strict `ProjectRoot` confinement.
pub fn load_blueprint(project_root: &ProjectRoot) -> Result<Blueprint, BlueprintError> {
    let abs = match project_root.resolve_existing(BLUEPRINT_JSON_REL) {
        Ok((path, _)) => path,
        Err(klens_core::PathError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Err(BlueprintError::NotFound(BLUEPRINT_JSON_REL.to_string()));
        }
        Err(err) => return Err(BlueprintError::Path(err)),
    };

    let raw =
        fs::read_to_string(&abs).map_err(|source| BlueprintError::Io { path: abs, source })?;
    let blueprint: Blueprint = serde_json::from_str(&raw)?;
    blueprint.validate_schema()?;
    Ok(blueprint)
}

/// Load `.klens/blueprint/blueprint.json` if it exists, returning `Ok(None)` when absent.
pub fn load_blueprint_optional(
    project_root: &ProjectRoot,
) -> Result<Option<Blueprint>, BlueprintError> {
    match load_blueprint(project_root) {
        Ok(bp) => Ok(Some(bp)),
        Err(BlueprintError::NotFound(_)) => Ok(None),
        Err(err) => Err(err),
    }
}

/// Atomically persist `.klens/blueprint/blueprint.json` under `ProjectRoot` confinement.
pub fn save_blueprint(
    project_root: &ProjectRoot,
    blueprint: &Blueprint,
) -> Result<PathBuf, BlueprintError> {
    blueprint.validate_schema()?;
    let (abs, _) = project_root.resolve_for_write(BLUEPRINT_JSON_REL)?;
    let mut encoded = serde_json::to_string_pretty(blueprint)?;
    encoded.push('\n');
    write_atomic(&abs, encoded.as_bytes())?;
    Ok(abs)
}

/// Load `.klens/blueprint/tasks.jsonl` under strict `ProjectRoot` confinement.
pub fn load_tasks(project_root: &ProjectRoot) -> Result<Vec<BlueprintTask>, BlueprintError> {
    let abs = match project_root.resolve_existing(TASKS_JSONL_REL) {
        Ok((path, _)) => path,
        Err(klens_core::PathError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Err(BlueprintError::NotFound(TASKS_JSONL_REL.to_string()));
        }
        Err(err) => return Err(BlueprintError::Path(err)),
    };

    let raw =
        fs::read_to_string(&abs).map_err(|source| BlueprintError::Io { path: abs, source })?;
    parse_tasks_jsonl(&raw)
}

/// Load `.klens/blueprint/tasks.jsonl` if present, or return an empty `Vec` if absent.
pub fn load_tasks_optional(
    project_root: &ProjectRoot,
) -> Result<Vec<BlueprintTask>, BlueprintError> {
    match load_tasks(project_root) {
        Ok(tasks) => Ok(tasks),
        Err(BlueprintError::NotFound(_)) => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

/// Parse deterministic JSONL task lines.
pub fn parse_tasks_jsonl(raw: &str) -> Result<Vec<BlueprintTask>, BlueprintError> {
    let mut tasks = Vec::new();
    for (idx, raw_line) in raw.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let task: BlueprintTask = serde_json::from_str(line).map_err(|err| {
            BlueprintError::ValidationFailed(format!(
                "invalid JSONL task at line {}: {err}",
                idx + 1
            ))
        })?;
        validate_identifier(&task.id)?;
        tasks.push(task);
    }
    Ok(tasks)
}

/// Serialize tasks to deterministic JSONL (one compact JSON object per line, trailing LF).
pub fn serialize_tasks_jsonl(tasks: &[BlueprintTask]) -> Result<String, BlueprintError> {
    let mut out = String::new();
    for task in tasks {
        validate_identifier(&task.id)?;
        let line = serde_json::to_string(task)?;
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

/// Atomically persist `.klens/blueprint/tasks.jsonl` under `ProjectRoot` confinement.
pub fn save_tasks(
    project_root: &ProjectRoot,
    tasks: &[BlueprintTask],
) -> Result<PathBuf, BlueprintError> {
    let encoded = serialize_tasks_jsonl(tasks)?;
    let (abs, _) = project_root.resolve_for_write(TASKS_JSONL_REL)?;
    write_atomic(&abs, encoded.as_bytes())?;
    Ok(abs)
}

/// Read `.klens/blueprint/PROJECT_CONTRACT.md` if it exists.
pub fn load_contract_optional(
    project_root: &ProjectRoot,
) -> Result<Option<String>, BlueprintError> {
    let abs = match project_root.resolve_existing(PROJECT_CONTRACT_REL) {
        Ok((path, _)) => path,
        Err(klens_core::PathError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(None);
        }
        Err(err) => return Err(BlueprintError::Path(err)),
    };

    let content =
        fs::read_to_string(&abs).map_err(|source| BlueprintError::Io { path: abs, source })?;
    Ok(Some(content))
}
