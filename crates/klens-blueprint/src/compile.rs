//! Blueprint locking, `PROJECT_CONTRACT.md` + `tasks.jsonl` compilation,
//! non-destructive scaffold materialization, and task-graph progression.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use klens_core::time::now_iso8601_utc;
use klens_core::{
    ProjectRoot, ProvenanceEnvelope, RelPath, TrustLevel, redact_secrets, write_atomic,
};
use serde::{Deserialize, Serialize};

use crate::conflicts::{ConflictReport, check_conflicts};
use crate::error::BlueprintError;
use crate::model::{
    BLUEPRINT_JSON_REL, Blueprint, BlueprintBubble, BlueprintTask, BubbleStatus,
    PROJECT_CONTRACT_REL, ScaffoldEntry, TASKS_JSONL_REL, TaskStatus, load_blueprint,
    load_blueprint_optional, load_tasks_optional, save_blueprint, save_tasks,
};
use crate::tasks::{compile_tasks_from_bubbles, next_ready_task, validate_task_graph};

/// Options controlling [`lock_and_execute`].
#[derive(Debug, Clone, Default)]
pub struct LockOptions {
    /// When `true`, materialize `blueprint.scaffold` and `extra_scaffold` without overwriting existing files.
    pub create_scaffold: bool,
    /// Additional scaffold directories/files to materialize alongside `blueprint.scaffold`.
    pub extra_scaffold: Vec<ScaffoldEntry>,
    /// Optional explicit task graph to persist instead of auto-deriving from confirmed bubbles.
    pub custom_tasks: Option<Vec<BlueprintTask>>,
}

/// Summary of non-destructive scaffold creation during `lock_and_execute`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScaffoldReport {
    pub created_dirs: Vec<String>,
    pub created_files: Vec<String>,
    pub skipped_existing: Vec<String>,
}

/// Payload returned by [`lock_and_execute`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockResult {
    pub blueprint_path: String,
    pub contract_path: String,
    pub tasks_path: String,
    pub locked_at: String,
    pub task_count: usize,
    pub scaffold: ScaffoldReport,
}

/// Summary payload returned by [`blueprint_status`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlueprintStatusPayload {
    pub initialized: bool,
    pub project_name: Option<String>,
    pub goal: Option<String>,
    pub locked: bool,
    pub locked_at: Option<String>,
    pub contract_exists: bool,
    pub bubble_count: usize,
    pub confirmed_bubbles: usize,
    pub pending_bubbles: usize,
    pub conflicts: ConflictReport,
    pub total_tasks: usize,
    pub done_tasks: usize,
    pub next_ready_task: Option<BlueprintTask>,
}

/// Inspect current Blueprint, live conflicts, contract presence, and task progress (strictly read-only).
pub fn blueprint_status(
    project_root: &ProjectRoot,
) -> Result<ProvenanceEnvelope<BlueprintStatusPayload>, BlueprintError> {
    let bp_opt = load_blueprint_optional(project_root)?;
    let tasks = load_tasks_optional(project_root)?;
    let contract_exists = project_root.resolve_existing(PROJECT_CONTRACT_REL).is_ok();

    let done_tasks = tasks
        .iter()
        .filter(|t| t.status == TaskStatus::Done)
        .count();
    let total_tasks = tasks.len();
    let next_ready = next_ready_task(&tasks);

    let (payload, trust) = match bp_opt {
        Some(bp) => {
            let conflicts = check_conflicts(&bp);
            let confirmed = bp
                .bubbles
                .iter()
                .filter(|b| b.status == BubbleStatus::UserConfirmed)
                .count();
            let pending = bp
                .bubbles
                .iter()
                .filter(|b| b.status == BubbleStatus::Pending)
                .count();
            let trust = if bp.locked {
                TrustLevel::UserLocked
            } else {
                TrustLevel::VerifiedRaw
            };
            (
                BlueprintStatusPayload {
                    initialized: true,
                    project_name: Some(bp.project_name),
                    goal: Some(bp.goal),
                    locked: bp.locked,
                    locked_at: bp.locked_at,
                    contract_exists,
                    bubble_count: bp.bubbles.len(),
                    confirmed_bubbles: confirmed,
                    pending_bubbles: pending,
                    conflicts,
                    total_tasks,
                    done_tasks,
                    next_ready_task: next_ready,
                },
                trust,
            )
        }
        None => (
            BlueprintStatusPayload {
                initialized: false,
                project_name: None,
                goal: None,
                locked: false,
                locked_at: None,
                contract_exists,
                bubble_count: 0,
                confirmed_bubbles: 0,
                pending_bubbles: 0,
                conflicts: ConflictReport {
                    conflicts: Vec::new(),
                    error_count: 0,
                    warning_count: 0,
                    can_lock: false,
                },
                total_tasks,
                done_tasks,
                next_ready_task: next_ready,
            },
            TrustLevel::VerifiedRaw,
        ),
    };

    Ok(ProvenanceEnvelope::new(
        trust,
        project_root.project_id(),
        payload,
    ))
}

/// Run the deterministic conflict checker against `.klens/blueprint/blueprint.json` (read-only).
pub fn check_blueprint(
    project_root: &ProjectRoot,
) -> Result<ProvenanceEnvelope<ConflictReport>, BlueprintError> {
    let bp = load_blueprint(project_root)?;
    let report = check_conflicts(&bp);
    let trust = if bp.locked && report.can_lock {
        TrustLevel::UserLocked
    } else {
        TrustLevel::VerifiedRaw
    };
    Ok(ProvenanceEnvelope::new(
        trust,
        project_root.project_id(),
        report,
    ))
}

/// Save or update `.klens/blueprint/blueprint.json` with freshly computed conflict diagnostics.
///
/// Always persists an unlocked draft (`locked = false`, `locked_at = None`) until explicitly
/// locked via [`lock_and_execute`].
pub fn propose_blueprint(
    project_root: &ProjectRoot,
    mut blueprint: Blueprint,
) -> Result<ProvenanceEnvelope<BlueprintStatusPayload>, BlueprintError> {
    blueprint.validate_schema()?;
    blueprint.locked = false;
    blueprint.locked_at = None;
    let report = check_conflicts(&blueprint);
    blueprint.conflicts = report.conflicts;
    save_blueprint(project_root, &blueprint)?;
    blueprint_status(project_root)
}

/// Select an option (and optional user vision note / confirmation) on an existing bubble.
pub fn select_bubble_option(
    project_root: &ProjectRoot,
    bubble_id: &str,
    option_id: &str,
    vision_note: Option<&str>,
    confirm: bool,
) -> Result<ProvenanceEnvelope<BlueprintStatusPayload>, BlueprintError> {
    let mut bp = load_blueprint(project_root)?;
    let bubble = bp
        .bubbles
        .iter_mut()
        .find(|b| b.id == bubble_id)
        .ok_or_else(|| BlueprintError::BubbleNotFound(bubble_id.to_string()))?;

    if !bubble.options.iter().any(|o| o.id == option_id) {
        return Err(BlueprintError::OptionNotFound {
            bubble_id: bubble_id.to_string(),
            option_id: option_id.to_string(),
        });
    }

    bubble.selected_option = Some(option_id.to_string());
    if let Some(note) = vision_note {
        bubble.user_vision_note = note.to_string();
    }
    if confirm {
        bubble.status = BubbleStatus::UserConfirmed;
    }

    // Mutating a selection invalidates any prior lock until re-locked.
    bp.locked = false;
    bp.locked_at = None;
    let report = check_conflicts(&bp);
    bp.conflicts = report.conflicts;
    save_blueprint(project_root, &bp)?;
    blueprint_status(project_root)
}

/// Deterministically verify conflicts == 0, lock the Blueprint, and emit:
/// 1. `.klens/blueprint/PROJECT_CONTRACT.md` (`TrustLevel::UserLocked`)
/// 2. `.klens/blueprint/tasks.jsonl`
/// 3. Optional non-destructive scaffold (never overwrites existing files).
///
/// Fail-closed guarantee: if ANY error-level conflict exists (or any task/scaffold validation fails),
/// returns `Err(...)` and writes ZERO files (`PROJECT_CONTRACT.md` and `tasks.jsonl` are NOT created).
pub fn lock_and_execute(
    project_root: &ProjectRoot,
    options: &LockOptions,
) -> Result<ProvenanceEnvelope<LockResult>, BlueprintError> {
    let mut bp = load_blueprint(project_root)?;
    let report = check_conflicts(&bp);

    if !report.can_lock {
        return Err(BlueprintError::ConflictsPresent {
            error_count: report.error_count,
            summary: report.error_summary(),
        });
    }

    // Order bubbles topologically (guaranteed acyclic because `report.can_lock == true`).
    let ordered_bubbles = topological_order_bubbles(&bp.bubbles);

    // Prepare and validate tasks BEFORE touching the filesystem.
    let existing_tasks = load_tasks_optional(project_root)?;
    let tasks = match &options.custom_tasks {
        Some(custom) => {
            validate_task_graph(custom)?;
            custom.clone()
        }
        None => compile_tasks_from_bubbles(&ordered_bubbles, &existing_tasks),
    };
    validate_task_graph(&tasks)?;

    // Collect and pre-validate all scaffold paths under `ProjectRoot` BEFORE touching disk.
    let should_materialize = options.create_scaffold || !options.extra_scaffold.is_empty();
    let validated_scaffold = if should_materialize {
        prepare_scaffold_entries(project_root, &bp.scaffold, &options.extra_scaffold)?
    } else {
        Vec::new()
    };

    let locked_at = bp.locked_at.clone().unwrap_or_else(now_iso8601_utc);
    bp.locked = true;
    bp.locked_at = Some(locked_at.clone());
    bp.conflicts = report.conflicts;

    let raw_contract = render_project_contract(&bp, &ordered_bubbles, &tasks, &locked_at);
    let redacted_contract = redact_secrets(&raw_contract);

    // Persist all 3 canonical blueprint artifacts atomically under `ProjectRoot` confinement.
    let (contract_abs, _) = project_root.resolve_for_write(PROJECT_CONTRACT_REL)?;
    save_blueprint(project_root, &bp)?;
    write_atomic(&contract_abs, redacted_contract.text.as_bytes())?;
    save_tasks(project_root, &tasks)?;

    let scaffold_report = if should_materialize {
        materialize_scaffold_entries(&validated_scaffold)?
    } else {
        ScaffoldReport::default()
    };

    let result = LockResult {
        blueprint_path: BLUEPRINT_JSON_REL.to_string(),
        contract_path: PROJECT_CONTRACT_REL.to_string(),
        tasks_path: TASKS_JSONL_REL.to_string(),
        locked_at,
        task_count: tasks.len(),
        scaffold: scaffold_report,
    };

    Ok(
        ProvenanceEnvelope::new(TrustLevel::UserLocked, project_root.project_id(), result)
            .with_redactions_count(redacted_contract.redactions_count),
    )
}

/// Deterministically order bubbles topologically (Kahn's algorithm with lexicographical tie-breaking).
fn topological_order_bubbles(bubbles: &[BlueprintBubble]) -> Vec<&BlueprintBubble> {
    let by_id: BTreeMap<&str, &BlueprintBubble> =
        bubbles.iter().map(|b| (b.id.as_str(), b)).collect();
    let mut in_degree: BTreeMap<&str, usize> = BTreeMap::new();
    let mut dependents: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();

    for &id in by_id.keys() {
        in_degree.insert(id, 0);
        dependents.entry(id).or_default();
    }

    for (&id, &bubble) in &by_id {
        let mut unique_deps: BTreeSet<&str> = BTreeSet::new();
        for dep in &bubble.depends_on {
            if by_id.contains_key(dep.as_str()) {
                unique_deps.insert(dep.as_str());
            }
        }
        in_degree.insert(id, unique_deps.len());
        for dep in unique_deps {
            dependents.entry(dep).or_default().insert(id);
        }
    }

    let mut ready: BTreeSet<&str> = in_degree
        .iter()
        .filter_map(|(&id, &deg)| (deg == 0).then_some(id))
        .collect();
    let mut ordered: Vec<&BlueprintBubble> = Vec::with_capacity(by_id.len());

    while let Some(&next_id) = ready.iter().next() {
        ready.remove(next_id);
        if let Some(&bubble) = by_id.get(next_id) {
            ordered.push(bubble);
        }
        if let Some(children) = dependents.get(next_id) {
            for &child in children {
                if let Some(deg) = in_degree.get_mut(child) {
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        ready.insert(child);
                    }
                }
            }
        }
    }

    ordered
}

/// Render the deterministic `PROJECT_CONTRACT.md` Markdown contract (`TrustLevel::UserLocked`).
fn render_project_contract(
    bp: &Blueprint,
    ordered_bubbles: &[&BlueprintBubble],
    tasks: &[BlueprintTask],
    locked_at: &str,
) -> String {
    let mut out = String::new();
    out.push_str("---\n");
    out.push_str(&format!("schema_version: {}\n", bp.schema_version));
    out.push_str("trust: USER_LOCKED\n");
    out.push_str(&format!(
        "project_name: {}\n",
        yaml_double_quoted(&bp.project_name)
    ));
    out.push_str(&format!("locked_at: {locked_at}\n"));
    out.push_str("---\n\n");

    out.push_str(&format!("# PROJECT CONTRACT — {}\n\n", bp.project_name));
    out.push_str(&format!("**Goal:** {}\n\n", bp.goal.trim()));

    out.push_str("## Locked Architectural Decisions (`USER_LOCKED`)\n\n");
    for bubble in ordered_bubbles {
        if bubble.status == BubbleStatus::Skipped {
            continue;
        }
        let selected_opt = bubble.selected_option_ref();
        let choice = selected_opt
            .map(|o| format!("{} (`{}`)", o.label, o.id))
            .or_else(|| bubble.selected_option.as_ref().map(|id| format!("`{id}`")))
            .unwrap_or_else(|| "none".to_string());

        out.push_str(&format!(
            "### {} — {} (`{}`)\n",
            bubble.category, bubble.title, bubble.id
        ));
        out.push_str(&format!("- **Selected:** {choice}\n"));
        if !bubble.plain_explanation.trim().is_empty() {
            out.push_str(&format!(
                "- **Rationale:** {}\n",
                bubble.plain_explanation.trim()
            ));
        }
        if let Some(opt) = selected_opt {
            if !opt.provides.is_empty() {
                let mut tags = opt.provides.clone();
                tags.sort();
                out.push_str(&format!("- **Provides:** {}\n", tags.join(", ")));
            }
            if !opt.requires.is_empty() {
                let mut reqs = opt.requires.clone();
                reqs.sort();
                out.push_str(&format!("- **Requires:** {}\n", reqs.join(", ")));
            }
        }
        if !bubble.depends_on.is_empty() {
            let mut deps = bubble.depends_on.clone();
            deps.sort();
            out.push_str(&format!("- **Depends On:** {}\n", deps.join(", ")));
        }
        if !bubble.user_vision_note.trim().is_empty() {
            out.push_str(&format!(
                "- **User Vision Note:** {}\n",
                bubble.user_vision_note.trim()
            ));
        }
        out.push('\n');
    }

    out.push_str("## Task Queue (`tasks.jsonl`)\n\n");
    if tasks.is_empty() {
        out.push_str("_No tasks compiled._\n\n");
    } else {
        for task in tasks {
            let deps = if task.blocked_by.is_empty() {
                "none".to_string()
            } else {
                task.blocked_by.join(", ")
            };
            let verify = task
                .verification_cmd
                .as_deref()
                .map(|c| format!(" | verify: `{c}`"))
                .unwrap_or_default();
            out.push_str(&format!(
                "- `{}` [{}] {} (blocked_by: {}){}\n",
                task.id,
                task.status.as_str(),
                task.title,
                deps,
                verify
            ));
        }
        out.push('\n');
    }

    out.push_str("## Contract Enforcement\n\n");
    out.push_str(
        "- Every decision above is `USER_LOCKED`. Do not silently deviate without explicit user confirmation.\n",
    );
    out.push_str("- Execute tasks in dependency order via `klens blueprint next-task` and `klens blueprint complete-task <id>`.\n");

    out
}

/// Format a YAML scalar safely inside double quotes, escaping `\` and `"` and collapsing line breaks.
fn yaml_double_quoted(raw: &str) -> String {
    let mut escaped = String::with_capacity(raw.len() + 2);
    escaped.push('"');
    for ch in raw.chars() {
        match ch {
            '\r' | '\n' => escaped.push(' '),
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            other => escaped.push(other),
        }
    }
    escaped.push('"');
    escaped
}

struct PreparedScaffold {
    abs: PathBuf,
    rel: RelPath,
    is_dir: bool,
    content: String,
}

fn prepare_scaffold_entries(
    project_root: &ProjectRoot,
    blueprint_entries: &[ScaffoldEntry],
    extra_entries: &[ScaffoldEntry],
) -> Result<Vec<PreparedScaffold>, BlueprintError> {
    let mut merged: BTreeMap<String, ScaffoldEntry> = BTreeMap::new();
    for entry in blueprint_entries.iter().chain(extra_entries.iter()) {
        let rel = RelPath::normalize(&entry.path)?;
        merged
            .entry(rel.as_str().to_string())
            .or_insert_with(|| entry.clone());
    }

    let mut prepared = Vec::with_capacity(merged.len());
    for entry in merged.into_values() {
        let (abs, rel) = project_root.resolve_for_write(&entry.path)?;
        prepared.push(PreparedScaffold {
            abs,
            rel,
            is_dir: entry.is_dir,
            content: entry.content.unwrap_or_default(),
        });
    }

    Ok(prepared)
}

fn materialize_scaffold_entries(
    entries: &[PreparedScaffold],
) -> Result<ScaffoldReport, BlueprintError> {
    let mut report = ScaffoldReport::default();

    for entry in entries {
        if entry.is_dir {
            if fs::symlink_metadata(&entry.abs).is_ok() {
                report.skipped_existing.push(entry.rel.as_str().to_string());
            } else {
                fs::create_dir_all(&entry.abs).map_err(|source| BlueprintError::Io {
                    path: entry.abs.clone(),
                    source,
                })?;
                report.created_dirs.push(entry.rel.as_str().to_string());
            }
            continue;
        }

        // Strict non-overwrite guard: never touch existing files or symlinks.
        if fs::symlink_metadata(&entry.abs).is_ok() {
            report.skipped_existing.push(entry.rel.as_str().to_string());
            continue;
        }

        if let Some(parent) = entry.abs.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|source| BlueprintError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        // OS-level `create_new(true)` guarantees atomic non-overwrite even under races.
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&entry.abs)
        {
            Ok(mut file) => {
                file.write_all(entry.content.as_bytes())
                    .map_err(|source| BlueprintError::Io {
                        path: entry.abs.clone(),
                        source,
                    })?;
                report.created_files.push(entry.rel.as_str().to_string());
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                report.skipped_existing.push(entry.rel.as_str().to_string());
            }
            Err(source) => {
                return Err(BlueprintError::Io {
                    path: entry.abs.clone(),
                    source,
                });
            }
        }
    }

    Ok(report)
}
