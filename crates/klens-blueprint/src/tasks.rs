//! Dependency-aware Blueprint task queue compilation, validation, and progression
//! (`next_ready_task`, `get_next_ready_task`, `complete_task`, `validate_task_graph`).

use std::collections::{BTreeMap, BTreeSet};

use klens_core::{ProjectRoot, ProvenanceEnvelope, TrustLevel};
use serde::{Deserialize, Serialize};

use crate::conflicts::detect_cycles;
use crate::error::BlueprintError;
use crate::model::{
    BlueprintBubble, BlueprintTask, BubbleStatus, TaskStatus, load_blueprint_optional, load_tasks,
    load_tasks_optional, save_tasks, validate_identifier,
};

/// Payload returned by [`get_next_ready_task`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NextTaskPayload {
    pub task: Option<BlueprintTask>,
    pub total_tasks: usize,
    pub done_tasks: usize,
    pub remaining_tasks: usize,
    pub all_done: bool,
}

/// Payload returned by [`complete_task`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompleteTaskResult {
    pub completed_task: BlueprintTask,
    pub next_ready_task: Option<BlueprintTask>,
    pub done_tasks: usize,
    pub total_tasks: usize,
}

/// Pure deterministic selector for the next ready task whose `blocked_by` dependencies are all `Done`.
///
/// Ordering rule: `in_progress` tasks take priority over `pending` tasks; ties break lexicographically by `id`.
pub fn next_ready_task(tasks: &[BlueprintTask]) -> Option<BlueprintTask> {
    let done_ids: BTreeSet<&str> = tasks
        .iter()
        .filter(|t| t.status == TaskStatus::Done)
        .map(|t| t.id.as_str())
        .collect();

    let mut ready: Vec<&BlueprintTask> = tasks
        .iter()
        .filter(|t| {
            t.status != TaskStatus::Done
                && t.blocked_by
                    .iter()
                    .all(|dep| done_ids.contains(dep.as_str()))
        })
        .collect();

    ready.sort_by(|a, b| {
        let prio = |status: TaskStatus| match status {
            TaskStatus::InProgress => 0u8,
            TaskStatus::Pending => 1u8,
            TaskStatus::Done => 2u8,
        };
        prio(a.status).cmp(&prio(b.status)).then(a.id.cmp(&b.id))
    });

    ready.into_iter().next().cloned()
}

/// Load `.klens/blueprint/tasks.jsonl` and return the deterministic next ready task.
pub fn get_next_ready_task(
    project_root: &ProjectRoot,
) -> Result<ProvenanceEnvelope<NextTaskPayload>, BlueprintError> {
    let tasks = load_tasks_optional(project_root)?;
    let total_tasks = tasks.len();
    let done_tasks = tasks
        .iter()
        .filter(|t| t.status == TaskStatus::Done)
        .count();
    let remaining_tasks = total_tasks.saturating_sub(done_tasks);
    let task = next_ready_task(&tasks);
    let all_done = total_tasks > 0 && remaining_tasks == 0;

    let bp_locked = load_blueprint_optional(project_root)?.is_some_and(|b| b.locked);
    let trust = if bp_locked {
        TrustLevel::UserLocked
    } else {
        TrustLevel::VerifiedRaw
    };

    Ok(ProvenanceEnvelope::new(
        trust,
        project_root.project_id(),
        NextTaskPayload {
            task,
            total_tasks,
            done_tasks,
            remaining_tasks,
            all_done,
        },
    ))
}

/// Mark `task_id` as `done` in `.klens/blueprint/tasks.jsonl` (rejecting if any `blocked_by` task is incomplete).
pub fn complete_task(
    project_root: &ProjectRoot,
    task_id: &str,
) -> Result<ProvenanceEnvelope<CompleteTaskResult>, BlueprintError> {
    validate_identifier(task_id)?;
    let mut tasks = load_tasks(project_root)?;

    let done_ids: BTreeSet<String> = tasks
        .iter()
        .filter(|t| t.status == TaskStatus::Done)
        .map(|t| t.id.clone())
        .collect();

    let Some(idx) = tasks.iter().position(|t| t.id == task_id) else {
        return Err(BlueprintError::TaskNotFound(task_id.to_string()));
    };

    let mut unmet: Vec<String> = tasks[idx]
        .blocked_by
        .iter()
        .filter(|dep| !done_ids.contains(dep.as_str()))
        .cloned()
        .collect();
    unmet.sort();
    unmet.dedup();
    if !unmet.is_empty() {
        return Err(BlueprintError::TaskBlocked {
            id: task_id.to_string(),
            blocked_by: unmet.join(", "),
        });
    }

    tasks[idx].status = TaskStatus::Done;
    let completed_task = tasks[idx].clone();
    save_tasks(project_root, &tasks)?;

    let done_tasks = tasks
        .iter()
        .filter(|t| t.status == TaskStatus::Done)
        .count();
    let total_tasks = tasks.len();
    let next_ready = next_ready_task(&tasks);

    let bp_locked = load_blueprint_optional(project_root)?.is_some_and(|b| b.locked);
    let trust = if bp_locked {
        TrustLevel::UserLocked
    } else {
        TrustLevel::VerifiedRaw
    };

    Ok(ProvenanceEnvelope::new(
        trust,
        project_root.project_id(),
        CompleteTaskResult {
            completed_task,
            next_ready_task: next_ready,
            done_tasks,
            total_tasks,
        },
    ))
}

/// Deterministically derive tasks from topologically ordered confirmed bubbles, preserving `Done` status
/// for matching task IDs if `tasks.jsonl` already existed.
pub(crate) fn compile_tasks_from_bubbles(
    ordered_bubbles: &[&BlueprintBubble],
    existing_tasks: &[BlueprintTask],
) -> Vec<BlueprintTask> {
    let existing_status: BTreeMap<&str, TaskStatus> = existing_tasks
        .iter()
        .map(|t| (t.id.as_str(), t.status))
        .collect();

    let active_bubbles: Vec<&BlueprintBubble> = ordered_bubbles
        .iter()
        .copied()
        .filter(|b| b.status == BubbleStatus::UserConfirmed)
        .collect();

    let mut bubble_to_task_id: BTreeMap<&str, String> = BTreeMap::new();
    for (idx, bubble) in active_bubbles.iter().enumerate() {
        let tid = format!("T{:02}-{}", idx + 1, bubble.id);
        bubble_to_task_id.insert(bubble.id.as_str(), tid);
    }

    let mut tasks = Vec::with_capacity(active_bubbles.len());
    for bubble in &active_bubbles {
        let task_id = bubble_to_task_id[bubble.id.as_str()].clone();
        let choice_label = bubble
            .selected_option_ref()
            .map(|o| o.label.as_str())
            .or(bubble.selected_option.as_deref())
            .unwrap_or("Confirmed");
        let title = format!("{}: {choice_label}", bubble.category);

        let mut blocked_by: Vec<String> = bubble
            .depends_on
            .iter()
            .filter_map(|dep| bubble_to_task_id.get(dep.as_str()).cloned())
            .collect();
        blocked_by.sort();
        blocked_by.dedup();

        let status = existing_status
            .get(task_id.as_str())
            .copied()
            .unwrap_or(TaskStatus::Pending);

        tasks.push(BlueprintTask {
            id: task_id,
            title,
            blocked_by,
            expected_files: Vec::new(),
            verification_cmd: None,
            status,
            bubble_id: Some(bubble.id.clone()),
        });
    }

    tasks
}

/// Validate a task graph for duplicate IDs, unknown `blocked_by` references, and dependency cycles.
pub fn validate_task_graph(tasks: &[BlueprintTask]) -> Result<(), BlueprintError> {
    let mut ids: BTreeSet<&str> = BTreeSet::new();
    for task in tasks {
        validate_identifier(&task.id)?;
        if !ids.insert(task.id.as_str()) {
            return Err(BlueprintError::ValidationFailed(format!(
                "duplicate task id `{}`",
                task.id
            )));
        }
    }

    let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for task in tasks {
        let mut deps: BTreeSet<String> = BTreeSet::new();
        for dep in &task.blocked_by {
            if !ids.contains(dep.as_str()) {
                return Err(BlueprintError::ValidationFailed(format!(
                    "task `{}` depends on unknown task `{dep}`",
                    task.id
                )));
            }
            deps.insert(dep.clone());
        }
        adjacency.insert(task.id.clone(), deps.into_iter().collect());
    }

    let cycles = detect_cycles(&adjacency);
    if let Some(cycle) = cycles.first() {
        return Err(BlueprintError::ValidationFailed(format!(
            "circular task dependency detected: {} -> {}",
            cycle.join(" -> "),
            cycle[0]
        )));
    }

    Ok(())
}
