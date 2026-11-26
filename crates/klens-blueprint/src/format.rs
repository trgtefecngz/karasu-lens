//! Human-readable compact text formatters for `klens-blueprint` CLI and MCP responses.

use klens_core::ProvenanceEnvelope;

use crate::compile::{BlueprintStatusPayload, LockResult};
use crate::conflicts::ConflictReport;
use crate::handoff::HandoffPayload;
use crate::tasks::{CompleteTaskResult, NextTaskPayload};

/// Format `klens blueprint status` for terminal / MCP text output.
pub fn format_status_text(env: &ProvenanceEnvelope<BlueprintStatusPayload>) -> String {
    let d = &env.data;
    if !d.initialized {
        return "[klens blueprint status] not initialized (no `.klens/blueprint/blueprint.json` found)"
            .to_string();
    }

    let state = if d.locked { "USER_LOCKED" } else { "DRAFT" };
    let name = d.project_name.as_deref().unwrap_or("project");
    let mut lines = vec![format!(
        "[klens blueprint status] project=\"{name}\" state={state} bubbles={} (confirmed={}, pending={}) conflicts={} (errors={}) tasks={}/{}",
        d.bubble_count,
        d.confirmed_bubbles,
        d.pending_bubbles,
        d.conflicts.conflicts.len(),
        d.conflicts.error_count,
        d.done_tasks,
        d.total_tasks
    )];

    if let Some(ref goal) = d.goal
        && !goal.trim().is_empty()
    {
        lines.push(format!("  goal: {}", goal.trim()));
    }
    if let Some(ref ts) = d.locked_at {
        lines.push(format!("  locked_at: {ts}"));
    }
    lines.push(format!(
        "  contract: {}",
        if d.contract_exists {
            ".klens/blueprint/PROJECT_CONTRACT.md"
        } else {
            "not compiled yet"
        }
    ));
    if let Some(ref next) = d.next_ready_task {
        lines.push(format!("  next_ready_task: `{}` — {}", next.id, next.title));
    }
    for c in &d.conflicts.conflicts {
        lines.push(format!(
            "  [{}] {}: {}",
            c.severity.as_str(),
            if c.bubble_ids.is_empty() {
                "-".to_string()
            } else {
                c.bubble_ids.join(", ")
            },
            c.message
        ));
    }

    lines.join("\n")
}

/// Format `klens blueprint check` for terminal / MCP text output.
pub fn format_conflicts_text(env: &ProvenanceEnvelope<ConflictReport>) -> String {
    let d = &env.data;
    let verdict = if d.can_lock {
        "READY_TO_LOCK"
    } else {
        "BLOCKED"
    };
    let mut lines = vec![format!(
        "[klens blueprint check] {verdict} errors={} warnings={}",
        d.error_count, d.warning_count
    )];
    for c in &d.conflicts {
        let bubbles = if c.bubble_ids.is_empty() {
            "-".to_string()
        } else {
            c.bubble_ids.join(", ")
        };
        lines.push(format!(
            "  [{}] ({bubbles}) {}",
            c.severity.as_str(),
            c.message
        ));
    }
    lines.join("\n")
}

/// Format `klens blueprint lock` for terminal / MCP text output.
pub fn format_lock_text(env: &ProvenanceEnvelope<LockResult>) -> String {
    let d = &env.data;
    let mut lines = vec![format!(
        "[klens blueprint lock] USER_LOCKED at {} tasks={} contract={} tasks_file={}",
        d.locked_at, d.task_count, d.contract_path, d.tasks_path
    )];
    if !d.scaffold.created_dirs.is_empty() {
        lines.push(format!(
            "  scaffold_dirs_created: {}",
            d.scaffold.created_dirs.join(", ")
        ));
    }
    if !d.scaffold.created_files.is_empty() {
        lines.push(format!(
            "  scaffold_files_created: {}",
            d.scaffold.created_files.join(", ")
        ));
    }
    if !d.scaffold.skipped_existing.is_empty() {
        lines.push(format!(
            "  scaffold_skipped_existing: {}",
            d.scaffold.skipped_existing.join(", ")
        ));
    }
    lines.join("\n")
}

/// Format `klens blueprint next-task` for terminal / MCP text output.
pub fn format_next_task_text(env: &ProvenanceEnvelope<NextTaskPayload>) -> String {
    let d = &env.data;
    if let Some(ref task) = d.task {
        let mut lines = vec![format!(
            "[klens blueprint next-task] `{}` [{}] {} ({}/{} done)",
            task.id,
            task.status.as_str(),
            task.title,
            d.done_tasks,
            d.total_tasks
        )];
        if !task.blocked_by.is_empty() {
            lines.push(format!(
                "  blocked_by (done): {}",
                task.blocked_by.join(", ")
            ));
        }
        if !task.expected_files.is_empty() {
            lines.push(format!(
                "  expected_files: {}",
                task.expected_files.join(", ")
            ));
        }
        if let Some(ref cmd) = task.verification_cmd {
            lines.push(format!("  verification_cmd: `{cmd}`"));
        }
        lines.join("\n")
    } else if d.all_done {
        format!(
            "[klens blueprint next-task] all {} task(s) completed",
            d.total_tasks
        )
    } else if d.total_tasks == 0 {
        "[klens blueprint next-task] no tasks found (run `klens blueprint lock` first)".to_string()
    } else {
        format!(
            "[klens blueprint next-task] no ready task ({}/{} done; remaining tasks are blocked)",
            d.done_tasks, d.total_tasks
        )
    }
}

/// Format `klens blueprint complete-task <id>` for terminal / MCP text output.
pub fn format_complete_task_text(env: &ProvenanceEnvelope<CompleteTaskResult>) -> String {
    let d = &env.data;
    let mut lines = vec![format!(
        "[klens blueprint complete-task] completed `{}` — {} ({}/{} done)",
        d.completed_task.id, d.completed_task.title, d.done_tasks, d.total_tasks
    )];
    match &d.next_ready_task {
        Some(next) => lines.push(format!("  next_ready_task: `{}` — {}", next.id, next.title)),
        None => lines.push("  next_ready_task: none".to_string()),
    }
    lines.join("\n")
}

/// Format `klens handoff` for terminal / MCP text output.
pub fn format_handoff_text(env: &ProvenanceEnvelope<HandoffPayload>) -> String {
    env.data.summary_markdown.clone()
}
