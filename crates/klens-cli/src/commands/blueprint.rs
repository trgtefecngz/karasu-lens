//! CLI subcommands for `.klens/blueprint/` (`klens blueprint status|check|lock|next-task|complete-task`)
//! and deterministic session handoff (`klens handoff`).

use std::io::{self, Write};
use std::path::PathBuf;

use clap::{Args, Subcommand};
use klens_blueprint::{
    DEFAULT_HANDOFF_BUDGET_TOKENS, LockOptions, blueprint_status, check_blueprint, complete_task,
    compose_handoff, format_complete_task_text, format_conflicts_text, format_handoff_text,
    format_lock_text, format_next_task_text, format_status_text, get_next_ready_task,
    lock_and_execute,
};
use klens_mcp::collect_handoff_input;

use super::common::{CliError, resolve_project_root};

#[derive(Debug, Args)]
pub(crate) struct BlueprintArgs {
    #[command(subcommand)]
    pub action: BlueprintAction,
}

#[derive(Debug, Subcommand)]
pub(crate) enum BlueprintAction {
    /// Inspect Blueprint status, lock state, live conflict counts, and task progress.
    Status(BlueprintStatusArgs),
    /// Run the deterministic zero-LLM conflict checker on `.klens/blueprint/blueprint.json`.
    Check(BlueprintCheckArgs),
    /// Lock the Blueprint (requires 0 error conflicts) and compile `PROJECT_CONTRACT.md` + `tasks.jsonl`.
    Lock(BlueprintLockArgs),
    /// Return the next ready task whose `blocked_by` dependencies are all completed.
    NextTask(BlueprintNextTaskArgs),
    /// Mark a compiled task as `done` (fails if prerequisites are incomplete) and show the next ready task.
    CompleteTask(BlueprintCompleteTaskArgs),
}

#[derive(Debug, Args)]
pub(crate) struct BlueprintStatusArgs {
    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct BlueprintCheckArgs {
    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct BlueprintLockArgs {
    /// Materialize optional scaffold directories/files declared in `blueprint.json` (never overwrites existing files).
    #[arg(long)]
    pub scaffold: bool,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct BlueprintNextTaskArgs {
    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct BlueprintCompleteTaskArgs {
    /// Task identifier from `.klens/blueprint/tasks.jsonl`.
    pub id: String,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct HandoffArgs {
    /// Maximum token budget for the session handoff summary (default 800).
    #[arg(long, default_value_t = DEFAULT_HANDOFF_BUDGET_TOKENS)]
    pub budget: usize,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Zero-footprint mode: never writes `.klens/cache/` into the target project.
    #[arg(long)]
    pub read_only: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

pub(crate) fn run_blueprint_cmd(args: BlueprintArgs) -> Result<String, CliError> {
    match args.action {
        BlueprintAction::Status(status_args) => {
            let project_root = resolve_project_root(None, status_args.root.as_deref())?;
            let env = blueprint_status(&project_root)?;
            if status_args.json {
                Ok(env.to_deterministic_json_pretty()?)
            } else {
                Ok(format_status_text(&env).trim_end().to_string())
            }
        }
        BlueprintAction::Check(check_args) => {
            let project_root = resolve_project_root(None, check_args.root.as_deref())?;
            let env = check_blueprint(&project_root)?;
            if check_args.json {
                Ok(env.to_deterministic_json_pretty()?)
            } else {
                Ok(format_conflicts_text(&env).trim_end().to_string())
            }
        }
        BlueprintAction::Lock(lock_args) => {
            let project_root = resolve_project_root(None, lock_args.root.as_deref())?;
            let options = LockOptions {
                create_scaffold: lock_args.scaffold,
                ..LockOptions::default()
            };
            let env = lock_and_execute(&project_root, &options)?;
            if lock_args.json {
                Ok(env.to_deterministic_json_pretty()?)
            } else {
                Ok(format_lock_text(&env).trim_end().to_string())
            }
        }
        BlueprintAction::NextTask(next_args) => {
            let project_root = resolve_project_root(None, next_args.root.as_deref())?;
            let env = get_next_ready_task(&project_root)?;
            if next_args.json {
                Ok(env.to_deterministic_json_pretty()?)
            } else {
                Ok(format_next_task_text(&env).trim_end().to_string())
            }
        }
        BlueprintAction::CompleteTask(complete_args) => {
            let project_root = resolve_project_root(None, complete_args.root.as_deref())?;
            let env = complete_task(&project_root, &complete_args.id)?;
            if complete_args.json {
                Ok(env.to_deterministic_json_pretty()?)
            } else {
                Ok(format_complete_task_text(&env).trim_end().to_string())
            }
        }
    }
}

pub(crate) fn run_handoff_cmd(args: HandoffArgs) -> Result<String, CliError> {
    let project_root = resolve_project_root(None, args.root.as_deref())?;
    let input = collect_handoff_input(&project_root, args.read_only, None);
    let env = compose_handoff(input, args.budget);
    if args.json {
        Ok(env.to_deterministic_json_pretty()?)
    } else {
        let text = format_handoff_text(&env).trim_end().to_string();
        let omitted_sections: usize = env
            .omissions
            .iter()
            .filter(|o| o.reason == "handoff_sections_omitted_to_fit_budget")
            .map(|o| o.count)
            .sum();
        let truncated_sections: usize = env
            .omissions
            .iter()
            .filter(|o| {
                o.reason.starts_with("handoff_section_") || o.reason == "handoff_final_budget_clamp"
            })
            .count();
        if omitted_sections > 0 || truncated_sections > 0 || text.is_empty() {
            let state = if text.is_empty() {
                "empty output"
            } else {
                "truncated output"
            };
            let mut stderr = io::stderr().lock();
            let _ = writeln!(
                stderr,
                "warning: `klens handoff --budget {}` is too small ({state}; {omitted_sections} section(s) omitted, {truncated_sections} truncated) — try a larger `--budget` (e.g. `--budget {DEFAULT_HANDOFF_BUDGET_TOKENS}`)",
                args.budget
            );
        }
        Ok(text)
    }
}
