//! Execution handler for the 8th MCP tool (`klens_blueprint`) and shared pure-input
//! collector (`collect_handoff_input`) bridging `klens-blueprint` with Git, `klens-exec`,
//! `klens-memory`, and `.klens/config.toml` without violating crate isolation.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Command, Stdio};

use klens_blueprint::{
    Blueprint, BubbleStatus, ContractSummary, DEFAULT_HANDOFF_BUDGET_TOKENS, FailedRunSummary,
    GitCommitSummary, GitStatusSummary, HandoffInput, LockOptions, MemoryEntrySummary,
    MemorySummary, TaskStatus, blueprint_status, check_blueprint, complete_task, compose_handoff,
    format_complete_task_text, format_conflicts_text, format_handoff_text, format_lock_text,
    format_next_task_text, format_status_text, get_next_ready_task, load_blueprint_optional,
    load_contract_optional, load_tasks_optional, lock_and_execute, next_ready_task,
    propose_blueprint, select_bubble_option,
};
use klens_core::{ProjectConfig, ProjectMode, ProjectRoot, TrustLevel, estimate_tokens};
use klens_exec::{RunStore, show_stored_run};
use klens_memory::list_memory_index;
use serde_json::Value;

use crate::error::McpError;
use crate::handler_common::{
    OutputFormat, ToolContext, ToolExecution, parse_format, parse_optional_bool,
    parse_optional_string, parse_optional_usize,
};
use crate::memory_handler::LazyCodeSymbolResolver;
use crate::protocol::CallToolResult;

/// Gather real project facts (contract, protected paths, git, last failed run, tasks, memory)
/// into a pure [`HandoffInput`] DTO for [`klens_blueprint::compose_handoff`].
///
/// Strictly read-only when `read_only == true` (never writes into `.klens/cache/` or the repo).
pub fn collect_handoff_input(
    project_root: &ProjectRoot,
    read_only: bool,
    readonly_cache_dir: Option<&Path>,
) -> HandoffInput {
    let default_name = project_root
        .root()
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("project")
        .to_string();

    let cfg_path = project_root.root().join(".klens").join("config.toml");
    let protected_paths = ProjectConfig::load_or_default(&cfg_path)
        .map(|c| c.protected_paths)
        .unwrap_or_default();

    let blueprint_opt = load_blueprint_optional(project_root).ok().flatten();
    let contract_text = load_contract_optional(project_root).ok().flatten();

    let (project_name, contract) = match blueprint_opt {
        Some(bp) => {
            let mut decisions = Vec::new();
            for bubble in &bp.bubbles {
                if bubble.status == BubbleStatus::Skipped {
                    continue;
                }
                let choice = bubble
                    .selected_option_ref()
                    .map(|o| format!("{} ({})", o.label, o.id))
                    .or_else(|| bubble.selected_option.clone())
                    .unwrap_or_else(|| "pending".to_string());
                let mut line = format!("{}: {choice}", bubble.id);
                let note = bubble.user_vision_note.trim();
                if !note.is_empty() {
                    line.push_str(&format!(" — {note}"));
                }
                decisions.push(line);
            }
            decisions.sort();

            let name = if bp.project_name.trim().is_empty() {
                default_name.clone()
            } else {
                bp.project_name.clone()
            };
            (
                name,
                Some(ContractSummary {
                    project_name: bp.project_name,
                    goal: bp.goal,
                    locked: bp.locked,
                    locked_at: bp.locked_at,
                    decisions,
                    contract_excerpt: contract_text,
                }),
            )
        }
        None => {
            let fallback_contract = contract_text.map(|excerpt| ContractSummary {
                project_name: default_name.clone(),
                goal: String::new(),
                locked: true,
                locked_at: None,
                decisions: Vec::new(),
                contract_excerpt: Some(excerpt),
            });
            (default_name, fallback_contract)
        }
    };

    let tasks = load_tasks_optional(project_root).unwrap_or_default();
    let completed_tasks_count = tasks
        .iter()
        .filter(|t| t.status == TaskStatus::Done)
        .count();
    let remaining_tasks_count = tasks.len().saturating_sub(completed_tasks_count);
    let next_ready = next_ready_task(&tasks);

    let git = collect_git_summary(project_root.root());
    let last_failed_run = collect_last_failed_run(project_root);
    let memory = collect_memory_summary(project_root, read_only, readonly_cache_dir);

    HandoffInput {
        project_id: project_root.project_id().to_string(),
        project_name,
        contract,
        protected_paths,
        git,
        last_failed_run,
        next_ready_task: next_ready,
        completed_tasks_count,
        remaining_tasks_count,
        memory,
    }
}

/// Dispatch `klens_blueprint` actions (`status`, `check`, `propose`, `select`, `lock`, `next_task`, `complete_task`, `handoff`).
pub(crate) fn handle_blueprint(
    ctx: &ToolContext<'_>,
    args: &Value,
) -> Result<ToolExecution, McpError> {
    let format = parse_format(args)?;
    let action = require_non_empty_string(args, "action")?;

    match action {
        "status" => {
            let env = blueprint_status(ctx.project_root)?;
            let text = match format {
                OutputFormat::Text => format_status_text(&env).trim_end().to_string(),
                OutputFormat::Json => env.to_deterministic_json()?,
            };
            let tokens = estimate_tokens(&text) as u64;
            Ok(ToolExecution {
                result: CallToolResult::text(text),
                raw_est_tokens: tokens,
                filtered_est_tokens: tokens,
                is_run_filtered: false,
                stale_memories_caught: 0,
            })
        }
        "check" => {
            let env = check_blueprint(ctx.project_root)?;
            let text = match format {
                OutputFormat::Text => format_conflicts_text(&env).trim_end().to_string(),
                OutputFormat::Json => env.to_deterministic_json()?,
            };
            let tokens = estimate_tokens(&text) as u64;
            Ok(ToolExecution {
                result: CallToolResult::text(text),
                raw_est_tokens: tokens,
                filtered_est_tokens: tokens,
                is_run_filtered: false,
                stale_memories_caught: 0,
            })
        }
        "propose" => {
            let bp_val = args.get("blueprint").ok_or_else(|| {
                McpError::InvalidParams(
                    "`blueprint` object is required for `action: \"propose\"`".to_string(),
                )
            })?;
            if !bp_val.is_object() {
                return Err(McpError::InvalidParams(
                    "`blueprint` must be a JSON object".to_string(),
                ));
            }
            let blueprint: Blueprint = serde_json::from_value(bp_val.clone()).map_err(|err| {
                McpError::InvalidParams(format!("invalid `blueprint` payload: {err}"))
            })?;

            let env = propose_blueprint(ctx.project_root, blueprint)?;
            let text = match format {
                OutputFormat::Text => format_status_text(&env).trim_end().to_string(),
                OutputFormat::Json => env.to_deterministic_json()?,
            };
            let tokens = estimate_tokens(&text) as u64;
            Ok(ToolExecution {
                result: CallToolResult::text(text),
                raw_est_tokens: tokens,
                filtered_est_tokens: tokens,
                is_run_filtered: false,
                stale_memories_caught: 0,
            })
        }
        "select" => {
            let bubble_id = require_non_empty_string(args, "bubble_id")?;
            let option_id = require_non_empty_string(args, "option_id")?;
            let vision_note = parse_optional_string(args, "vision_note")?;
            let confirm = parse_optional_bool(args, "confirm")?.unwrap_or(true);

            let env = select_bubble_option(
                ctx.project_root,
                bubble_id,
                option_id,
                vision_note.as_deref(),
                confirm,
            )?;
            let text = match format {
                OutputFormat::Text => format_status_text(&env).trim_end().to_string(),
                OutputFormat::Json => env.to_deterministic_json()?,
            };
            let tokens = estimate_tokens(&text) as u64;
            Ok(ToolExecution {
                result: CallToolResult::text(text),
                raw_est_tokens: tokens,
                filtered_est_tokens: tokens,
                is_run_filtered: false,
                stale_memories_caught: 0,
            })
        }
        "lock" => {
            let create_scaffold = parse_optional_bool(args, "create_scaffold")?.unwrap_or(false);
            let options = LockOptions {
                create_scaffold,
                ..LockOptions::default()
            };
            let env = lock_and_execute(ctx.project_root, &options)?;
            let text = match format {
                OutputFormat::Text => format_lock_text(&env).trim_end().to_string(),
                OutputFormat::Json => env.to_deterministic_json()?,
            };
            let tokens = estimate_tokens(&text) as u64;
            Ok(ToolExecution {
                result: CallToolResult::text(text),
                raw_est_tokens: tokens,
                filtered_est_tokens: tokens,
                is_run_filtered: false,
                stale_memories_caught: 0,
            })
        }
        "next_task" => {
            let env = get_next_ready_task(ctx.project_root)?;
            let text = match format {
                OutputFormat::Text => format_next_task_text(&env).trim_end().to_string(),
                OutputFormat::Json => env.to_deterministic_json()?,
            };
            let tokens = estimate_tokens(&text) as u64;
            Ok(ToolExecution {
                result: CallToolResult::text(text),
                raw_est_tokens: tokens,
                filtered_est_tokens: tokens,
                is_run_filtered: false,
                stale_memories_caught: 0,
            })
        }
        "complete_task" => {
            let task_id = require_non_empty_string(args, "task_id")?;
            let env = complete_task(ctx.project_root, task_id)?;
            let text = match format {
                OutputFormat::Text => format_complete_task_text(&env).trim_end().to_string(),
                OutputFormat::Json => env.to_deterministic_json()?,
            };
            let tokens = estimate_tokens(&text) as u64;
            Ok(ToolExecution {
                result: CallToolResult::text(text),
                raw_est_tokens: tokens,
                filtered_est_tokens: tokens,
                is_run_filtered: false,
                stale_memories_caught: 0,
            })
        }
        "handoff" => {
            let budget =
                parse_optional_usize(args, "budget")?.unwrap_or(DEFAULT_HANDOFF_BUDGET_TOKENS);
            let read_only = ctx.mode == ProjectMode::ReadOnly;
            let input = collect_handoff_input(ctx.project_root, read_only, ctx.readonly_cache_dir);
            let env = compose_handoff(input, budget);
            let stale_caught = env.data.stale_memory_count as u64;
            let text = match format {
                OutputFormat::Text => format_handoff_text(&env).trim_end().to_string(),
                OutputFormat::Json => env.to_deterministic_json()?,
            };
            let tokens = estimate_tokens(&text) as u64;
            Ok(ToolExecution {
                result: CallToolResult::text(text),
                raw_est_tokens: tokens,
                filtered_est_tokens: tokens,
                is_run_filtered: false,
                stale_memories_caught: stale_caught,
            })
        }
        other => Err(McpError::InvalidParams(format!(
            "unsupported `klens_blueprint` action `{other}` (expected status|check|propose|select|lock|next_task|complete_task|handoff)"
        ))),
    }
}

fn require_non_empty_string<'a>(args: &'a Value, field: &str) -> Result<&'a str, McpError> {
    match args.get(field) {
        Some(val) => val
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                McpError::InvalidParams(format!("`{field}` must be a non-empty string"))
            }),
        None => Err(McpError::InvalidParams(format!(
            "`{field}` is required and must be a non-empty string"
        ))),
    }
}

fn collect_git_summary(root: &Path) -> Option<GitStatusSummary> {
    let inside = run_git_stdout(root, &["rev-parse", "--is-inside-work-tree"])?;
    if inside.trim() != "true" {
        return None;
    }

    let branch = run_git_stdout(root, &["symbolic-ref", "--short", "HEAD"])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            run_git_stdout(root, &["rev-parse", "--short", "HEAD"])
                .map(|s| format!("DETACHED@{}", s.trim()))
        })
        .unwrap_or_else(|| "UNBORN".to_string());

    let recent_commits = run_git_stdout(root, &["log", "-n", "5", "--pretty=format:%h%x09%s"])
        .map(|raw| {
            raw.lines()
                .filter_map(|line| {
                    let (sha, msg) = line.split_once('\t')?;
                    Some(GitCommitSummary {
                        sha: sha.trim().to_string(),
                        message: msg.trim().to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let mut dirty_files: Vec<String> = run_git_stdout(
        root,
        &["-c", "core.quotepath=false", "status", "--porcelain=v1"],
    )
    .map(|raw| {
        raw.lines()
            .map(str::trim_end)
            .filter(|line| !line.trim().is_empty())
            .map(|line| line.trim().replace('\\', "/"))
            .collect()
    })
    .unwrap_or_default();
    dirty_files.sort();
    dirty_files.dedup();

    Some(GitStatusSummary {
        branch,
        recent_commits,
        dirty_files,
    })
}

fn run_git_stdout(root: &Path, args: &[&str]) -> Option<String> {
    let mut cmd = Command::new("git");
    cmd.args(args)
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(klens_exec::WINDOWS_CREATE_NO_WINDOW);
    }
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn collect_last_failed_run(project_root: &ProjectRoot) -> Option<FailedRunSummary> {
    let store = RunStore::new(project_root.clone());
    let runs = store.list_runs(Some(25)).ok()?;

    // `runs` is sorted newest-first. Track commands that have already succeeded (`exit_code == 0`)
    // in a newer run so resolved historical failures are not reported as active failures.
    let mut passed_commands: BTreeSet<&str> = BTreeSet::new();
    let mut active_failure = None;
    for run in &runs {
        let cmd_key = run.command.trim();
        if run.exit_code == 0 {
            passed_commands.insert(cmd_key);
        } else if !passed_commands.contains(cmd_key) {
            active_failure = Some(run);
            break;
        }
    }
    let failed_meta = active_failure?.clone();

    let error_excerpt = match show_stored_run(project_root, &failed_meta.run_id, false) {
        Ok(env) => env.data.content,
        Err(_) => String::new(),
    };

    Some(FailedRunSummary {
        run_id: failed_meta.run_id,
        command: failed_meta.command,
        exit_code: failed_meta.exit_code,
        raw_log_path: failed_meta.raw_log_path,
        error_excerpt,
    })
}

fn collect_memory_summary(
    project_root: &ProjectRoot,
    read_only: bool,
    readonly_cache_dir: Option<&Path>,
) -> MemorySummary {
    let mut resolver = LazyCodeSymbolResolver::new(project_root, read_only, readonly_cache_dir);
    let Ok(env) = list_memory_index(project_root, None, None, false, &mut resolver) else {
        return MemorySummary::default();
    };

    let mut active_notes = Vec::new();
    let mut stale_notes = Vec::new();

    for entry in env.data.entries {
        let is_stale = entry.trust == TrustLevel::Stale;
        let stale_details: Vec<String> = entry
            .stale_anchors
            .iter()
            .map(|chk| {
                let target = match &chk.symbol {
                    Some(sym) => format!("{}#{sym}", chk.path),
                    None => chk.path.clone(),
                };
                let reason = chk.stale_reason.map(|r| r.as_str()).unwrap_or("stale");
                format!("{target}: {reason}")
            })
            .collect();

        let item = MemoryEntrySummary {
            id: entry.id,
            title: entry.title,
            kind: entry.kind.as_str().to_string(),
            is_stale,
            stale_details,
        };
        if is_stale {
            stale_notes.push(item);
        } else {
            active_notes.push(item);
        }
    }

    let parse_warnings: Vec<String> = env
        .warnings
        .into_iter()
        .filter(|w| !w.contains("memory note(s) have STALE BLAKE3 anchors"))
        .collect();

    MemorySummary {
        total_notes: env.data.total_notes,
        active_notes,
        stale_notes,
        parse_warnings,
    }
}
