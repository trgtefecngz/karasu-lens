//! Blueprint board and deterministic session handoff API routes (`/api/blueprint/*`, `/api/handoff`).

use std::collections::BTreeMap;

use klens_blueprint::{
    Blueprint, DEFAULT_HANDOFF_BUDGET_TOKENS, LockOptions, blueprint_status, complete_task,
    compose_handoff, format_handoff_text, load_blueprint_optional, load_contract_optional,
    load_tasks_optional, lock_and_execute, propose_blueprint, select_bubble_option,
};
use serde_json::json;
use tiny_http::Request;

use crate::error::UiError;
use crate::routes::bridge::collect_handoff_input;
use crate::routes::common::{
    HttpResponse, ensure_writable, json_opt_bool, json_opt_str, json_req_str, query_opt_usize,
    read_json_body,
};
use crate::state::UiState;

/// `GET /api/blueprint` — full board snapshot (status, bubbles, conflicts, tasks, contract, ui_lang).
pub fn handle_get_blueprint(state: &UiState) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    let (_, _, ui_lang) = state.snapshot();

    let status_env = blueprint_status(&project_root)?;
    let blueprint = load_blueprint_optional(&project_root)?;
    let tasks = load_tasks_optional(&project_root)?;
    let contract_markdown = load_contract_optional(&project_root)?;

    HttpResponse::json_ok(&json!({
        "read_only": read_only,
        "preferred_user_language": ui_lang,
        "status": status_env,
        "blueprint": blueprint,
        "tasks": tasks,
        "contract_markdown": contract_markdown,
    }))
}

/// `POST /api/blueprint/propose` — create or update draft `blueprint.json`.
pub fn handle_propose_blueprint(
    state: &UiState,
    request: &mut Request,
) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    ensure_writable(read_only, "blueprint.propose")?;

    let body = read_json_body(request, false)?;
    let bp_value = body.get("blueprint").unwrap_or(&body);
    let blueprint: Blueprint = serde_json::from_value(bp_value.clone())
        .map_err(|e| UiError::BadRequest(format!("invalid blueprint payload: {e}")))?;

    let status_env = propose_blueprint(&project_root, blueprint)?;
    let saved = load_blueprint_optional(&project_root)?;
    HttpResponse::json_ok(&json!({
        "status": status_env,
        "blueprint": saved,
    }))
}

/// `POST /api/blueprint/select` — select an option and optional vision note on a bubble.
pub fn handle_select_bubble(
    state: &UiState,
    request: &mut Request,
) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    ensure_writable(read_only, "blueprint.select")?;

    let body = read_json_body(request, false)?;
    let bubble_id = json_req_str(&body, "bubble_id")?;
    let option_id = json_req_str(&body, "option_id")?;
    let vision_note = json_opt_str(&body, "vision_note", true)?;
    let confirm = json_opt_bool(&body, "confirm")?.unwrap_or(true);

    let status_env = select_bubble_option(
        &project_root,
        bubble_id,
        option_id,
        vision_note.as_deref(),
        confirm,
    )?;
    let saved = load_blueprint_optional(&project_root)?;
    HttpResponse::json_ok(&json!({
        "status": status_env,
        "blueprint": saved,
    }))
}

/// `POST /api/blueprint/lock` — lock Blueprint (requires 0 error conflicts) and compile contract + tasks.
pub fn handle_lock_blueprint(
    state: &UiState,
    request: &mut Request,
) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    ensure_writable(read_only, "blueprint.lock")?;

    let body = read_json_body(request, true)?;
    let create_scaffold = json_opt_bool(&body, "create_scaffold")?.unwrap_or(false);
    let options = LockOptions {
        create_scaffold,
        ..LockOptions::default()
    };

    let lock_env = lock_and_execute(&project_root, &options)?;
    let status_env = blueprint_status(&project_root)?;
    let tasks = load_tasks_optional(&project_root)?;
    let contract_markdown = load_contract_optional(&project_root)?;

    HttpResponse::json_ok(&json!({
        "lock": lock_env,
        "status": status_env,
        "tasks": tasks,
        "contract_markdown": contract_markdown,
    }))
}

/// `POST /api/blueprint/tasks/complete` — mark a compiled task as `done`.
pub fn handle_complete_task(
    state: &UiState,
    request: &mut Request,
) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    ensure_writable(read_only, "blueprint.complete_task")?;

    let body = read_json_body(request, false)?;
    let task_id = json_req_str(&body, "task_id")?;

    let result_env = complete_task(&project_root, task_id)?;
    let tasks = load_tasks_optional(&project_root)?;

    HttpResponse::json_ok(&json!({
        "result": result_env,
        "tasks": tasks,
    }))
}

/// `GET /api/handoff?budget=...` — generate deterministic verified handoff summary.
pub fn handle_get_handoff(
    state: &UiState,
    params: &BTreeMap<String, String>,
) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    let budget =
        query_opt_usize(params, "budget", 100, 32_000)?.unwrap_or(DEFAULT_HANDOFF_BUDGET_TOKENS);

    let input = collect_handoff_input(
        &project_root,
        read_only,
        state.readonly_cache_dir.as_deref(),
    );
    let env = compose_handoff(input, budget);
    let text = format_handoff_text(&env).trim_end().to_string();

    HttpResponse::json_ok(&json!({
        "envelope": env,
        "text": text,
    }))
}
