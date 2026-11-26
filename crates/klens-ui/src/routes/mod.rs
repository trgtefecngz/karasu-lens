//! Thin route dispatcher mapping HTTP `(Method, path)` pairs to modular route handlers.
//!
//! Zero shared helpers live here (`routes/common.rs` is the strict leaf module) to maintain
//! a clean DAG with 0 circular dependencies.

pub mod blueprint;
pub mod bridge;
pub mod code;
pub mod common;
pub mod extensions;
pub mod memory;
pub mod stats;
pub mod system;

use std::collections::BTreeMap;

use tiny_http::{Method, Request};

use crate::assets::lookup_static_asset;
use crate::error::UiError;
use crate::routes::common::HttpResponse;
use crate::security::{parse_query_params, percent_decode_utf8, split_url_path_query};
use crate::state::UiState;

/// Dispatch an already-authenticated HTTP request to its corresponding handler.
pub fn dispatch(state: &UiState, request: &mut Request) -> Result<HttpResponse, UiError> {
    let method = request.method().clone();
    let url = request.url().to_string();
    let (raw_path, raw_query) = split_url_path_query(&url);

    let params: BTreeMap<String, String> = match raw_query {
        Some(q) => parse_query_params(q)?,
        None => BTreeMap::new(),
    };

    // Embedded offline static assets (`GET` / `HEAD`).
    if matches!(method, Method::Get | Method::Head)
        && !raw_path.starts_with("/api/")
        && let Some((content_type, body)) = lookup_static_asset(raw_path)
    {
        let mut resp = HttpResponse::static_asset(content_type, body);
        if matches!(method, Method::Head) {
            resp.body.clear();
        }
        return Ok(resp);
    }

    // Dynamic API routes with path segments (`/api/memory/<id>`, `/api/runs/<id>`).
    if let Some(rest) = raw_path.strip_prefix("/api/memory/") {
        if rest == "verify" {
            return match method {
                Method::Get => memory::handle_verify_memory(state),
                _ => Err(UiError::MethodNotAllowed(format!(
                    "{method} not allowed on {raw_path}"
                ))),
            };
        }
        if rest == "export" {
            return match method {
                Method::Get => memory::handle_export_memory(state, &params),
                _ => Err(UiError::MethodNotAllowed(format!(
                    "{method} not allowed on {raw_path}"
                ))),
            };
        }
        if rest == "refresh-all" {
            return match method {
                Method::Post => memory::handle_refresh_all_memory(state, request),
                _ => Err(UiError::MethodNotAllowed(format!(
                    "{method} not allowed on {raw_path}"
                ))),
            };
        }
        if let Some(id_raw) = rest.strip_suffix("/refresh") {
            let id = percent_decode_utf8(id_raw, false)?;
            return match method {
                Method::Post => memory::handle_refresh_memory(state, &id),
                _ => Err(UiError::MethodNotAllowed(format!(
                    "{method} not allowed on {raw_path}"
                ))),
            };
        }
        if !rest.contains('/') && !rest.is_empty() {
            let id = percent_decode_utf8(rest, false)?;
            return match method {
                Method::Get => memory::handle_get_memory(state, &id),
                Method::Put => memory::handle_update_memory(state, &id, request),
                Method::Delete => memory::handle_delete_memory(state, &id),
                _ => Err(UiError::MethodNotAllowed(format!(
                    "{method} not allowed on {raw_path}"
                ))),
            };
        }
    }

    if let Some(id_raw) = raw_path.strip_prefix("/api/runs/")
        && !id_raw.contains('/')
        && !id_raw.is_empty()
    {
        let run_id = percent_decode_utf8(id_raw, false)?;
        return match method {
            Method::Get => memory::handle_show_run(state, &run_id, &params),
            _ => Err(UiError::MethodNotAllowed(format!(
                "{method} not allowed on {raw_path}"
            ))),
        };
    }

    match (method, raw_path) {
        // System, filesystem picker, project lifecycle, agents, checkpoints, settings, shutdown
        (Method::Get, "/api/status") => system::handle_get_status(state),
        (Method::Get, "/api/fs/dirs") => system::handle_fs_dirs(state, &params),
        (Method::Post, "/api/projects/select") => system::handle_select_project(state, request),
        (Method::Post, "/api/projects/scan") => system::handle_scan_projects(state, request),
        (Method::Post, "/api/projects/attach") => system::handle_attach_project(state, request),
        (Method::Post, "/api/projects/detach") => system::handle_detach_project(state, request),
        (Method::Post, "/api/projects/mode") => system::handle_set_project_mode(state, request),
        (Method::Get, "/api/agents/detect") => system::handle_agents_detect(state),
        (Method::Get, "/api/agents/doctor") => system::handle_agents_doctor(state),
        (Method::Post, "/api/agents/init") => system::handle_agents_init(state, request),
        (Method::Post, "/api/agents/disconnect") => {
            system::handle_agents_disconnect(state, request)
        }
        (Method::Get, "/api/checkpoints") => system::handle_list_checkpoints(state),
        (Method::Post, "/api/checkpoints") => system::handle_create_checkpoint(state, request),
        (Method::Post, "/api/checkpoints/rollback") => {
            system::handle_rollback_checkpoint(state, request)
        }
        (Method::Put, "/api/settings/lang") => system::handle_set_lang(state, request),
        (Method::Get, "/api/extensions") => extensions::handle_list_extensions(state),
        (Method::Post, "/api/extensions/toggle") => {
            extensions::handle_toggle_extension(state, request)
        }
        (Method::Post, "/api/shutdown") => system::handle_shutdown(state),

        // Blueprint & Handoff
        (Method::Get, "/api/blueprint") => blueprint::handle_get_blueprint(state),
        (Method::Post, "/api/blueprint/propose") => {
            blueprint::handle_propose_blueprint(state, request)
        }
        (Method::Post, "/api/blueprint/select") => blueprint::handle_select_bubble(state, request),
        (Method::Post, "/api/blueprint/lock") => blueprint::handle_lock_blueprint(state, request),
        (Method::Post, "/api/blueprint/tasks/complete") => {
            blueprint::handle_complete_task(state, request)
        }
        (Method::Get, "/api/handoff") => blueprint::handle_get_handoff(state, &params),

        // Code graph, outline, impact, health
        (Method::Get, "/api/code/graph") => code::handle_get_graph(state),
        (Method::Get, "/api/code/outline") => code::handle_get_outline(state, &params),
        (Method::Get, "/api/code/impact") => code::handle_get_impact(state, &params),
        (Method::Get, "/api/code/health") => code::handle_get_health(state),

        // Memory & Runs
        (Method::Get, "/api/memory") => memory::handle_list_memory(state, &params),
        (Method::Post, "/api/memory") => memory::handle_add_memory(state, request),
        (Method::Get, "/api/runs") => memory::handle_list_runs(state, &params),

        // Unified 2-layer stats
        (Method::Get, "/api/stats") => stats::handle_get_stats(state, &params),

        _ => Err(UiError::NotFound(format!("unknown endpoint `{raw_path}`"))),
    }
}
