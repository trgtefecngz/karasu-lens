//! Out-of-core optional extension routes (`GET /api/extensions`, `POST /api/extensions/toggle`).
//!
//! Delegates exclusively to `klens_core::extensions` (single source of truth) and
//! enforces fail-closed JSON type validation + `read_only` lock protection on writes.

use klens_adapters::global_config_path_in;
use klens_core::{ExtensionScope, list_extensions, set_extension_enabled};
use tiny_http::Request;

use crate::error::UiError;
use crate::routes::common::{
    HttpResponse, ensure_writable, json_opt_str, json_req_bool, json_req_str, read_json_body,
};
use crate::state::UiState;

/// `GET /api/extensions` — read-only catalog and global/project opt-in status.
pub fn handle_list_extensions(state: &UiState) -> Result<HttpResponse, UiError> {
    let (active_opt, _, _) = state.snapshot();
    let global_cfg_path = global_config_path_in(&state.home_dir);
    let mut report = list_extensions(&global_cfg_path, active_opt.as_ref())?;
    klens_code::enrich_extension_list_health(&mut report, &global_cfg_path, active_opt.as_ref());
    HttpResponse::json_ok(&report)
}

/// `POST /api/extensions/toggle` — atomically enable or disable a validated optional extension.
///
/// Security & fail-closed guarantees:
/// - Protected by `security_guard` (strict `Host` + triple CSRF gate: `Origin` + `X-Klens-Request: 1` + session cookie).
/// - Blocked with `403` whenever `read_only` mode is active.
/// - Rejects unknown/invalid extension IDs, non-boolean `enabled`, or unknown `scope` with `400`.
pub fn handle_toggle_extension(
    state: &UiState,
    request: &mut Request,
) -> Result<HttpResponse, UiError> {
    let (active_opt, read_only, _) = state.snapshot();
    ensure_writable(read_only, "extensions.toggle")?;

    let body = read_json_body(request, false)?;
    let id = json_req_str(&body, "id")?;
    let enabled = json_req_bool(&body, "enabled")?;
    let scope = match json_opt_str(&body, "scope", false)? {
        None => ExtensionScope::Project,
        Some(raw) => parse_extension_scope(&raw)?,
    };

    let project_root = match scope {
        ExtensionScope::Project => Some(active_opt.ok_or(UiError::NoActiveProject)?),
        ExtensionScope::Global => None,
    };

    let global_cfg_path = global_config_path_in(&state.home_dir);
    let report =
        set_extension_enabled(id, enabled, scope, &global_cfg_path, project_root.as_ref())?;
    HttpResponse::json_ok(&report)
}

fn parse_extension_scope(raw: &str) -> Result<ExtensionScope, UiError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "project" => Ok(ExtensionScope::Project),
        "global" => Ok(ExtensionScope::Global),
        other => Err(UiError::BadRequest(format!(
            "invalid extension scope `{other}` (expected `project` or `global`)"
        ))),
    }
}
