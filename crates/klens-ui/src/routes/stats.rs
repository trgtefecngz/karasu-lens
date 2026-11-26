//! Unified 2-layer telemetry statistics route (`/api/stats`).
//!
//! Single source of truth: delegates 100% of aggregation directly to
//! `klens_core::telemetry::compute_stats` with fail-closed query validation.

use std::collections::BTreeMap;

use klens_core::telemetry::{StatsQuery, StatsRange, compute_stats};

use crate::error::UiError;
use crate::routes::common::HttpResponse;
use crate::state::UiState;

/// `GET /api/stats?range=today|7d|30d|all&scope=all|project`
pub fn handle_get_stats(
    state: &UiState,
    params: &BTreeMap<String, String>,
) -> Result<HttpResponse, UiError> {
    let range = match params.get("range") {
        None => StatsRange::Days7,
        Some(raw) => StatsRange::parse(raw).ok_or_else(|| {
            UiError::BadRequest(format!(
                "invalid `range` query parameter `{raw}` (expected one of: today, 7d, 30d, all)"
            ))
        })?,
    };

    let scope = match params.get("scope") {
        None => "all",
        Some(raw) => match raw.trim() {
            "all" => "all",
            "project" => "project",
            other => {
                return Err(UiError::BadRequest(format!(
                    "invalid `scope` query parameter `{other}` (expected `all` or `project`)"
                )));
            }
        },
    };

    let mut query = StatsQuery {
        range,
        metrics_path: state.metrics_path.clone(),
        claude_projects_dir: state.claude_projects_dir.clone(),
        ..StatsQuery::default()
    };

    if scope == "project" {
        let (proj_opt, _, _) = state.snapshot();
        if let Some(root) = proj_opt {
            query.project_id_filter = Some(root.project_id().to_string());
            query.project_filter = root
                .root()
                .file_name()
                .and_then(|s| s.to_str())
                .map(ToOwned::to_owned);
        }
    }

    let report = compute_stats(&query)?;
    HttpResponse::json_ok(&report)
}
