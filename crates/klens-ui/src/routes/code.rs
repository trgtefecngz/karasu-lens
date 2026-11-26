//! Code graph, AST outline, blast-radius impact, and traffic-light health routes (`/api/code/*`).

use std::collections::{BTreeMap, BTreeSet};

use klens_code::{analyze_impact, build_code_graph, outline_path, run_health_check};
use klens_core::{RelPath, TrustLevel};
use klens_memory::{MEMORY_DIR_REL, list_memory_index};
use serde_json::json;

use crate::error::UiError;
use crate::routes::bridge::{
    UiCodeSymbolResolver, collect_last_failed_run, open_code_index, upgrade_health_with_memory,
};
use crate::routes::common::{HttpResponse, query_opt_usize, query_req_str};
use crate::state::UiState;

/// `GET /api/code/graph` — build deterministic code graph enriched with live memory & run badges.
pub fn handle_get_graph(state: &UiState) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    let mut index = open_code_index(state, &project_root, read_only)?;
    let graph_env = build_code_graph(&mut index)?;

    // Collect per-file memory metadata (`active_count`, `stale_count`, note IDs) from `klens-memory`.
    let mut file_memory_badges: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut stale_files: BTreeSet<String> = BTreeSet::new();

    if project_root.root().join(MEMORY_DIR_REL).is_dir() {
        let mut resolver = UiCodeSymbolResolver::new(
            &project_root,
            read_only,
            state.readonly_cache_dir.as_deref(),
        );
        if let Ok(mem_env) = list_memory_index(&project_root, None, None, false, &mut resolver) {
            let mut per_file: BTreeMap<String, (usize, usize, Vec<String>)> = BTreeMap::new();
            for entry in &mem_env.data.entries {
                let is_stale = entry.trust == TrustLevel::Stale;
                let mut seen_paths = BTreeSet::new();
                for anchor_path in &entry.anchor_paths {
                    let file_path = anchor_path.split('#').next().unwrap_or(anchor_path);
                    if file_path.is_empty() {
                        continue;
                    }
                    let file_key = file_path.to_string();
                    if seen_paths.insert(file_key.clone()) {
                        let slot = per_file
                            .entry(file_key.clone())
                            .or_insert_with(|| (0, 0, Vec::new()));
                        slot.0 += 1;
                        if is_stale {
                            slot.1 += 1;
                            stale_files.insert(file_key);
                        }
                        slot.2.push(entry.id.clone());
                    }
                }
            }
            for (path, (total, stale, note_ids)) in per_file {
                file_memory_badges.insert(
                    path,
                    json!({
                        "total_notes": total,
                        "stale_notes": stale,
                        "note_ids": note_ids,
                    }),
                );
            }
        }
    }

    // Detect files referenced in the latest active failed run (if any).
    let failed_run_files = collect_latest_failed_run_files(&project_root, &graph_env.data.nodes);

    HttpResponse::json_ok(&json!({
        "graph": graph_env,
        "memory_badges": file_memory_badges,
        "stale_files": stale_files,
        "failed_run_files": failed_run_files,
    }))
}

/// `GET /api/code/outline?path=...&budget=...` — AST symbol outline for a confined workspace path.
pub fn handle_get_outline(
    state: &UiState,
    params: &BTreeMap<String, String>,
) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    let rel_str = query_req_str(params, "path")?;
    let rel = RelPath::normalize(rel_str)?;
    // Verify confinement and reject sensitive files cleanly before indexing.
    project_root.resolve_existing(rel.as_str())?;

    let budget = query_opt_usize(params, "budget", 50, 100_000)?;
    let mut index = open_code_index(state, &project_root, read_only)?;
    let outline_env = outline_path(&mut index, Some(&rel), budget)?;

    HttpResponse::json_ok(&outline_env)
}

/// `GET /api/code/impact?target=...` — blast-radius dependents/callers with confidence tags.
pub fn handle_get_impact(
    state: &UiState,
    params: &BTreeMap<String, String>,
) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    let target = query_req_str(params, "target")?;

    let mut index = open_code_index(state, &project_root, read_only)?;
    let impact_env = analyze_impact(&mut index, target)?;

    HttpResponse::json_ok(&impact_env)
}

/// `GET /api/code/health` — 5 deterministic code health checks + live `.klens/memory/` staleness check.
pub fn handle_get_health(state: &UiState) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    let mut index = open_code_index(state, &project_root, read_only)?;
    let mut health_env = run_health_check(&mut index)?;
    drop(index);

    upgrade_health_with_memory(
        &mut health_env,
        &project_root,
        read_only,
        state.readonly_cache_dir.as_deref(),
    );

    HttpResponse::json_ok(&health_env)
}

fn collect_latest_failed_run_files(
    project_root: &klens_core::ProjectRoot,
    nodes: &[klens_code::GraphNode],
) -> Vec<String> {
    let Some(failed) = collect_last_failed_run(project_root) else {
        return Vec::new();
    };
    let text_norm = failed.error_excerpt.replace('\\', "/");
    let mut matched = Vec::new();
    for node in nodes {
        if text_norm.contains(&node.path) {
            matched.push(node.path.clone());
        }
    }
    matched.sort();
    matched.dedup();
    matched
}
