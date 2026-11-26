//! Verifiable second-brain memory CRUD routes (`/api/memory/*`) and terminal run history (`/api/runs/*`).

use std::collections::BTreeMap;

use klens_adapters::clean_binary_path_string;
use klens_exec::{list_stored_runs, show_stored_run};
use klens_memory::{
    AddMemoryRequest, MEMORY_DIR_REL, MemoryExportFormat, MemoryExportRequest, MemoryKind,
    MemoryStatus, UpdateMemoryRequest, add_memory, delete_memory, export_memory, get_memory,
    list_memory_index, refresh_memories, refresh_memory, search_memory, serialize_markdown_note,
    update_memory, verify_all_notes,
};
use serde_json::json;
use tiny_http::Request;

use crate::error::UiError;
use crate::routes::bridge::UiCodeSymbolResolver;
use crate::routes::common::{
    HttpResponse, ensure_writable, json_opt_anchors, json_opt_bool, json_opt_str,
    json_opt_string_array, json_req_str, query_opt_bool, query_opt_usize, read_json_body,
};
use crate::state::UiState;

/// `GET /api/memory?kind=...&tag=...&stale_only=...&q=...&limit=...`
pub fn handle_list_memory(
    state: &UiState,
    params: &BTreeMap<String, String>,
) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;

    let kind = match params
        .get("kind")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        Some(k) if !k.eq_ignore_ascii_case("all") => Some(MemoryKind::parse(k)?),
        _ => None,
    };
    let tag = params
        .get("tag")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let stale_only = query_opt_bool(params, "stale_only")?.unwrap_or(false);
    let q = params.get("q").map(|s| s.trim()).filter(|s| !s.is_empty());
    let limit = query_opt_usize(params, "limit", 1, 500)?;

    let memory_dir = clean_binary_path_string(&project_root.root().join(MEMORY_DIR_REL));
    let mut resolver = UiCodeSymbolResolver::new(
        &project_root,
        read_only,
        state.readonly_cache_dir.as_deref(),
    );

    if let Some(query) = q {
        let env = search_memory(&project_root, query, kind, limit, &mut resolver)?;
        let entries: Vec<_> = env
            .data
            .hits
            .iter()
            .filter(|h| !stale_only || h.entry.trust == klens_core::TrustLevel::Stale)
            .filter(|h| {
                tag.is_none_or(|t| h.entry.tags.iter().any(|et| et.eq_ignore_ascii_case(t)))
            })
            .map(|h| h.entry.clone())
            .collect();
        let stale_count = entries
            .iter()
            .filter(|e| e.trust == klens_core::TrustLevel::Stale)
            .count();

        return HttpResponse::json_ok(&json!({
            "mode": "search",
            "query": query,
            "memory_dir": memory_dir,
            "total_notes": entries.len(),
            "stale_count": stale_count,
            "entries": entries,
            "warnings": env.warnings,
        }));
    }

    let env = list_memory_index(&project_root, kind, tag, stale_only, &mut resolver)?;
    HttpResponse::json_ok(&json!({
        "mode": "index",
        "memory_dir": memory_dir,
        "total_notes": env.data.total_notes,
        "stale_count": env.data.stale_count,
        "entries": env.data.entries,
        "warnings": env.warnings,
    }))
}

/// `GET /api/memory/verify` — live BLAKE3 verification across all notes.
pub fn handle_verify_memory(state: &UiState) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    let mut resolver = UiCodeSymbolResolver::new(
        &project_root,
        read_only,
        state.readonly_cache_dir.as_deref(),
    );
    let env = verify_all_notes(&project_root, &mut resolver)?;
    HttpResponse::json_ok(&env)
}

/// `GET /api/memory/export?format=md|json&kind=...&tag=...&stale_only=...` — read-only export.
pub fn handle_export_memory(
    state: &UiState,
    params: &BTreeMap<String, String>,
) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;

    let format_raw = params
        .get("format")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("md");
    let format = MemoryExportFormat::parse(format_raw)?;

    let kind = match params
        .get("kind")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        Some(k) if !k.eq_ignore_ascii_case("all") => Some(MemoryKind::parse(k)?),
        _ => None,
    };
    let tag = params
        .get("tag")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let stale_only = query_opt_bool(params, "stale_only")?.unwrap_or(false);

    let mut resolver = UiCodeSymbolResolver::new(
        &project_root,
        read_only,
        state.readonly_cache_dir.as_deref(),
    );
    let env = export_memory(
        &project_root,
        MemoryExportRequest {
            kind,
            tag,
            stale_only,
            format,
        },
        &mut resolver,
    )?;

    let filename = format!("klens-memory-export.{}", format.file_extension());
    let content = match format {
        MemoryExportFormat::Markdown => env.data.rendered_markdown.clone().unwrap_or_default(),
        MemoryExportFormat::Json => env.to_deterministic_json_pretty()?,
    };

    HttpResponse::json_ok(&json!({
        "format": format.as_str(),
        "filename": filename,
        "content": content,
        "total_notes": env.data.total_notes,
        "stale_count": env.data.stale_count,
        "redactions_count": env.redactions_count,
        "warnings": env.warnings,
    }))
}

/// `POST /api/memory/refresh-all` — batch BLAKE3 anchor refresh with optional `stale_only` & `dry_run`.
pub fn handle_refresh_all_memory(
    state: &UiState,
    request: &mut Request,
) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    ensure_writable(read_only, "memory.refresh_all")?;

    let body = read_json_body(request, true)?;
    let stale_only = json_opt_bool(&body, "stale_only")?.unwrap_or(true);
    let dry_run = json_opt_bool(&body, "dry_run")?.unwrap_or(false);

    let mut resolver =
        UiCodeSymbolResolver::new(&project_root, dry_run, state.readonly_cache_dir.as_deref());
    let env = refresh_memories(&project_root, None, stale_only, dry_run, &mut resolver)?;
    HttpResponse::json_ok(&env)
}

/// `GET /api/memory/<id>` — read single note with live anchor verification and raw Markdown.
pub fn handle_get_memory(state: &UiState, id: &str) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    let mut resolver = UiCodeSymbolResolver::new(
        &project_root,
        read_only,
        state.readonly_cache_dir.as_deref(),
    );
    let env = get_memory(&project_root, id, &mut resolver)?;
    let markdown = serialize_markdown_note(&env.data.note.frontmatter, &env.data.note.body);
    HttpResponse::json_ok(&json!({
        "envelope": env,
        "markdown": markdown,
    }))
}

/// `POST /api/memory` — create a new Markdown memory note with BLAKE3 anchors.
pub fn handle_add_memory(state: &UiState, request: &mut Request) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    ensure_writable(read_only, "memory.add")?;

    let body = read_json_body(request, false)?;
    let title = json_req_str(&body, "title")?.to_string();
    let id = json_opt_str(&body, "id", false)?;
    let kind_str = json_opt_str(&body, "kind", false)?.unwrap_or_else(|| "decision".to_string());
    let kind = MemoryKind::parse(&kind_str)?;
    let note_body = json_opt_str(&body, "body", true)?.unwrap_or_default();
    let anchors = json_opt_anchors(&body, "anchors")?.unwrap_or_default();
    let tags = json_opt_string_array(&body, "tags")?.unwrap_or_default();

    let mut resolver =
        UiCodeSymbolResolver::new(&project_root, false, state.readonly_cache_dir.as_deref());
    let env = add_memory(
        &project_root,
        AddMemoryRequest {
            id,
            title,
            kind,
            body: note_body,
            anchors,
            tags,
        },
        &mut resolver,
    )?;

    HttpResponse::json_status(201, &env)
}

/// `PUT /api/memory/<id>` — update an existing memory note.
pub fn handle_update_memory(
    state: &UiState,
    id: &str,
    request: &mut Request,
) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    ensure_writable(read_only, "memory.update")?;

    let body = read_json_body(request, false)?;
    let title = json_opt_str(&body, "title", false)?;
    let kind = match json_opt_str(&body, "kind", false)? {
        Some(k) => Some(MemoryKind::parse(&k)?),
        None => None,
    };
    let status = match json_opt_str(&body, "status", false)? {
        Some(s) => Some(MemoryStatus::parse(&s)?),
        None => None,
    };
    let note_body = json_opt_str(&body, "body", true)?;
    let anchors = json_opt_anchors(&body, "anchors")?;
    let tags = json_opt_string_array(&body, "tags")?;
    let refresh_anchors = json_opt_bool(&body, "refresh_anchors")?.unwrap_or(false);

    let mut resolver =
        UiCodeSymbolResolver::new(&project_root, false, state.readonly_cache_dir.as_deref());
    let env = update_memory(
        &project_root,
        UpdateMemoryRequest {
            id: id.to_string(),
            title,
            kind,
            status,
            body: note_body,
            anchors,
            tags,
            refresh_anchors,
        },
        &mut resolver,
    )?;

    HttpResponse::json_ok(&env)
}

/// `POST /api/memory/<id>/refresh` — recompute BLAKE3 anchors of a reviewed note verbatim.
pub fn handle_refresh_memory(state: &UiState, id: &str) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    ensure_writable(read_only, "memory.refresh")?;

    let mut resolver =
        UiCodeSymbolResolver::new(&project_root, false, state.readonly_cache_dir.as_deref());
    let env = refresh_memory(&project_root, id, &mut resolver)?;
    HttpResponse::json_ok(&env)
}

/// `DELETE /api/memory/<id>` — delete a memory note from `.klens/memory/`.
pub fn handle_delete_memory(state: &UiState, id: &str) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    ensure_writable(read_only, "memory.delete")?;

    let env = delete_memory(&project_root, id)?;
    HttpResponse::json_ok(&env)
}

/// `GET /api/runs?limit=...` — list recorded `klens run` executions newest-first.
pub fn handle_list_runs(
    state: &UiState,
    params: &BTreeMap<String, String>,
) -> Result<HttpResponse, UiError> {
    let (project_root, _) = state.require_project()?;
    let limit = query_opt_usize(params, "limit", 1, 500)?;
    let env = list_stored_runs(&project_root, limit)?;
    HttpResponse::json_ok(&env)
}

/// `GET /api/runs/<id>?raw=true|false` — show filtered or raw log for a stored run.
pub fn handle_show_run(
    state: &UiState,
    run_id: &str,
    params: &BTreeMap<String, String>,
) -> Result<HttpResponse, UiError> {
    let (project_root, _) = state.require_project()?;
    let raw = query_opt_bool(params, "raw")?.unwrap_or(false);
    let env = show_stored_run(&project_root, run_id, raw)?;
    HttpResponse::json_ok(&env)
}
