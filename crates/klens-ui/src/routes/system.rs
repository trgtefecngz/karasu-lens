//! System, directory picker, project lifecycle, agent access, checkpoints, settings, and shutdown routes.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use klens_adapters::{
    AdapterOptions, AdapterRegistry, HostKind, HostTarget, attach_project,
    clean_binary_path_string, detach_project, detect_environment, disconnect_host,
    global_config_path_in, init_hosts, paths_equivalent, run_doctor, scan_directory,
};
use klens_core::{
    AdapterContext, GlobalConfig, ProjectConfig, ProjectMode, ProjectRoot, SUPPORTED_UI_LANGS,
};
use klens_exec::{create_checkpoint, list_checkpoints, rollback_checkpoint};
use serde_json::json;
use tiny_http::Request;

use crate::error::UiError;
use crate::routes::bridge::upgrade_doctor_with_ast_memory;
use crate::routes::common::{
    HttpResponse, ensure_writable, json_opt_bool, json_opt_str, json_opt_usize, json_req_str,
    read_json_body,
};
use crate::state::{UiState, directory_looks_like_project};

/// `GET /api/status` — active project, read-only state, registered projects, language, port.
pub fn handle_get_status(state: &UiState) -> Result<HttpResponse, UiError> {
    let (active_opt, read_only, ui_lang) = state.snapshot();
    let global_cfg = GlobalConfig::load_or_default(&global_config_path_in(&state.home_dir))
        .unwrap_or_else(|_| GlobalConfig::default());

    let active_project = active_opt.as_ref().map(|root| {
        let cleaned = clean_binary_path_string(root.root());
        let name = root
            .root()
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&cleaned)
            .to_string();
        let cfg_path = root.root().join(".klens").join("config.toml");
        let attached = cfg_path.is_file();
        let mode = ProjectConfig::load(&cfg_path)
            .map(|c| c.mode)
            .unwrap_or(ProjectMode::Active);
        json!({
            "name": name,
            "path": cleaned,
            "project_id": root.project_id(),
            "attached": attached,
            "mode": mode,
        })
    });

    HttpResponse::json_ok(&json!({
        "version": env!("CARGO_PKG_VERSION"),
        "port": state.bound_port,
        "read_only": read_only,
        "cli_read_only_locked": state.cli_read_only_locked,
        "ui_lang": ui_lang,
        "supported_langs": SUPPORTED_UI_LANGS,
        "active_project": active_project,
        "registered_projects": global_cfg.registered_projects,
    }))
}

/// `GET /api/fs/dirs?path=...` — strictly read-only folder browser (NEVER reads file contents).
pub fn handle_fs_dirs(
    state: &UiState,
    params: &BTreeMap<String, String>,
) -> Result<HttpResponse, UiError> {
    let raw_path = params
        .get("path")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());

    let shortcuts = build_quick_shortcuts(&state.home_dir);

    let Some(target_str) = raw_path else {
        let roots = list_system_roots(&state.home_dir);
        return HttpResponse::json_ok(&json!({
            "current": null,
            "parent": null,
            "has_project_markers": false,
            "shortcuts": shortcuts,
            "dirs": roots,
        }));
    };

    if target_str.contains('\0') {
        return Err(UiError::BadRequest("path contains NUL byte".into()));
    }

    let candidate = PathBuf::from(target_str);
    if !candidate.exists() {
        return Err(UiError::NotFound(format!(
            "directory does not exist: {target_str}"
        )));
    }
    if !candidate.is_dir() {
        return Err(UiError::BadRequest(format!(
            "path is not a directory: {target_str}"
        )));
    }

    let canonical = fs::canonicalize(&candidate)?;
    let current = clean_binary_path_string(&canonical);
    let parent = canonical
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(clean_binary_path_string);

    let mut dirs = Vec::new();
    let entries = fs::read_dir(&canonical)?;
    for entry in entries.flatten() {
        let path = entry.path();
        // Metadata check only — never reads file contents.
        if !path.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        let cleaned = clean_binary_path_string(&path);
        let is_project = directory_looks_like_project(&path);
        dirs.push(json!({
            "name": name,
            "path": cleaned,
            "has_project_markers": is_project,
        }));
    }

    dirs.sort_by(|a, b| {
        let an = a
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        let bn = b
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        an.cmp(&bn)
    });

    HttpResponse::json_ok(&json!({
        "current": current,
        "parent": parent,
        "has_project_markers": directory_looks_like_project(&canonical),
        "shortcuts": shortcuts,
        "dirs": dirs,
    }))
}

/// `POST /api/projects/select` — switch active project and optional read-only mode.
pub fn handle_select_project(
    state: &UiState,
    request: &mut Request,
) -> Result<HttpResponse, UiError> {
    let body = read_json_body(request, false)?;
    let path_str = json_req_str(&body, "path")?;
    let requested_ro = json_opt_bool(&body, "read_only")?;

    let (project, effective_ro) = state.select_project(Path::new(path_str), requested_ro)?;
    let cleaned = clean_binary_path_string(project.root());
    let name = project
        .root()
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&cleaned)
        .to_string();

    HttpResponse::json_ok(&json!({
        "name": name,
        "path": cleaned,
        "project_id": project.project_id(),
        "read_only": effective_ro,
    }))
}

/// `POST /api/projects/scan` — read-only discovery of candidate projects 1–2 levels deep.
pub fn handle_scan_projects(
    state: &UiState,
    request: &mut Request,
) -> Result<HttpResponse, UiError> {
    let body = read_json_body(request, false)?;
    let path_str = json_req_str(&body, "path")?;
    let depth = json_opt_usize(&body, "depth")?.unwrap_or(2);
    if depth == 0 || depth > 2 {
        return Err(UiError::BadRequest("`depth` must be 1 or 2".to_string()));
    }

    let report = scan_directory(Path::new(path_str), &state.home_dir, depth)?;
    HttpResponse::json_ok(&report)
}

/// `POST /api/projects/attach` — attach active (or specified) project (supports `dry_run`).
pub fn handle_attach_project(
    state: &UiState,
    request: &mut Request,
) -> Result<HttpResponse, UiError> {
    let body = read_json_body(request, true)?;
    let dry_run = json_opt_bool(&body, "dry_run")?.unwrap_or(false);
    let mode = match json_opt_str(&body, "mode", false)? {
        Some(m) => Some(parse_project_mode(&m)?),
        None => None,
    };
    let explicit_path = json_opt_str(&body, "path", false)?;

    let (active_opt, read_only, _) = state.snapshot();
    if !dry_run {
        ensure_writable(read_only, "projects.attach")?;
    }

    let project_root = match explicit_path {
        Some(p) => ProjectRoot::new(Path::new(&p))?,
        None => active_opt.ok_or(UiError::NoActiveProject)?,
    };

    let report = attach_project(&state.home_dir, &project_root, mode, dry_run)?;
    HttpResponse::json_ok(&report)
}

/// `POST /api/projects/detach` — detach active (or specified) project (supports `dry_run` + `purge`).
pub fn handle_detach_project(
    state: &UiState,
    request: &mut Request,
) -> Result<HttpResponse, UiError> {
    let body = read_json_body(request, true)?;
    let dry_run = json_opt_bool(&body, "dry_run")?.unwrap_or(false);
    let purge = json_opt_bool(&body, "purge")?.unwrap_or(false);
    let explicit_path = json_opt_str(&body, "path", false)?;

    let (active_opt, read_only, _) = state.snapshot();
    if !dry_run {
        ensure_writable(read_only, "projects.detach")?;
    }

    let project_root = match explicit_path {
        Some(p) => ProjectRoot::new(Path::new(&p))?,
        None => active_opt.ok_or(UiError::NoActiveProject)?,
    };

    let registry = AdapterRegistry::with_home(state.home_dir.clone(), &AdapterOptions::default());
    let report = detach_project(&registry, &project_root, purge, dry_run)?;
    HttpResponse::json_ok(&report)
}

/// `POST /api/projects/mode` — change `.klens/config.toml` mode (`active|read_only|paused`).
pub fn handle_set_project_mode(
    state: &UiState,
    request: &mut Request,
) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    ensure_writable(read_only, "projects.mode")?;

    let body = read_json_body(request, false)?;
    let mode_str = json_req_str(&body, "mode")?;
    let mode = parse_project_mode(mode_str)?;

    let (cfg_abs, _) = project_root.resolve_for_write(".klens/config.toml")?;
    let mut proj_cfg = ProjectConfig::load_or_default(&cfg_abs)?;
    proj_cfg.mode = mode;
    proj_cfg.save_atomic(&cfg_abs)?;

    // Mirror mode change in `~/.klens/config.toml` if this project is registered.
    let global_path = global_config_path_in(&state.home_dir);
    if global_path.exists()
        && let Ok(mut gcfg) = GlobalConfig::load(&global_path)
    {
        let mut updated = false;
        for entry in &mut gcfg.registered_projects {
            if paths_equivalent(&entry.path, project_root.root()) {
                entry.mode = mode;
                updated = true;
            }
        }
        if updated {
            let _ = gcfg.save_atomic(&global_path);
        }
    }

    HttpResponse::json_ok(&json!({
        "mode": mode,
        "config_path": clean_binary_path_string(&cfg_abs),
    }))
}

/// `GET /api/agents/detect` — project-scoped agent access panel (configured + observed).
pub fn handle_agents_detect(state: &UiState) -> Result<HttpResponse, UiError> {
    let (project_root, _) = state.require_project()?;
    let registry = AdapterRegistry::with_home(state.home_dir.clone(), &AdapterOptions::default());
    let report = detect_environment(&registry, &project_root, &state.binary_path);
    HttpResponse::json_ok(&report)
}

/// `GET /api/agents/doctor` — full `klens doctor` diagnostics upgraded with AST memory verification.
pub fn handle_agents_doctor(state: &UiState) -> Result<HttpResponse, UiError> {
    let (project_root, _) = state.require_project()?;
    let registry = AdapterRegistry::with_home(state.home_dir.clone(), &AdapterOptions::default());
    let mut report = run_doctor(&registry, &project_root, &state.binary_path);
    upgrade_doctor_with_ast_memory(
        &mut report,
        &project_root,
        state.readonly_cache_dir.as_deref(),
    );
    let global_cfg_path = global_config_path_in(&state.home_dir);
    let sidecar_checks =
        klens_code::inspect_language_extensions_doctor(&global_cfg_path, &project_root);
    report.checks.extend(sidecar_checks);
    report.overall = report
        .checks
        .iter()
        .map(|c| c.severity)
        .max()
        .unwrap_or(klens_core::CheckSeverity::Ok);
    HttpResponse::json_ok(&report)
}

/// `POST /api/agents/init` — connect / refresh an AI host adapter (supports `dry_run`).
pub fn handle_agents_init(state: &UiState, request: &mut Request) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    let body = read_json_body(request, false)?;
    let host_str = json_req_str(&body, "host")?;
    let dry_run = json_opt_bool(&body, "dry_run")?.unwrap_or(false);

    if !dry_run {
        ensure_writable(read_only, "agents.init")?;
    }

    let target = parse_host_target(host_str, true)?;
    let registry = AdapterRegistry::with_home(state.home_dir.clone(), &AdapterOptions::default());
    let ctx = AdapterContext {
        project_root: project_root.root().to_path_buf(),
        binary_path: state.binary_path.clone(),
        dry_run,
    };
    let report = init_hosts(&registry, target, &ctx)?;
    HttpResponse::json_ok(&report)
}

/// `POST /api/agents/disconnect` — disconnect an AI host adapter (supports `dry_run`).
pub fn handle_agents_disconnect(
    state: &UiState,
    request: &mut Request,
) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    let body = read_json_body(request, false)?;
    let host_str = json_req_str(&body, "host")?;
    let dry_run = json_opt_bool(&body, "dry_run")?.unwrap_or(false);

    if !dry_run {
        ensure_writable(read_only, "agents.disconnect")?;
    }

    let target = parse_host_target(host_str, false)?;
    let registry = AdapterRegistry::with_home(state.home_dir.clone(), &AdapterOptions::default());
    let ctx = AdapterContext {
        project_root: project_root.root().to_path_buf(),
        binary_path: state.binary_path.clone(),
        dry_run,
    };
    let report = disconnect_host(&registry, target, &ctx)?;
    HttpResponse::json_ok(&report)
}

/// `GET /api/checkpoints` — list Git safety checkpoints (`refs/klens/checkpoints/*`).
pub fn handle_list_checkpoints(state: &UiState) -> Result<HttpResponse, UiError> {
    let (project_root, _) = state.require_project()?;
    let env = list_checkpoints(&project_root)?;
    HttpResponse::json_ok(&env)
}

/// `POST /api/checkpoints` — create a new Git safety checkpoint.
pub fn handle_create_checkpoint(
    state: &UiState,
    request: &mut Request,
) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    ensure_writable(read_only, "checkpoints.create")?;

    let body = read_json_body(request, true)?;
    let note = json_opt_str(&body, "note", false)?;
    let env = create_checkpoint(&project_root, note.as_deref())?;
    HttpResponse::json_status(201, &env)
}

/// `POST /api/checkpoints/rollback` — preview (`dry_run: true`) or apply rollback to a checkpoint.
pub fn handle_rollback_checkpoint(
    state: &UiState,
    request: &mut Request,
) -> Result<HttpResponse, UiError> {
    let (project_root, read_only) = state.require_project()?;
    let body = read_json_body(request, false)?;
    let id = json_req_str(&body, "id")?;
    let dry_run = json_opt_bool(&body, "dry_run")?.unwrap_or(true);

    if !dry_run {
        ensure_writable(read_only, "checkpoints.rollback")?;
    }

    let env = rollback_checkpoint(&project_root, id, dry_run)?;
    HttpResponse::json_ok(&env)
}

/// `PUT /api/settings/lang` — persist human-facing Web UI language into `~/.klens/config.toml`.
pub fn handle_set_lang(state: &UiState, request: &mut Request) -> Result<HttpResponse, UiError> {
    let body = read_json_body(request, false)?;
    let lang = json_req_str(&body, "ui_lang")?;
    let saved = state.set_ui_lang(lang)?;
    HttpResponse::json_ok(&json!({
        "ui_lang": saved,
    }))
}

/// `POST /api/shutdown` — gracefully stop the local HTTP server (guarded by triple CSRF gate).
pub fn handle_shutdown(state: &UiState) -> Result<HttpResponse, UiError> {
    state.request_shutdown();
    HttpResponse::json_ok(&json!({
        "status": "shutting_down",
    }))
}

fn parse_project_mode(raw: &str) -> Result<ProjectMode, UiError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "active" => Ok(ProjectMode::Active),
        "read_only" | "read-only" => Ok(ProjectMode::ReadOnly),
        "paused" => Ok(ProjectMode::Paused),
        other => Err(UiError::BadRequest(format!(
            "invalid project mode `{other}` (expected active|read_only|paused)"
        ))),
    }
}

fn parse_host_target(raw: &str, allow_auto: bool) -> Result<HostTarget, UiError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "auto" if allow_auto => Ok(HostTarget::Auto),
        "antigravity" => Ok(HostTarget::Single(HostKind::Antigravity)),
        "claude-code" | "claude_code" => Ok(HostTarget::Single(HostKind::ClaudeCode)),
        "codex" => Ok(HostTarget::Single(HostKind::Codex)),
        "generic" => Ok(HostTarget::Single(HostKind::Generic)),
        "all" => Ok(HostTarget::All),
        other => Err(UiError::BadRequest(format!(
            "invalid host target `{other}`"
        ))),
    }
}

fn build_quick_shortcuts(home_dir: &Path) -> Vec<serde_json::Value> {
    let mut items = Vec::new();
    let candidates = [
        ("Home", home_dir.to_path_buf()),
        ("Desktop", home_dir.join("Desktop")),
        ("Documents", home_dir.join("Documents")),
        ("Projects", home_dir.join("Projects")),
    ];
    for (label, path) in candidates {
        if path.is_dir() {
            let cleaned = fs::canonicalize(&path)
                .map(|p| clean_binary_path_string(&p))
                .unwrap_or_else(|_| clean_binary_path_string(&path));
            items.push(json!({ "label": label, "path": cleaned }));
        }
    }
    items
}

fn list_system_roots(home_dir: &Path) -> Vec<serde_json::Value> {
    let mut roots = Vec::new();
    #[cfg(windows)]
    {
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:\\", letter as char);
            let p = Path::new(&drive);
            if p.is_dir() {
                roots.push(json!({
                    "name": drive,
                    "path": drive,
                    "has_project_markers": false,
                }));
            }
        }
    }
    #[cfg(not(windows))]
    {
        let root = Path::new("/");
        if root.is_dir() {
            roots.push(json!({
                "name": "/",
                "path": "/",
                "has_project_markers": false,
            }));
        }
    }
    if roots.is_empty() && home_dir.is_dir() {
        let cleaned = clean_binary_path_string(home_dir);
        roots.push(json!({
            "name": cleaned.clone(),
            "path": cleaned,
            "has_project_markers": directory_looks_like_project(home_dir),
        }));
    }
    roots
}
