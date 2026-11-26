//! Symmetric attach/detach, read-only directory scan, host init/disconnect, and global uninstall.
//!
//! Invariants enforced across every function here:
//! - Single source of truth for registered projects: `klens_core::GlobalConfig` (`~/.klens/config.toml`).
//!   NEVER writes a separate `projects.json`.
//! - Every mutating command honors `dry_run == true` with **zero bytes written or deleted**.
//! - `detach` touches ONLY the target project (never global host configs) and preserves
//!   `.klens/blueprint/` + `.klens/memory/` unless `purge == true`.

use std::fs;
use std::path::{Path, PathBuf};

use klens_core::{
    AdapterContext, GlobalConfig, HostDetectStatus, InstallReport, KlensError, ProjectConfig,
    ProjectMode, ProjectRoot, RegisteredProject,
};
use serde::{Deserialize, Serialize};

use crate::adapters::{
    AdapterRegistry, HostKind, HostTarget, clean_binary_path_string, global_config_path_in,
    paths_equivalent,
};
use crate::error::AdapterError;
use crate::git_hook::detach_pre_commit_hook_if_present;
use crate::purge::purge_project_backups_and_empty_claude_dirs;
use crate::text_format::{MarkerStyle, remove_marked_file, upsert_marked_file};

/// Managed `.gitignore` block inserted by `klens attach` and removed cleanly by `klens detach`.
pub const GITIGNORE_BLOCK_BODY: &str = ".klens/cache/\n.klens/runs/";

const PROJECT_MARKERS: &[&str] = &[
    ".klens",
    ".git",
    "Cargo.toml",
    "package.json",
    "pyproject.toml",
    "go.mod",
    "Makefile",
    "pom.xml",
    "build.gradle",
];

const SCAN_SKIP_DIRS: &[&str] = &[
    ".git",
    ".klens",
    "node_modules",
    "target",
    ".venv",
    "venv",
    "dist",
    "build",
    "__pycache__",
];

/// Single project discovered by read-only `klens scan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannedProject {
    pub name: String,
    pub path: PathBuf,
    pub markers: Vec<String>,
    pub has_klens_dir: bool,
    pub registered_globally: bool,
}

/// Output of `klens scan <dir>` (strictly read-only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub root_dir: PathBuf,
    pub max_depth: usize,
    pub projects: Vec<ScannedProject>,
}

/// Output of `klens init`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitReport {
    pub dry_run: bool,
    pub binary_path: PathBuf,
    pub selected_hosts: Vec<HostKind>,
    pub reports: Vec<InstallReport>,
}

/// Output of `klens attach`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachReport {
    pub project_root: PathBuf,
    pub project_name: String,
    pub mode: ProjectMode,
    pub dry_run: bool,
    pub changed: bool,
    pub files_touched: Vec<PathBuf>,
    pub notes: Vec<String>,
}

/// Output of `klens detach`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachReport {
    pub project_root: PathBuf,
    pub purge: bool,
    pub dry_run: bool,
    pub changed: bool,
    pub files_touched: Vec<PathBuf>,
    pub preserved: Vec<PathBuf>,
    pub notes: Vec<String>,
}

/// Output of `klens disconnect`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisconnectReport {
    pub dry_run: bool,
    pub target_hosts: Vec<HostKind>,
    pub reports: Vec<InstallReport>,
}

/// Output of `klens uninstall --all`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UninstallReport {
    pub dry_run: bool,
    pub changed: bool,
    pub global_dir: PathBuf,
    pub global_dir_removed: bool,
    pub host_reports: Vec<InstallReport>,
    pub notes: Vec<String>,
}

/// Read-only scan of 1–2 directory levels under `root_dir` for candidate projects.
///
/// Guarantees ZERO filesystem writes.
pub fn scan_directory(
    root_dir: &Path,
    home_dir: &Path,
    max_depth: usize,
) -> Result<ScanReport, AdapterError> {
    if !root_dir.is_dir() {
        return Err(AdapterError::InvalidScanDir(root_dir.to_path_buf()));
    }

    let canonical_root = fs::canonicalize(root_dir).map_err(|source| AdapterError::Io {
        path: root_dir.to_path_buf(),
        source,
    })?;
    let clamped_depth = max_depth.clamp(1, 2);

    let global_cfg = GlobalConfig::load(&global_config_path_in(home_dir)).unwrap_or_default();
    let mut projects = Vec::new();
    scan_recursive(
        &canonical_root,
        0,
        clamped_depth,
        &global_cfg,
        &mut projects,
    );
    projects.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(ScanReport {
        root_dir: PathBuf::from(clean_binary_path_string(&canonical_root)),
        max_depth: clamped_depth,
        projects,
    })
}

fn scan_recursive(
    dir: &Path,
    depth: usize,
    max_depth: usize,
    global_cfg: &GlobalConfig,
    out: &mut Vec<ScannedProject>,
) {
    if depth > 0 {
        let markers: Vec<String> = PROJECT_MARKERS
            .iter()
            .filter(|m| dir.join(m).exists())
            .map(|m| (*m).to_string())
            .collect();

        if !markers.is_empty() {
            let name = dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("project")
                .to_string();
            let has_klens_dir = dir.join(".klens").is_dir();
            let registered_globally = global_cfg
                .registered_projects
                .iter()
                .any(|p| paths_equivalent(&p.path, dir));

            out.push(ScannedProject {
                name,
                path: PathBuf::from(clean_binary_path_string(dir)),
                markers,
                has_klens_dir,
                registered_globally,
            });
            // Don't descend inside an already-identified project when scanning a workspace parent.
            return;
        }
    }

    if depth >= max_depth {
        return;
    }

    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut child_dirs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let file_type = entry.file_type().ok()?;
            if !file_type.is_dir() || file_type.is_symlink() {
                return None;
            }
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if SCAN_SKIP_DIRS.contains(&name_str.as_ref()) {
                return None;
            }
            Some(entry.path())
        })
        .collect();
    child_dirs.sort();

    for child in child_dirs {
        scan_recursive(&child, depth + 1, max_depth, global_cfg, out);
    }
}

/// Idempotently install or update `klens` for the selected host(s).
///
/// Updates moved `.exe` paths cleanly without errors, and writes ZERO bytes under `ctx.dry_run`.
pub fn init_hosts(
    registry: &AdapterRegistry,
    target: HostTarget,
    ctx: &AdapterContext,
) -> Result<InitReport, AdapterError> {
    let selected_hosts = match target {
        HostTarget::Single(kind) => vec![kind],
        HostTarget::All => HostKind::ALL.to_vec(),
        HostTarget::Auto => {
            let mut detected: Vec<HostKind> = HostKind::NATIVE
                .iter()
                .copied()
                .filter(|&kind| {
                    !matches!(
                        registry.adapter(kind).detect(&ctx.project_root),
                        HostDetectStatus::NotDetected
                    )
                })
                .collect();
            if detected.is_empty() {
                detected.push(HostKind::Generic);
            }
            detected
        }
    };

    let mut reports = Vec::with_capacity(selected_hosts.len());
    for &kind in &selected_hosts {
        let rep = registry.adapter(kind).install_or_update(ctx)?;
        reports.push(rep);
    }

    Ok(InitReport {
        dry_run: ctx.dry_run,
        binary_path: ctx.binary_path.clone(),
        selected_hosts,
        reports,
    })
}

/// Attach a project to Karasu Lens:
/// 1. Atomically registers the project in `~/.klens/config.toml` (`GlobalConfig.registered_projects`).
/// 2. Creates/updates `.klens/config.toml`.
/// 3. Upserts the `# klens:start` ... `# klens:end` block in `.gitignore`.
pub fn attach_project(
    home_dir: &Path,
    project_root: &ProjectRoot,
    requested_mode: Option<ProjectMode>,
    dry_run: bool,
) -> Result<AttachReport, AdapterError> {
    let mut files_touched = Vec::new();
    let mut notes = Vec::new();
    let mut mutated = false;
    let prefix = if dry_run { "[dry-run] would " } else { "" };

    let project_name = project_root
        .root()
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("project")
        .to_string();
    let clean_proj_path = clean_binary_path_string(project_root.root());

    // 1. Project `.klens/config.toml`
    let proj_cfg_path = project_root.root().join(".klens").join("config.toml");
    let proj_cfg_existed = proj_cfg_path.exists();
    let mut proj_cfg = ProjectConfig::load_or_default(&proj_cfg_path)?;
    let effective_mode = requested_mode.unwrap_or(proj_cfg.mode);
    let proj_cfg_needs_write = !proj_cfg_existed || proj_cfg.mode != effective_mode;
    if proj_cfg_needs_write {
        proj_cfg.mode = effective_mode;
        files_touched.push(proj_cfg_path.clone());
        if !dry_run {
            proj_cfg.save_atomic(&proj_cfg_path)?;
            mutated = true;
        }
        notes.push(format!(
            "{prefix}write project config {} (mode={:?})",
            clean_binary_path_string(&proj_cfg_path),
            effective_mode
        ));
    }

    // 2. Global `~/.klens/config.toml` (single source of truth — NEVER `projects.json`)
    let global_cfg_path = global_config_path_in(home_dir);
    let global_existed = global_cfg_path.exists();
    let mut global_cfg = GlobalConfig::load_or_default(&global_cfg_path)?;

    let existing_idx = global_cfg
        .registered_projects
        .iter()
        .position(|p| paths_equivalent(&p.path, project_root.root()));
    let desired_entry = RegisteredProject {
        name: project_name.clone(),
        path: clean_proj_path,
        mode: effective_mode,
    };

    let global_needs_write = match existing_idx {
        Some(idx) if global_cfg.registered_projects[idx] == desired_entry && global_existed => {
            false
        }
        Some(idx) => {
            global_cfg.registered_projects[idx] = desired_entry;
            true
        }
        None => {
            global_cfg.registered_projects.push(desired_entry);
            true
        }
    };

    if global_needs_write {
        global_cfg
            .registered_projects
            .sort_by(|a, b| a.path.cmp(&b.path));
        files_touched.push(global_cfg_path.clone());
        if !dry_run {
            global_cfg.save_atomic(&global_cfg_path)?;
            mutated = true;
        }
        notes.push(format!(
            "{prefix}register `{project_name}` in {}",
            clean_binary_path_string(&global_cfg_path)
        ));
    }

    // 3. Managed `# klens:start ... # klens:end` block in `.gitignore`
    let gitignore_path = project_root.root().join(".gitignore");
    let gitignore_out = upsert_marked_file(
        &gitignore_path,
        MarkerStyle::Hash,
        GITIGNORE_BLOCK_BODY,
        dry_run,
        false,
    )?;
    if gitignore_out.is_planned_change() {
        files_touched.push(gitignore_path.clone());
        mutated |= gitignore_out.mutated_disk();
        notes.push(format!(
            "{prefix}update klens ignore block in {}",
            clean_binary_path_string(&gitignore_path)
        ));
    }

    Ok(AttachReport {
        project_root: PathBuf::from(clean_binary_path_string(project_root.root())),
        project_name,
        mode: effective_mode,
        dry_run,
        changed: mutated && !dry_run,
        files_touched,
        notes,
    })
}

/// Surgically detach a single project without touching global host configs or other projects.
///
/// Preserves `.klens/blueprint/` and `.klens/memory/` (and `.klens/config.toml`) unless
/// `purge == true`, in which case `.klens/` is completely removed to leave zero trace.
pub fn detach_project(
    registry: &AdapterRegistry,
    project_root: &ProjectRoot,
    purge: bool,
    dry_run: bool,
) -> Result<DetachReport, AdapterError> {
    let mut files_touched = Vec::new();
    let mut preserved = Vec::new();
    let mut notes = Vec::new();
    let mut mutated = false;
    let prefix = if dry_run { "[dry-run] would " } else { "" };

    let ctx = AdapterContext {
        project_root: project_root.root().to_path_buf(),
        binary_path: PathBuf::new(),
        dry_run,
    };

    // 1. Project-local host artifacts only (never global configs!)
    let claude_rep = registry.claude_code.detach_project(&ctx, false)?;
    let codex_rep = registry.codex.detach_project(&ctx, false)?;
    let generic_rep = registry.generic.detach_project(&ctx, false)?;
    for rep in [claude_rep, codex_rep, generic_rep] {
        files_touched.extend(rep.files_touched);
        mutated |= rep.changed;
        notes.extend(rep.notes);
    }

    // 2. Surgically remove `# klens:start ... # klens:end` from `.gitignore`
    let gitignore_path = project_root.root().join(".gitignore");
    let gitignore_out = remove_marked_file(&gitignore_path, MarkerStyle::Hash, dry_run, false)?;
    if gitignore_out.is_planned_change() {
        files_touched.push(gitignore_path.clone());
        mutated |= gitignore_out.mutated_disk();
        notes.push(format!(
            "{prefix}remove klens ignore block from {}",
            clean_binary_path_string(&gitignore_path)
        ));
    }

    // 2b. Surgically remove any managed `# klens:start ... # klens:end` block from git `pre-commit`
    if let Some((hook_path, hook_mutated, hook_note)) =
        detach_pre_commit_hook_if_present(project_root.root(), dry_run)?
    {
        files_touched.push(hook_path);
        mutated |= hook_mutated;
        notes.push(hook_note);
    }

    // 3. Remove ephemeral `.klens/cache/` and `.klens/runs/`, or purge `.klens/` completely.
    let klens_dir = project_root.root().join(".klens");
    if klens_dir.is_dir() {
        if purge {
            files_touched.push(klens_dir.clone());
            if !dry_run {
                fs::remove_dir_all(&klens_dir).map_err(|source| AdapterError::Io {
                    path: klens_dir.clone(),
                    source,
                })?;
                mutated = true;
            }
            notes.push(format!(
                "{prefix}purge entire directory {}",
                clean_binary_path_string(&klens_dir)
            ));
        } else {
            for ephemeral in ["cache", "runs"] {
                let target = klens_dir.join(ephemeral);
                if target.exists() {
                    files_touched.push(target.clone());
                    if !dry_run {
                        fs::remove_dir_all(&target).map_err(|source| AdapterError::Io {
                            path: target.clone(),
                            source,
                        })?;
                        mutated = true;
                    }
                    notes.push(format!(
                        "{prefix}remove temporary {}",
                        clean_binary_path_string(&target)
                    ));
                }
            }
            for keep in ["blueprint", "memory", "config.toml"] {
                let keep_path = klens_dir.join(keep);
                if keep_path.exists() {
                    preserved.push(keep_path);
                }
            }
            if !preserved.is_empty() {
                notes.push(
                    "preserved user data under `.klens/` (pass `--purge` to delete completely)"
                        .to_string(),
                );
            }
        }
    }

    // 4. When `purge == true`, remove project-local klens backup files (never global backups!)
    //    and prune empty project-local `.claude/` directories bottom-up using `fs::remove_dir`.
    if purge {
        mutated |= purge_project_backups_and_empty_claude_dirs(
            project_root.root(),
            dry_run,
            prefix,
            &mut files_touched,
            &mut notes,
        )?;
    }

    // 5. Unregister project from global `~/.klens/config.toml` (only if file exists)
    let global_cfg_path = global_config_path_in(&registry.home_dir);
    if global_cfg_path.is_file() {
        let mut global_cfg = GlobalConfig::load(&global_cfg_path)?;
        let before = global_cfg.registered_projects.len();
        global_cfg
            .registered_projects
            .retain(|p| !paths_equivalent(&p.path, project_root.root()));
        if global_cfg.registered_projects.len() != before {
            files_touched.push(global_cfg_path.clone());
            if !dry_run {
                global_cfg.save_atomic(&global_cfg_path)?;
                mutated = true;
            }
            notes.push(format!(
                "{prefix}unregister project from {}",
                clean_binary_path_string(&global_cfg_path)
            ));
        }
    }

    Ok(DetachReport {
        project_root: PathBuf::from(clean_binary_path_string(project_root.root())),
        purge,
        dry_run,
        changed: mutated && !dry_run,
        files_touched,
        preserved,
        notes,
    })
}

/// Disconnect one or all AI host adapters, taking timestamped backups before modifying configs.
pub fn disconnect_host(
    registry: &AdapterRegistry,
    target: HostTarget,
    ctx: &AdapterContext,
) -> Result<DisconnectReport, AdapterError> {
    let target_hosts = match target {
        HostTarget::Single(kind) => vec![kind],
        HostTarget::All | HostTarget::Auto => HostKind::ALL.to_vec(),
    };

    let mut reports = Vec::with_capacity(target_hosts.len());
    for &kind in &target_hosts {
        let rep = registry.adapter(kind).uninstall(ctx)?;
        reports.push(rep);
    }

    Ok(DisconnectReport {
        dry_run: ctx.dry_run,
        target_hosts,
        reports,
    })
}

/// Disconnect all AI host adapters and remove `~/.klens/` global directory completely.
///
/// Requires explicit `confirmed_all == true` (`--all` flag).
pub fn uninstall_all(
    registry: &AdapterRegistry,
    ctx: &AdapterContext,
    confirmed_all: bool,
) -> Result<UninstallReport, AdapterError> {
    if !confirmed_all {
        return Err(AdapterError::UninstallRequiresAllFlag);
    }

    let disconnect = disconnect_host(registry, HostTarget::All, ctx)?;
    let mut changed = disconnect.reports.iter().any(|r| r.changed);
    let mut notes = Vec::new();
    let prefix = if ctx.dry_run { "[dry-run] would " } else { "" };

    let global_dir = registry.home_dir.join(".klens");
    let mut global_dir_removed = false;
    if global_dir.exists() {
        if !ctx.dry_run {
            fs::remove_dir_all(&global_dir).map_err(|source| AdapterError::Io {
                path: global_dir.clone(),
                source,
            })?;
            changed = true;
            global_dir_removed = true;
        }
        notes.push(format!(
            "{prefix}remove global directory {}",
            global_dir.display()
        ));
    } else {
        notes.push(format!(
            "global directory {} not present",
            global_dir.display()
        ));
    }

    Ok(UninstallReport {
        dry_run: ctx.dry_run,
        changed: changed && !ctx.dry_run,
        global_dir,
        global_dir_removed,
        host_reports: disconnect.reports,
        notes,
    })
}

/// Resolve the current `klens` executable path cleanly (strips Windows `\\?\` prefix).
pub fn current_binary_path() -> Result<PathBuf, AdapterError> {
    let exe = std::env::current_exe().map_err(KlensError::from)?;
    Ok(PathBuf::from(clean_binary_path_string(&exe)))
}
