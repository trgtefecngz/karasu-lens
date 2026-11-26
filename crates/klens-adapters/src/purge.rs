//! Project-local managed backup pruning and empty `.claude/` cleanup for `klens detach --purge`.
//!
//! Strict leaf module: depends only on `adapters` and `error` (never `lifecycle`) to keep
//! the crate module graph acyclic.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::adapters::claude_code::claude_settings_deleted_on_detach;
use crate::adapters::clean_binary_path_string;
use crate::error::AdapterError;

const PROJECT_ROOT_BACKUP_PREFIXES: &[&str] = &[".mcp.json", "CLAUDE.md", "AGENTS.md", "KLENS.md"];
const CLAUDE_DIR_BACKUP_PREFIXES: &[&str] = &["settings.json"];

fn is_managed_backup_name(name: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| {
        name.strip_prefix(prefix)
            .and_then(|rest| rest.strip_prefix(".klens-backup-"))
            .and_then(|rest| rest.strip_suffix(".bak"))
            .is_some_and(|stamp| !stamp.is_empty())
    })
}

fn collect_managed_backups(dir: &Path, prefixes: &[&str]) -> Result<Vec<PathBuf>, AdapterError> {
    let Ok(meta) = fs::symlink_metadata(dir) else {
        return Ok(Vec::new());
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Ok(Vec::new());
    }

    let mut backups = Vec::new();
    for entry in fs::read_dir(dir).map_err(|source| AdapterError::Io {
        path: dir.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| AdapterError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let file_type = entry.file_type().map_err(|source| AdapterError::Io {
            path: entry.path(),
            source,
        })?;
        // Fail-closed: delete ONLY regular files, never symlinks or directories.
        if file_type.is_symlink() || !file_type.is_file() {
            continue;
        }
        let file_name = entry.file_name();
        let Some(name_str) = file_name.to_str() else {
            continue;
        };
        if is_managed_backup_name(name_str, prefixes) {
            backups.push(entry.path());
        }
    }
    backups.sort();
    Ok(backups)
}

fn dir_would_be_empty_after_removals(
    dir: &Path,
    planned_removed: &BTreeSet<PathBuf>,
) -> Result<bool, AdapterError> {
    let Ok(meta) = fs::symlink_metadata(dir) else {
        return Ok(false);
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Ok(false);
    }
    for entry in fs::read_dir(dir).map_err(|source| AdapterError::Io {
        path: dir.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| AdapterError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let ft = entry.file_type().map_err(|source| AdapterError::Io {
            path: path.clone(),
            source,
        })?;
        if ft.is_symlink() {
            return Ok(false);
        }
        if ft.is_file() {
            if !planned_removed.contains(&path) {
                return Ok(false);
            }
        } else if ft.is_dir() {
            if !planned_removed.contains(&path)
                && !dir_would_be_empty_after_removals(&path, planned_removed)?
            {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn purge_project_backups_and_empty_claude_dirs(
    project_root: &Path,
    dry_run: bool,
    prefix: &str,
    files_touched: &mut Vec<PathBuf>,
    notes: &mut Vec<String>,
) -> Result<bool, AdapterError> {
    let mut mutated = false;

    let claude_dir = project_root.join(".claude");
    let karasu_skills_dir = claude_dir.join("skills").join("karasu-lens");
    let mut backups = collect_managed_backups(project_root, PROJECT_ROOT_BACKUP_PREFIXES)?;
    backups.extend(collect_managed_backups(
        &claude_dir,
        CLAUDE_DIR_BACKUP_PREFIXES,
    )?);
    backups.sort();

    let mut planned_removed: BTreeSet<PathBuf> = BTreeSet::new();
    if dry_run {
        let settings_path = claude_dir.join("settings.json");
        if claude_settings_deleted_on_detach(&settings_path) {
            planned_removed.insert(settings_path);
        }
        for path in files_touched.iter() {
            if path.starts_with(&karasu_skills_dir) {
                planned_removed.insert(path.clone());
            }
        }
    }

    for bak in backups {
        files_touched.push(bak.clone());
        if !dry_run {
            fs::remove_file(&bak).map_err(|source| AdapterError::Io {
                path: bak.clone(),
                source,
            })?;
            mutated = true;
        }
        notes.push(format!(
            "{prefix}remove managed backup {}",
            clean_binary_path_string(&bak)
        ));
        planned_removed.insert(bak);
    }

    // Bottom-up check of project-local `.claude/` hierarchy; only `fs::remove_dir` if empty.
    let claude_candidates = [karasu_skills_dir, claude_dir.join("skills"), claude_dir];
    let mut removed_dirs = Vec::new();
    for dir in claude_candidates {
        let Ok(meta) = fs::symlink_metadata(&dir) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            continue;
        }
        let can_remove = if dry_run {
            dir_would_be_empty_after_removals(&dir, &planned_removed)?
        } else {
            fs::read_dir(&dir)
                .map_err(|source| AdapterError::Io {
                    path: dir.clone(),
                    source,
                })?
                .next()
                .is_none()
        };
        if can_remove {
            if !dry_run {
                fs::remove_dir(&dir).map_err(|source| AdapterError::Io {
                    path: dir.clone(),
                    source,
                })?;
                mutated = true;
            }
            planned_removed.insert(dir.clone());
            removed_dirs.push(dir);
        }
    }

    removed_dirs.sort();
    for dir in removed_dirs {
        files_touched.push(dir.clone());
        notes.push(format!(
            "{prefix}remove empty directory {}",
            clean_binary_path_string(&dir)
        ));
    }

    Ok(mutated)
}
