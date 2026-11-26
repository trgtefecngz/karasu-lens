//! Opt-in Git `pre-commit` hook management (`klens hook install|uninstall|status`).
//!
//! Leaf module with strictly downward dependencies (`error`, `text_format`, `adapters::common`)
//! so `klens-adapters` stays 100% acyclic.
//!
//! Safety guarantees:
//! - Resolves the active hook path via `git rev-parse --git-path hooks/pre-commit`
//!   (compatible with standard repos, `git worktree`, and custom `core.hooksPath`).
//! - Fail-closed when the target directory is not inside a Git repository.
//! - Uses surgical `# klens:start` ... `# klens:end` markers (`MarkerStyle::Hash`):
//!   NEVER overwrites existing user hooks (Husky, lefthook, custom scripts), preserves
//!   UTF-8 BOM and CRLF/LF line endings, and deletes the hook file on uninstall ONLY
//!   when no user content remains outside a bare `#!/bin/sh` / `#!/usr/bin/env sh` shebang.
//! - Honors `dry_run == true` with zero bytes written or deleted.

use std::fmt::Write as _;
#[cfg(unix)]
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde::{Deserialize, Serialize};

use crate::adapters::common::{clean_binary_path_string, paths_equivalent};
use crate::error::AdapterError;
use crate::text_format::{
    MarkerStyle, TextFormat, apply_file_delete, apply_file_write, has_marked_block, read_text_file,
    remove_marked_block, upsert_marked_block,
};

/// Read-only status of the optional Karasu Lens `pre-commit` Git hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHookStatusReport {
    pub project_root: PathBuf,
    pub is_git_repo: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook_path: Option<PathBuf>,
    pub installed: bool,
    pub has_other_user_hooks: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configured_binary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_matches_current: Option<bool>,
}

/// Output of installing or updating the Karasu Lens `pre-commit` Git hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHookInstallReport {
    pub project_root: PathBuf,
    pub hook_path: PathBuf,
    pub binary_path: PathBuf,
    pub fail_on_warning: bool,
    pub dry_run: bool,
    pub changed: bool,
    pub created_new_file: bool,
    pub preserved_existing_hook: bool,
    pub notes: Vec<String>,
}

/// Output of surgically uninstalling the Karasu Lens `pre-commit` Git hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHookUninstallReport {
    pub project_root: PathBuf,
    pub hook_path: PathBuf,
    pub dry_run: bool,
    pub changed: bool,
    pub removed_file: bool,
    pub preserved_user_hook: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_path: Option<PathBuf>,
    pub notes: Vec<String>,
}

/// Inspect the `pre-commit` Git hook status in strictly read-only mode (writes zero bytes).
pub fn pre_commit_hook_status(project_root: &Path, current_binary: &Path) -> GitHookStatusReport {
    let clean_root = PathBuf::from(clean_binary_path_string(project_root));
    let Ok(hook_path) = resolve_pre_commit_hook_path(project_root) else {
        return GitHookStatusReport {
            project_root: clean_root,
            is_git_repo: false,
            hook_path: None,
            installed: false,
            has_other_user_hooks: false,
            configured_binary: None,
            binary_matches_current: None,
        };
    };

    let clean_hook = PathBuf::from(clean_binary_path_string(&hook_path));
    let Ok(Some((_, existing_lf, _))) = read_text_file(&hook_path) else {
        return GitHookStatusReport {
            project_root: clean_root,
            is_git_repo: true,
            hook_path: Some(clean_hook),
            installed: false,
            has_other_user_hooks: false,
            configured_binary: None,
            binary_matches_current: None,
        };
    };

    let installed = has_marked_block(&hook_path, &existing_lf, MarkerStyle::Hash);
    let has_other_user_hooks =
        has_user_content_outside_klens_block(&hook_path, &existing_lf).unwrap_or(true);
    let configured_binary = if installed {
        extract_configured_binary(&existing_lf)
    } else {
        None
    };
    let binary_matches_current = configured_binary
        .as_deref()
        .map(|cfg| paths_equivalent(cfg, current_binary));

    GitHookStatusReport {
        project_root: clean_root,
        is_git_repo: true,
        hook_path: Some(clean_hook),
        installed,
        has_other_user_hooks,
        configured_binary,
        binary_matches_current,
    }
}

/// Idempotently install or update the managed `# klens:start ... # klens:end` block inside
/// the repository's `pre-commit` hook.
///
/// Honors `dry_run == true` with zero bytes written to disk.
pub fn install_pre_commit_hook(
    project_root: &Path,
    binary_path: &Path,
    fail_on_warning: bool,
    dry_run: bool,
) -> Result<GitHookInstallReport, AdapterError> {
    let hook_path = resolve_pre_commit_hook_path(project_root)?;
    let existing = read_text_file(&hook_path)?;
    let (fmt, existing_lf) = match existing {
        Some((fmt, lf, _)) => (fmt, Some(lf)),
        None => (TextFormat::default(), None),
    };

    let body = render_hook_block_body(binary_path, fail_on_warning);
    let (updated_lf, created_new_file, preserved_existing_hook) = match existing_lf {
        None => (render_fresh_hook_script(&body), true, false),
        Some(ref content) if content.trim().is_empty() => {
            (render_fresh_hook_script(&body), false, false)
        }
        Some(ref content) => {
            let has_other = has_user_content_outside_klens_block(&hook_path, content)?;
            let updated = upsert_marked_block(&hook_path, Some(content), MarkerStyle::Hash, &body)?;
            (updated, false, has_other)
        }
    };

    let encoded = fmt.encode(&updated_lf);
    let outcome = apply_file_write(&hook_path, &encoded, dry_run, false)?;
    if outcome.mutated_disk() {
        ensure_hook_executable(&hook_path)?;
    }

    let prefix = if dry_run { "[dry-run] would " } else { "" };
    let clean_hook = clean_binary_path_string(&hook_path);
    let severity_label = if fail_on_warning { "warning" } else { "error" };
    let mut notes = Vec::new();
    if outcome.is_planned_change() {
        if created_new_file {
            notes.push(format!(
                "{prefix}create pre-commit hook at {clean_hook} (fail-on={severity_label})"
            ));
        } else if preserved_existing_hook {
            notes.push(format!(
                "{prefix}update klens block in {clean_hook} while preserving existing user hook (fail-on={severity_label})"
            ));
        } else {
            notes.push(format!(
                "{prefix}update klens pre-commit hook at {clean_hook} (fail-on={severity_label})"
            ));
        }
    } else {
        notes.push(format!(
            "pre-commit hook at {clean_hook} is already up-to-date"
        ));
    }

    Ok(GitHookInstallReport {
        project_root: PathBuf::from(clean_binary_path_string(project_root)),
        hook_path: PathBuf::from(clean_hook),
        binary_path: PathBuf::from(clean_binary_path_string(binary_path)),
        fail_on_warning,
        dry_run,
        changed: outcome.mutated_disk(),
        created_new_file,
        preserved_existing_hook,
        notes,
    })
}

/// Surgically remove only the `# klens:start ... # klens:end` block from `pre-commit`.
///
/// Deletes the hook file only when nothing remains outside whitespace or a bare
/// `#!/bin/sh` / `#!/usr/bin/env sh` shebang. Preserves all user hook lines intact.
pub fn uninstall_pre_commit_hook(
    project_root: &Path,
    dry_run: bool,
    backup_existing: bool,
) -> Result<GitHookUninstallReport, AdapterError> {
    let hook_path = resolve_pre_commit_hook_path(project_root)?;
    let clean_root = PathBuf::from(clean_binary_path_string(project_root));
    let clean_hook = clean_binary_path_string(&hook_path);
    let prefix = if dry_run { "[dry-run] would " } else { "" };

    let Some((fmt, existing_lf, _)) = read_text_file(&hook_path)? else {
        return Ok(GitHookUninstallReport {
            project_root: clean_root,
            hook_path: PathBuf::from(clean_hook),
            dry_run,
            changed: false,
            removed_file: false,
            preserved_user_hook: false,
            backup_path: None,
            notes: vec!["no pre-commit hook file found".to_string()],
        });
    };

    let Some(remaining_lf) = remove_marked_block(&hook_path, &existing_lf, MarkerStyle::Hash)?
    else {
        return Ok(GitHookUninstallReport {
            project_root: clean_root,
            hook_path: PathBuf::from(clean_hook),
            dry_run,
            changed: false,
            removed_file: false,
            preserved_user_hook: !is_only_shebang_or_empty(&existing_lf),
            backup_path: None,
            notes: vec!["pre-commit hook contains no klens block; left untouched".to_string()],
        });
    };

    if is_only_shebang_or_empty(&remaining_lf) {
        let outcome = apply_file_delete(&hook_path, dry_run, backup_existing)?;
        let note = format!("{prefix}remove klens-only pre-commit hook file {clean_hook}");
        return Ok(GitHookUninstallReport {
            project_root: clean_root,
            hook_path: PathBuf::from(clean_hook),
            dry_run,
            changed: outcome.mutated_disk(),
            removed_file: outcome.mutated_disk(),
            preserved_user_hook: false,
            backup_path: outcome.backup_path().map(Path::to_path_buf),
            notes: vec![note],
        });
    }

    #[cfg(unix)]
    let orig_perms = fs::metadata(&hook_path).ok().map(|m| m.permissions());

    let encoded = fmt.encode(&remaining_lf);
    let outcome = apply_file_write(&hook_path, &encoded, dry_run, backup_existing)?;

    #[cfg(unix)]
    if outcome.mutated_disk()
        && let Some(perms) = orig_perms
    {
        fs::set_permissions(&hook_path, perms).map_err(|source| AdapterError::Io {
            path: hook_path.clone(),
            source,
        })?;
    }

    let note =
        format!("{prefix}remove klens block from {clean_hook} while preserving existing user hook");
    Ok(GitHookUninstallReport {
        project_root: clean_root,
        hook_path: PathBuf::from(clean_hook),
        dry_run,
        changed: outcome.mutated_disk(),
        removed_file: false,
        preserved_user_hook: true,
        backup_path: outcome.backup_path().map(Path::to_path_buf),
        notes: vec![note],
    })
}

/// Internal helper for `lifecycle::detach_project`: surgically removes any klens block in
/// `pre-commit` when `project_root` is a Git repo, silently skipping non-git projects.
pub(crate) fn detach_pre_commit_hook_if_present(
    project_root: &Path,
    dry_run: bool,
) -> Result<Option<(PathBuf, bool, String)>, AdapterError> {
    let hook_path = match resolve_pre_commit_hook_path(project_root) {
        Ok(path) => path,
        Err(AdapterError::NotAGitRepo(_)) => return Ok(None),
        Err(err) => return Err(err),
    };

    let Some((_, existing_lf, _)) = read_text_file(&hook_path)? else {
        return Ok(None);
    };
    if remove_marked_block(&hook_path, &existing_lf, MarkerStyle::Hash)?.is_none() {
        return Ok(None);
    }

    let report = uninstall_pre_commit_hook(project_root, dry_run, false)?;
    let note = report.notes.into_iter().next().unwrap_or_else(|| {
        format!(
            "{}remove klens pre-commit hook from {}",
            if dry_run { "[dry-run] would " } else { "" },
            clean_binary_path_string(&hook_path)
        )
    });
    Ok(Some((hook_path, report.changed, note)))
}

/// Render human-readable text output for `klens hook status`.
pub fn format_hook_status_text(report: &GitHookStatusReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Karasu Lens — Git Pre-Commit Hook Status (read-only)");
    let _ = writeln!(
        out,
        "Project  : {}",
        clean_binary_path_string(&report.project_root)
    );
    if !report.is_git_repo {
        let _ = writeln!(out, "Git Repo : no (not a git repository)");
        return out.trim_end().to_string();
    }
    if let Some(ref path) = report.hook_path {
        let _ = writeln!(out, "Hook Path: {}", clean_binary_path_string(path));
    }
    let state = if report.installed {
        "installed"
    } else {
        "not installed"
    };
    let _ = writeln!(out, "Status   : {state}");
    let _ = writeln!(
        out,
        "Other Hooks: {}",
        if report.has_other_user_hooks {
            "yes (preserved)"
        } else {
            "none"
        }
    );
    if let Some(ref bin) = report.configured_binary {
        let freshness = match report.binary_matches_current {
            Some(true) => " [binary: OK]",
            Some(false) => " [binary: STALE]",
            None => "",
        };
        let _ = writeln!(out, "Binary   : {bin}{freshness}");
    }
    out.trim_end().to_string()
}

/// Render human-readable text output for `klens hook install`.
pub fn format_hook_install_text(report: &GitHookInstallReport) -> String {
    let mut out = String::new();
    let mode = if report.dry_run { " [DRY-RUN]" } else { "" };
    let _ = writeln!(out, "Karasu Lens — Git Pre-Commit Hook Install{mode}");
    let _ = writeln!(
        out,
        "Hook Path: {}",
        clean_binary_path_string(&report.hook_path)
    );
    let _ = writeln!(
        out,
        "Binary   : {}",
        clean_binary_path_string(&report.binary_path)
    );
    let _ = writeln!(
        out,
        "Severity : fail-on {}",
        if report.fail_on_warning {
            "warning"
        } else {
            "error"
        }
    );
    let _ = writeln!(out, "Changed  : {}", report.changed);
    for note in &report.notes {
        let _ = writeln!(out, "  - {note}");
    }
    out.trim_end().to_string()
}

/// Render human-readable text output for `klens hook uninstall`.
pub fn format_hook_uninstall_text(report: &GitHookUninstallReport) -> String {
    let mut out = String::new();
    let mode = if report.dry_run { " [DRY-RUN]" } else { "" };
    let _ = writeln!(out, "Karasu Lens — Git Pre-Commit Hook Uninstall{mode}");
    let _ = writeln!(
        out,
        "Hook Path: {}",
        clean_binary_path_string(&report.hook_path)
    );
    let _ = writeln!(out, "Changed  : {}", report.changed);
    if report.removed_file {
        let _ = writeln!(out, "Action   : removed klens-only hook file");
    } else if report.preserved_user_hook {
        let _ = writeln!(out, "Action   : preserved existing user hook lines");
    }
    if let Some(ref bak) = report.backup_path {
        let _ = writeln!(out, "Backup   : {}", clean_binary_path_string(bak));
    }
    for note in &report.notes {
        let _ = writeln!(out, "  - {note}");
    }
    out.trim_end().to_string()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

struct GitQueryOutput {
    success: bool,
    stdout: String,
}

fn run_git_query(project_root: &Path, args: &[&str]) -> Option<GitQueryOutput> {
    let mut cmd = klens_core::git_command(project_root);
    cmd.args(args).stdin(Stdio::null()).stderr(Stdio::null());

    let output = cmd.output().ok()?;
    Some(GitQueryOutput {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
    })
}

fn resolve_pre_commit_hook_path(project_root: &Path) -> Result<PathBuf, AdapterError> {
    let in_repo = run_git_query(project_root, &["rev-parse", "--is-inside-work-tree"])
        .is_some_and(|out| out.success && out.stdout.trim() == "true");
    if !in_repo {
        return Err(AdapterError::NotAGitRepo(project_root.to_path_buf()));
    }

    // klens's git commands override `core.hooksPath` (so repository hooks never run), which
    // means `--git-path hooks/...` cannot be used here. The setting is read as plain data
    // instead; reading configuration never runs a program.
    if let Some(hooks_dir) = configured_hooks_dir(project_root)? {
        return Ok(hooks_dir.join("pre-commit"));
    }
    let common_dir = git_query_line(project_root, &["rev-parse", "--git-common-dir"])?;
    Ok(absolute_from(project_root, &common_dir)
        .join("hooks")
        .join("pre-commit"))
}

/// `core.hooksPath`, resolved against the work tree top level. A value set in the
/// repository's own configuration must stay inside the repository: that file can come with
/// the folder, and klens must not be steered into writing a hook file anywhere else.
fn configured_hooks_dir(project_root: &Path) -> Result<Option<PathBuf>, AdapterError> {
    let Some(out) = run_git_query(
        project_root,
        &["config", "--show-scope", "--get-all", "core.hooksPath"],
    ) else {
        return Ok(None);
    };
    // The last value wins, ignoring klens's own command-line override (scope `command`).
    let Some((scope, value)) = out
        .stdout
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .rfind(|(scope, _)| *scope != "command")
    else {
        return Ok(None);
    };
    if !out.success || value.trim().is_empty() {
        return Ok(None);
    }

    let top = absolute_from(
        project_root,
        &git_query_line(project_root, &["rev-parse", "--show-toplevel"])?,
    );
    let raw = value.trim();
    let dir = match raw.strip_prefix("~/") {
        Some(rest) => std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map_or_else(|| PathBuf::from(raw), |home| PathBuf::from(home).join(rest)),
        None => absolute_from(&top, raw),
    };
    let dir = lexically_normalized(&dir);

    if matches!(scope, "local" | "worktree") && !dir.starts_with(lexically_normalized(&top)) {
        return Err(AdapterError::UntrustedHooksPath { path: dir });
    }
    Ok(Some(dir))
}

fn git_query_line(project_root: &Path, args: &[&str]) -> Result<String, AdapterError> {
    run_git_query(project_root, args)
        .filter(|out| out.success)
        .map(|out| out.stdout.trim().to_string())
        .filter(|line| !line.is_empty())
        .ok_or_else(|| AdapterError::NotAGitRepo(project_root.to_path_buf()))
}

fn absolute_from(base: &Path, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

/// Resolve `.` and `..` without touching the filesystem.
fn lexically_normalized(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn format_shell_binary_path(binary_path: &Path) -> String {
    clean_binary_path_string(binary_path).replace('\\', "/")
}

fn sh_single_quote(raw: &str) -> String {
    let escaped = raw.replace('\'', "'\\''");
    format!("'{escaped}'")
}

fn render_hook_block_body(binary_path: &Path, fail_on_warning: bool) -> String {
    let bin_posix = format_shell_binary_path(binary_path);
    let quoted_bin = sh_single_quote(&bin_posix);
    let severity = if fail_on_warning { "warning" } else { "error" };
    format!(
        "# Karasu Lens (klens) pre-commit guard — managed block (`klens hook uninstall` to remove)\n\
         {quoted_bin} diff-check --staged --read-only --fail-on {severity} || exit $?"
    )
}

fn render_fresh_hook_script(body: &str) -> String {
    format!(
        "#!/bin/sh\n{}\n{}\n{}\n",
        MarkerStyle::Hash.start_marker(),
        body.trim_matches('\n'),
        MarkerStyle::Hash.end_marker()
    )
}

fn is_only_shebang_or_empty(normalized_lf: &str) -> bool {
    let non_empty: Vec<&str> = normalized_lf
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    match non_empty.as_slice() {
        [] => true,
        [only] => *only == "#!/bin/sh" || *only == "#!/usr/bin/env sh",
        _ => false,
    }
}

fn has_user_content_outside_klens_block(
    path: &Path,
    normalized_lf: &str,
) -> Result<bool, AdapterError> {
    let outside = match remove_marked_block(path, normalized_lf, MarkerStyle::Hash)? {
        Some(rem) => rem,
        None => normalized_lf.to_string(),
    };
    Ok(!is_only_shebang_or_empty(&outside))
}

fn extract_configured_binary(normalized_lf: &str) -> Option<String> {
    let mut in_block = false;
    for line in normalized_lf.lines() {
        let trimmed = line.trim();
        if trimmed == MarkerStyle::Hash.start_marker() {
            in_block = true;
            continue;
        }
        if trimmed == MarkerStyle::Hash.end_marker() {
            break;
        }
        if !in_block || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((prefix, _)) = trimmed.split_once(" diff-check --staged") {
            let raw_cmd = prefix.trim();
            if let Some(inner) = raw_cmd
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
            {
                return Some(inner.replace("'\\''", "'"));
            }
            if !raw_cmd.is_empty() {
                return Some(raw_cmd.to_string());
            }
        }
    }
    None
}

#[cfg(unix)]
fn ensure_hook_executable(path: &Path) -> Result<(), AdapterError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o755);
    fs::set_permissions(path, perms).map_err(|source| AdapterError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn ensure_hook_executable(_path: &Path) -> Result<(), AdapterError> {
    Ok(())
}
