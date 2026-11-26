//! Git-based safe checkpoints (`klens checkpoint`, `klens checkpoints`, `klens rollback`).
//!
//! Stores snapshots under `refs/klens/checkpoints/<id>` using pure Git plumbing with an
//! isolated temporary index file (`GIT_INDEX_FILE`), so:
//! - `HEAD`, active branch history, `git log`, `git stash list`, and staged files are NEVER polluted.
//! - Zero extra external crates are needed.
//! - Every `git` invocation runs with `CREATE_NO_WINDOW` (`0x08000000`) on Windows.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};

use klens_core::{ProjectRoot, ProvenanceEnvelope, TrustLevel};
use serde::{Deserialize, Serialize};

use crate::error::ExecError;
use klens_core::time::generate_sortable_id;

const CHECKPOINT_REF_PREFIX: &str = "refs/klens/checkpoints/";
static TMP_INDEX_SEQ: AtomicU64 = AtomicU64::new(0);

/// Metadata for a single Git checkpoint snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointInfo {
    pub id: String,
    pub commit_oid: String,
    pub timestamp_utc: String,
    pub note: String,
    pub branch: String,
    pub base_head: Option<String>,
}

/// Result of `klens rollback <id> [--dry-run]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackReport {
    pub checkpoint_id: String,
    pub checkpoint_note: String,
    pub dry_run: bool,
    pub applied: bool,
    pub files_to_restore: Vec<String>,
    pub files_to_modify: Vec<String>,
    pub files_to_delete: Vec<String>,
    /// Automatic checkpoint of the working tree saved right before an applied rollback
    /// changed any file (v0.3.3+). Rolling back to it undoes the rollback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safety_checkpoint_id: Option<String>,
}

impl RollbackReport {
    /// Total number of file operations planned or applied.
    pub fn total_changes(&self) -> usize {
        self.files_to_restore.len() + self.files_to_modify.len() + self.files_to_delete.len()
    }
}

/// RAII cleanup guard for an isolated temporary `GIT_INDEX_FILE`.
struct TempGitIndex {
    path: PathBuf,
}

impl TempGitIndex {
    fn allocate(git_dir: &Path) -> Self {
        let seq = TMP_INDEX_SEQ.fetch_add(1, Ordering::Relaxed);
        let name = format!("klens-tmp-index-{}-{seq}", std::process::id());
        let path = git_dir.join(name);
        // Ensure the path does not pre-exist (Git rejects an empty 0-byte index file).
        if path.exists() {
            let _ = fs::remove_file(&path);
        }
        Self { path }
    }

    fn git_env_path(&self) -> String {
        let raw = self.path.to_string_lossy();
        #[cfg(windows)]
        {
            if let Some(unc) = raw.strip_prefix(r"\\?\UNC\") {
                return format!(r"\\{unc}");
            }
            if let Some(stripped) = raw.strip_prefix(r"\\?\") {
                return stripped.to_string();
            }
        }
        raw.into_owned()
    }
}

impl Drop for TempGitIndex {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Create a safe Git snapshot under `refs/klens/checkpoints/<id>` without modifying
/// `HEAD`, the active branch, `git stash list`, or the user's real `.git/index`.
pub fn create_checkpoint(
    project_root: &ProjectRoot,
    note: Option<&str>,
) -> Result<ProvenanceEnvelope<CheckpointInfo>, ExecError> {
    let root = project_root.root();
    ensure_git_repo(root)?;

    let git_dir = resolve_git_dir(root)?;
    let tree_oid = snapshot_worktree_to_tree(root, &git_dir)?;
    let info = write_checkpoint_commit(root, &tree_oid, note)?;

    Ok(ProvenanceEnvelope::new(
        TrustLevel::VerifiedRaw,
        project_root.project_id(),
        info,
    ))
}

/// Commit an already-snapshotted worktree `tree_oid` under `refs/klens/checkpoints/<id>`
/// without touching `HEAD`, the active branch, or the real index.
fn write_checkpoint_commit(
    root: &Path,
    tree_oid: &str,
    note: Option<&str>,
) -> Result<CheckpointInfo, ExecError> {
    let clean_note = note
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("checkpoint")
        .replace(['\r', '\n'], " ");

    let (id, timestamp_utc) = generate_sortable_id(&clean_note);
    let head_full = git_stdout_optional(root, &["rev-parse", "--verify", "--quiet", "HEAD"]);
    let base_head = head_full
        .as_deref()
        .map(|h| h[..h.len().min(7)].to_string());
    let branch =
        git_stdout_optional(root, &["symbolic-ref", "--short", "HEAD"]).unwrap_or_else(|| {
            if head_full.is_some() {
                "DETACHED"
            } else {
                "UNBORN"
            }
            .to_string()
        });

    let message = format!(
        "{clean_note}\n\nklens-checkpoint-id: {id}\nklens-timestamp-utc: {timestamp_utc}\nklens-branch: {branch}\nklens-base-head: {}\n",
        base_head.as_deref().unwrap_or("none")
    );

    let mut commit_args: Vec<&str> = vec!["commit-tree", tree_oid];
    if let Some(ref parent) = head_full {
        commit_args.push("-p");
        commit_args.push(parent);
    }
    commit_args.push("-m");
    commit_args.push(&message);

    // Ensure commit-tree works even in fresh repositories without user.name/user.email.
    let extra_env = ensure_commit_identity_env(root);
    let commit_oid = git_stdout_with_env(root, &commit_args, &extra_env)?;
    let short_oid = commit_oid[..commit_oid.len().min(7)].to_string();

    let full_ref = format!("{CHECKPOINT_REF_PREFIX}{id}");
    git_stdout(root, &["update-ref", &full_ref, &commit_oid])?;

    Ok(CheckpointInfo {
        id,
        commit_oid: short_oid,
        timestamp_utc,
        note: clean_note,
        branch,
        base_head,
    })
}

/// List all checkpoints stored under `refs/klens/checkpoints/*`, sorted newest-first.
pub fn list_checkpoints(
    project_root: &ProjectRoot,
) -> Result<ProvenanceEnvelope<Vec<CheckpointInfo>>, ExecError> {
    let root = project_root.root();
    ensure_git_repo(root)?;

    let checkpoints = read_all_checkpoints(root)?;
    Ok(ProvenanceEnvelope::new(
        TrustLevel::VerifiedRaw,
        project_root.project_id(),
        checkpoints,
    ))
}

/// Preview (`dry_run = true`) or execute (`dry_run = false`) a safe rollback of the working tree
/// to a previously captured checkpoint without touching `HEAD` or branch history.
pub fn rollback_checkpoint(
    project_root: &ProjectRoot,
    id_or_prefix: &str,
    dry_run: bool,
) -> Result<ProvenanceEnvelope<RollbackReport>, ExecError> {
    validate_checkpoint_id(id_or_prefix)?;
    let root = project_root.root();
    ensure_git_repo(root)?;

    let all = read_all_checkpoints(root)?;
    let target = resolve_checkpoint(&all, id_or_prefix)?;

    let git_dir = resolve_git_dir(root)?;
    let current_tree = snapshot_worktree_to_tree(root, &git_dir)?;

    let target_ref = format!("{CHECKPOINT_REF_PREFIX}{}", target.id);
    let target_tree_spec = format!("{target_ref}^{{tree}}");
    let target_tree = git_stdout(root, &["rev-parse", &target_tree_spec])?;

    // `-z`: paths are emitted verbatim (never C-quoted), so names containing `"`, `\`, tabs or
    // newlines are handled exactly (v0.3.3+).
    // `--relative`: when the project is a sub-folder of a larger repository, only changes inside
    // it are listed, with paths relative to it — the same base `checkout-index`, deletion and
    // `rm --cached` below use. Files elsewhere in the repository are never touched.
    let diff_out = git_stdout(
        root,
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--relative",
            "-z",
            "--name-status",
            "--no-renames",
            &current_tree,
            &target_tree,
        ],
    )?;

    let mut files_to_restore = Vec::new();
    let mut files_to_modify = Vec::new();
    let mut files_to_delete = Vec::new();

    let mut fields = diff_out.split('\0').filter(|f| !f.is_empty());
    while let (Some(status), Some(path)) = (fields.next(), fields.next()) {
        // Credential files are never restored or deleted (older checkpoints may contain them).
        if !is_safe_git_relative_path(path)
            || is_protected_klens_runtime_path(path)
            || klens_core::sensitive::is_builtin_sensitive(path)
        {
            continue;
        }
        let path = path.to_string();
        match status.chars().next() {
            Some('A') => files_to_restore.push(path),
            Some('D') => files_to_delete.push(path),
            Some(_) => files_to_modify.push(path),
            None => {}
        }
    }

    files_to_restore.sort();
    files_to_modify.sort();
    files_to_delete.sort();

    let has_changes =
        !files_to_restore.is_empty() || !files_to_modify.is_empty() || !files_to_delete.is_empty();

    let mut safety_checkpoint_id = None;
    if !dry_run && has_changes {
        // 0. Safety net (v0.3.3+): save the CURRENT working tree (incl. uncommitted edits and
        //    new untracked files) before touching anything. Fail closed if it cannot be saved.
        let note = format!("auto-backup before rollback to {}", target.id);
        let safety = write_checkpoint_commit(root, &current_tree, Some(&note))?;
        safety_checkpoint_id = Some(safety.id);

        // 1. Restore ONLY changed/deleted files from the target tree first, via an isolated temp
        //    index (`checkout-index -f -- <paths>`), so unchanged files keep their `mtime` and
        //    `HEAD` / the real `.git/index` stay untouched. If this fails, nothing was deleted yet.
        const GIT_PATH_CHUNK_SIZE: usize = 64;
        let paths_to_checkout: Vec<&str> = files_to_restore
            .iter()
            .chain(files_to_modify.iter())
            .map(String::as_str)
            .collect();

        if !paths_to_checkout.is_empty() {
            let tmp_idx = TempGitIndex::allocate(&git_dir);
            let idx_env = vec![("GIT_INDEX_FILE".to_string(), tmp_idx.git_env_path())];
            git_stdout_with_env(root, &["read-tree", &target_tree], &idx_env)?;
            for chunk in paths_to_checkout.chunks(GIT_PATH_CHUNK_SIZE) {
                let mut checkout_args: Vec<&str> = Vec::with_capacity(chunk.len() + 3);
                checkout_args.extend(["checkout-index", "-f", "--"]);
                checkout_args.extend_from_slice(chunk);
                git_stdout_with_env(root, &checkout_args, &idx_env)?;
            }
        }

        // 2. Delete files added after the checkpoint (confined: the parent directory must
        //    canonicalize inside the project root, so symlinked folders cannot redirect it).
        for rel in &files_to_delete {
            if let Some(target_abs) = confined_delete_target(root, rel) {
                fs::remove_file(&target_abs).map_err(|source| ExecError::Io {
                    path: target_abs.clone(),
                    source,
                })?;
                prune_empty_parents(target_abs.parent(), root);
            }
        }

        // Remove deleted files from the real git index if they had been staged after the checkpoint.
        for chunk in files_to_delete.chunks(GIT_PATH_CHUNK_SIZE) {
            let mut rm_args: Vec<&str> = Vec::with_capacity(chunk.len() + 4);
            rm_args.extend(["rm", "--cached", "--ignore-unmatch", "--"]);
            rm_args.extend(chunk.iter().map(String::as_str));
            let _ = git_stdout(root, &rm_args);
        }
    }

    let report = RollbackReport {
        checkpoint_id: target.id,
        checkpoint_note: target.note,
        dry_run,
        applied: !dry_run,
        files_to_restore,
        files_to_modify,
        files_to_delete,
        safety_checkpoint_id,
    };

    Ok(ProvenanceEnvelope::new(
        TrustLevel::VerifiedRaw,
        project_root.project_id(),
        report,
    ))
}

/// Plain-text formatter for `klens checkpoint`.
pub fn format_checkpoint_created_text(env: &ProvenanceEnvelope<CheckpointInfo>) -> String {
    let cp = &env.data;
    format!(
        "[klens checkpoint] saved id={} commit={} branch={} time={} note=\"{}\"",
        cp.id, cp.commit_oid, cp.branch, cp.timestamp_utc, cp.note
    )
}

/// Plain-text formatter for `klens checkpoints`.
pub fn format_checkpoints_list_text(env: &ProvenanceEnvelope<Vec<CheckpointInfo>>) -> String {
    if env.data.is_empty() {
        return "[klens checkpoints] none saved yet (create one with `klens checkpoint \"note\"`)"
            .to_string();
    }
    let mut lines = vec![format!("[klens checkpoints] {} saved:", env.data.len())];
    for cp in &env.data {
        lines.push(format!(
            "  {}  {}  [{}]  {}",
            cp.id, cp.timestamp_utc, cp.branch, cp.note
        ));
    }
    lines.join("\n")
}

/// Plain-text formatter for `klens rollback`.
pub fn format_rollback_text(env: &ProvenanceEnvelope<RollbackReport>) -> String {
    let r = &env.data;
    let mode = if r.dry_run {
        "DRY-RUN preview"
    } else {
        "APPLIED"
    };
    let mut lines = vec![format!(
        "[klens rollback] {mode} target={} note=\"{}\" changes={}",
        r.checkpoint_id,
        r.checkpoint_note,
        r.total_changes()
    )];
    if let Some(safety) = &r.safety_checkpoint_id {
        lines.push(format!(
            "  safety checkpoint saved before rollback: {safety} (undo with `klens rollback {safety}`)"
        ));
    }
    if !r.files_to_restore.is_empty() {
        lines.push(format!("  restore ({}):", r.files_to_restore.len()));
        for p in &r.files_to_restore {
            lines.push(format!("    + {p}"));
        }
    }
    if !r.files_to_modify.is_empty() {
        lines.push(format!("  revert ({}):", r.files_to_modify.len()));
        for p in &r.files_to_modify {
            lines.push(format!("    ~ {p}"));
        }
    }
    if !r.files_to_delete.is_empty() {
        lines.push(format!("  remove ({}):", r.files_to_delete.len()));
        for p in &r.files_to_delete {
            lines.push(format!("    - {p}"));
        }
    }
    if r.total_changes() == 0 {
        lines.push("  working tree already matches this checkpoint.".to_string());
    }
    lines.join("\n")
}

fn ensure_git_repo(root: &Path) -> Result<(), ExecError> {
    let ok = git_stdout_optional(root, &["rev-parse", "--is-inside-work-tree"])
        .is_some_and(|out| out.trim() == "true");
    if !ok {
        return Err(ExecError::NotAGitRepository(root.to_path_buf()));
    }
    Ok(())
}

fn resolve_git_dir(root: &Path) -> Result<PathBuf, ExecError> {
    let raw = git_stdout(root, &["rev-parse", "--git-dir"])?;
    let p = PathBuf::from(raw.trim());
    if p.is_absolute() {
        Ok(p)
    } else {
        Ok(root.join(p))
    }
}

fn snapshot_worktree_to_tree(root: &Path, git_dir: &Path) -> Result<String, ExecError> {
    let tmp_idx = TempGitIndex::allocate(git_dir);
    let env = vec![("GIT_INDEX_FILE".to_string(), tmp_idx.git_env_path())];
    git_stdout_with_env(root, &["add", "-A", "--", "."], &env)?;
    // Always exclude runtime `.klens/cache` and `.klens/runs` from snapshots whether
    // or not the project's `.gitignore` already ignores them.
    let _ = git_stdout_with_env(
        root,
        &[
            "rm",
            "--cached",
            "-r",
            "--ignore-unmatch",
            "--",
            ".klens/cache",
            ".klens/runs",
        ],
        &env,
    );
    // Never store credential files (`.env`, SSH keys, ...) in checkpoint objects: they travel
    // with bundles, mirrors and backups of the repository.
    let mut rm_sensitive: Vec<String> = ["rm", "--cached", "-r", "--ignore-unmatch", "--"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    rm_sensitive.extend(
        klens_core::sensitive::BUILTIN_SENSITIVE_PATTERNS
            .iter()
            .map(|pattern| format!(":(glob,icase)**/{pattern}")),
    );
    let rm_args: Vec<&str> = rm_sensitive.iter().map(String::as_str).collect();
    git_stdout_with_env(root, &rm_args, &env)?;
    let tree_oid = git_stdout_with_env(root, &["write-tree"], &env)?;
    Ok(tree_oid.trim().to_string())
}

fn read_all_checkpoints(root: &Path) -> Result<Vec<CheckpointInfo>, ExecError> {
    let out = git_stdout(
        root,
        &[
            "for-each-ref",
            "--format=%(refname)%1f%(objectname)%1f%(creatordate:iso-strict)%1f%(contents)%1e",
            "refs/klens/checkpoints",
        ],
    )?;

    let mut items = Vec::new();
    for raw_record in out.split('\x1e') {
        let record = raw_record.trim();
        if record.is_empty() {
            continue;
        }
        let mut parts = record.splitn(4, '\x1f');
        let Some(refname) = parts.next() else {
            continue;
        };
        let Some(oid) = parts.next() else {
            continue;
        };
        let Some(creator_iso) = parts.next() else {
            continue;
        };
        let body = parts.next().unwrap_or("");

        let Some(id) = refname.strip_prefix(CHECKPOINT_REF_PREFIX) else {
            continue;
        };

        let mut note = String::new();
        let mut timestamp_utc = creator_iso.trim().to_string();
        let mut branch = "unknown".to_string();
        let mut base_head: Option<String> = None;

        for (idx, line) in body.lines().enumerate() {
            let trimmed = line.trim();
            if idx == 0 {
                note = trimmed.to_string();
            } else if let Some(val) = trimmed.strip_prefix("klens-timestamp-utc:") {
                timestamp_utc = val.trim().to_string();
            } else if let Some(val) = trimmed.strip_prefix("klens-branch:") {
                branch = val.trim().to_string();
            } else if let Some(val) = trimmed.strip_prefix("klens-base-head:") {
                let v = val.trim();
                if !v.is_empty() && v != "none" {
                    base_head = Some(v.to_string());
                }
            }
        }

        items.push(CheckpointInfo {
            id: id.to_string(),
            commit_oid: oid[..oid.len().min(7)].to_string(),
            timestamp_utc,
            note,
            branch,
            base_head,
        });
    }

    // Deterministic newest-first ordering.
    items.sort_by(|a, b| b.id.cmp(&a.id));
    Ok(items)
}

fn resolve_checkpoint(
    all: &[CheckpointInfo],
    id_or_prefix: &str,
) -> Result<CheckpointInfo, ExecError> {
    if let Some(exact) = all.iter().find(|cp| cp.id == id_or_prefix) {
        return Ok(exact.clone());
    }

    let matches: Vec<&CheckpointInfo> = all
        .iter()
        .filter(|cp| cp.id.starts_with(id_or_prefix))
        .collect();

    match matches.len() {
        0 => Err(ExecError::CheckpointNotFound(id_or_prefix.to_string())),
        1 => Ok(matches[0].clone()),
        _ => {
            let candidates = matches
                .iter()
                .map(|c| c.id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            Err(ExecError::AmbiguousCheckpoint {
                query: id_or_prefix.to_string(),
                candidates,
            })
        }
    }
}

fn validate_checkpoint_id(id: &str) -> Result<(), ExecError> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(ExecError::InvalidCheckpointId(id.to_string()));
    }
    Ok(())
}

/// Git tree paths are `/`-separated and repo-relative; reject anything else defensively.
fn is_safe_git_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\0')
        && path
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// Resolve a file to delete during rollback, confined to the project root.
///
/// Returns `None` when the file is already gone, is a directory, or when its parent directory
/// does not canonicalize inside `root` (e.g. a symlinked folder pointing elsewhere).
fn confined_delete_target(root: &Path, rel: &str) -> Option<PathBuf> {
    let candidate = root.join(rel);
    let meta = fs::symlink_metadata(&candidate).ok()?;
    if meta.is_dir() {
        return None;
    }
    let canonical_root = fs::canonicalize(root).ok()?;
    let canonical_parent = fs::canonicalize(candidate.parent()?).ok()?;
    canonical_parent
        .starts_with(&canonical_root)
        .then_some(candidate)
}

fn is_protected_klens_runtime_path(path: &str) -> bool {
    path == ".klens/cache"
        || path.starts_with(".klens/cache/")
        || path == ".klens/runs"
        || path.starts_with(".klens/runs/")
}

fn prune_empty_parents(mut dir: Option<&Path>, root: &Path) {
    while let Some(current) = dir {
        if current == root || !current.starts_with(root) {
            break;
        }
        let is_empty = fs::read_dir(current)
            .map(|mut it| it.next().is_none())
            .unwrap_or(false);
        if !is_empty {
            break;
        }
        let _ = fs::remove_dir(current);
        dir = current.parent();
    }
}

fn ensure_commit_identity_env(root: &Path) -> Vec<(String, String)> {
    let mut env = Vec::new();
    let has_name =
        git_stdout_optional(root, &["config", "user.name"]).is_some_and(|s| !s.trim().is_empty());
    let has_email =
        git_stdout_optional(root, &["config", "user.email"]).is_some_and(|s| !s.trim().is_empty());

    if !has_name {
        env.push(("GIT_AUTHOR_NAME".to_string(), "Karasu Lens".to_string()));
        env.push(("GIT_COMMITTER_NAME".to_string(), "Karasu Lens".to_string()));
    }
    if !has_email {
        env.push(("GIT_AUTHOR_EMAIL".to_string(), "klens@local".to_string()));
        env.push(("GIT_COMMITTER_EMAIL".to_string(), "klens@local".to_string()));
    }
    env
}

fn git_stdout(root: &Path, args: &[&str]) -> Result<String, ExecError> {
    git_stdout_with_env(root, args, &[])
}

fn git_stdout_with_env(
    root: &Path,
    args: &[&str],
    extra_env: &[(String, String)],
) -> Result<String, ExecError> {
    let mut cmd = klens_core::git_command(root);
    cmd.args(["-c", "core.autocrlf=false"])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    let output = cmd.output().map_err(|source| ExecError::SpawnFailed {
        program: "git".to_string(),
        source,
    })?;

    if !output.status.success() {
        return Err(ExecError::GitCommandFailed {
            args: args.join(" "),
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .trim_end_matches(['\r', '\n'])
        .to_string())
}

fn git_stdout_optional(root: &Path, args: &[&str]) -> Option<String> {
    git_stdout(root, args).ok().filter(|s| !s.trim().is_empty())
}
