use std::path::Path;
use std::process::Stdio;

/// Result of invoking `git` in read-only query mode.
#[derive(Debug, Clone)]
pub(crate) struct GitCommandOutput {
    pub success: bool,
    pub stdout: String,
}

/// Run a read-only `git` subprocess in `root` through [`klens_core::git_command`], which
/// disables every repository-configured program (fsmonitor, hooks, filters, diff drivers).
pub(crate) fn run_git(root: &Path, args: &[&str]) -> Option<GitCommandOutput> {
    let mut cmd = klens_core::git_command(root);
    cmd.args(args).stdin(Stdio::null()).stderr(Stdio::null());

    let output = cmd.output().ok()?;
    Some(GitCommandOutput {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
    })
}

/// Check whether `root` is inside a git work tree.
pub(crate) fn is_git_repo(root: &Path) -> bool {
    run_git(root, &["rev-parse", "--is-inside-work-tree"])
        .is_some_and(|out| out.success && out.stdout.trim() == "true")
}

/// Return the abbreviated `HEAD` commit hash if available (e.g. `"7af04da"`).
pub(crate) fn head_short_commit(root: &Path) -> Option<String> {
    let out = run_git(root, &["rev-parse", "--short", "HEAD"])?;
    if !out.success {
        return None;
    }
    let trimmed = out.stdout.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Check whether `HEAD` resolves to a commit (false for brand-new empty git repos).
pub(crate) fn has_head_commit(root: &Path) -> bool {
    run_git(root, &["rev-parse", "--verify", "--quiet", "HEAD"]).is_some_and(|out| out.success)
}

/// Read a file's contents at `HEAD:<rel_path>` if present in git history.
pub(crate) fn show_head_file(root: &Path, rel_path: &str) -> Option<String> {
    let spec = format!("HEAD:{rel_path}");
    let out = run_git(root, &["show", &spec])?;
    if out.success { Some(out.stdout) } else { None }
}

/// Read a file's staged contents from the git index (`:<rel_path>`).
pub(crate) fn show_staged_file(root: &Path, rel_path: &str) -> Option<String> {
    let spec = format!(":{rel_path}");
    let out = run_git(root, &["show", &spec])?;
    if out.success { Some(out.stdout) } else { None }
}

/// List git-tracked files matching the provided pathspecs.
pub(crate) fn ls_tracked_files(root: &Path, pathspecs: &[&str]) -> Vec<String> {
    let mut args = Vec::with_capacity(pathspecs.len() + 2);
    args.push("ls-files");
    args.push("--");
    args.extend_from_slice(pathspecs);

    let Some(out) = run_git(root, &args) else {
        return Vec::new();
    };
    if !out.success {
        return Vec::new();
    }
    out.stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}
