use std::path::Path;
use std::process::Command;

/// Result of invoking `git` in read-only query mode.
#[derive(Debug, Clone)]
pub(crate) struct GitCommandOutput {
    pub success: bool,
    pub stdout: String,
}

/// Run a read-only `git` subprocess in `root` with `CREATE_NO_WINDOW` on Windows
/// and `-c core.quotepath=false` so Unicode / Turkish filenames are never octal-escaped.
pub(crate) fn run_git(root: &Path, args: &[&str]) -> Option<GitCommandOutput> {
    let mut cmd = Command::new("git");
    cmd.args(["-c", "core.quotepath=false"])
        .args(args)
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0");

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

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
