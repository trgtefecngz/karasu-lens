//! The single way klens starts `git`.
//!
//! A project folder may come with its own `.git/config` (archive, shared folder). Several git
//! settings name programs that git would run during ordinary read/write commands:
//! `core.fsmonitor`, hooks (via `core.hooksPath` or `.git/hooks`, e.g. `reference-transaction`
//! on `update-ref`), filter drivers (`filter.<x>.clean/smudge/process` on `add`, `diff`,
//! `checkout-index`), diff drivers (`diff.<x>.textconv/command`, `diff.external`) and signing
//! (`commit.gpgSign` + `gpg.program` on `commit-tree`). klens must never run them, so every
//! command built here overrides those settings on the command line, where they win over any
//! repository or user configuration.
//!
//! Diff drivers are the exception: an empty `diff.external` / textconv value is taken as a
//! (failing) command and silently empties the diff. Callers that produce patches therefore
//! pass `--no-ext-diff --no-textconv` instead.

use std::path::Path;
use std::process::{Command, Stdio};

#[cfg(windows)]
const NULL_DEVICE: &str = "NUL";
#[cfg(not(windows))]
const NULL_DEVICE: &str = "/dev/null";

/// Settings applied to every klens git command (`-c key=value`).
fn hardening_config() -> [String; 9] {
    [
        "core.quotepath=false".to_string(),
        "core.fsmonitor=false".to_string(),
        format!("core.hooksPath={NULL_DEVICE}"),
        "diff.ignoreSubmodules=all".to_string(),
        "commit.gpgSign=false".to_string(),
        "tag.gpgSign=false".to_string(),
        "protocol.allow=never".to_string(),
        "gc.auto=0".to_string(),
        "maintenance.auto=false".to_string(),
    ]
}

/// Environment inherited from a parent process that could redirect or reconfigure git.
const STRIPPED_ENV: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_EXTERNAL_DIFF",
    "GIT_DIFF_OPTS",
    "GIT_PAGER",
    "GIT_EDITOR",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_ASKPASS",
];

/// Build a `git` command for `dir` with every program-launching setting disabled.
///
/// Callers add their own subcommand and arguments, stdio and extra environment.
pub fn git_command(dir: &Path) -> Command {
    let mut cmd = base_command(dir);
    for key in configured_driver_programs(dir) {
        cmd.arg("-c").arg(format!("{key}="));
    }
    cmd
}

fn base_command(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir);
    for var in STRIPPED_ENV {
        cmd.env_remove(var);
    }
    cmd.env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0");
    for setting in hardening_config() {
        cmd.arg("-c").arg(setting);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Names of filter driver program settings defined by the REPOSITORY's own configuration
/// (`local`/`worktree` scope — the part that can arrive with a folder). Driver names are
/// arbitrary, so they are read from the configuration; reading config never runs a program.
/// An empty value disables the driver: `add`, `status` and `checkout-index` then use the file
/// as-is. Filters from the user's global/system config (Git LFS) are trusted and left alone.
fn configured_driver_programs(dir: &Path) -> Vec<String> {
    let output = base_command(dir)
        .args([
            "config",
            "--show-scope",
            "--get-regexp",
            r"^filter\..+\.(clean|smudge|process)$",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    // `<scope>\t<key> <value>`
    let entries: Vec<(&str, &str, &str)> = text
        .lines()
        .filter_map(|line| {
            let (scope, rest) = line.trim_end().split_once('\t')?;
            let (key, value) = rest.split_once(' ').unwrap_or((rest, ""));
            Some((scope, key.trim(), value.trim()))
        })
        .collect();

    let mut untrusted: Vec<String> = entries
        .iter()
        .filter(|(scope, key, value)| {
            matches!(*scope, "local" | "worktree")
                && is_driver_program_key(key)
                && !is_trusted_repository_filter(key, value, &entries)
        })
        .map(|(_, key, _)| (*key).to_string())
        .collect();
    untrusted.sort();
    untrusted.dedup();
    untrusted
}

/// A repository-scope filter setting is still trusted when it only repeats what the user's
/// own (global/system) configuration already says, or when it is a stock Git LFS command —
/// `git lfs install --local` writes exactly those into `.git/config`.
fn is_trusted_repository_filter(key: &str, value: &str, entries: &[(&str, &str, &str)]) -> bool {
    let repeats_user_config = entries.iter().any(|(scope, other_key, other_value)| {
        matches!(*scope, "global" | "system")
            && other_key.eq_ignore_ascii_case(key)
            && *other_value == value
    });
    let stock_lfs = key.to_ascii_lowercase().starts_with("filter.lfs.")
        && matches!(
            value,
            "git-lfs clean -- %f"
                | "git-lfs smudge -- %f"
                | "git-lfs smudge --skip -- %f"
                | "git-lfs filter-process"
                | "git-lfs filter-process --skip"
        );
    repeats_user_config || stock_lfs
}

fn is_driver_program_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    !key.contains(['=', '\n', '\0'])
        && lower.starts_with("filter.")
        && [".clean", ".smudge", ".process"]
            .iter()
            .any(|suffix| lower.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_program_keys_are_recognised() {
        assert!(is_driver_program_key("filter.lfs.clean"));
        assert!(is_driver_program_key("filter.a.b.smudge"));
        assert!(is_driver_program_key("filter.x.process"));
        assert!(!is_driver_program_key("diff.evil.textconv"));
        assert!(!is_driver_program_key("diff.external"));
        assert!(!is_driver_program_key("core.fsmonitor"));
        assert!(!is_driver_program_key("filter.a.clean=x"));
    }

    #[test]
    fn repository_filters_are_trusted_only_when_harmless() {
        let entries = [
            ("system", "filter.lfs.clean", "git-lfs clean -- %f"),
            ("global", "filter.mine.clean", "my-tool clean"),
        ];
        // `git lfs install --local` and repeats of the user's own settings are trusted.
        assert!(is_trusted_repository_filter(
            "filter.lfs.clean",
            "git-lfs clean -- %f",
            &entries
        ));
        assert!(is_trusted_repository_filter(
            "filter.lfs.process",
            "git-lfs filter-process",
            &[]
        ));
        assert!(is_trusted_repository_filter(
            "filter.mine.clean",
            "my-tool clean",
            &entries
        ));
        // Anything else defined by the repository is not.
        assert!(!is_trusted_repository_filter(
            "filter.lfs.clean",
            "sh evil.sh",
            &entries
        ));
        assert!(!is_trusted_repository_filter(
            "filter.mine.clean",
            "my-tool clean; rm -rf ~",
            &entries
        ));
        assert!(!is_trusted_repository_filter(
            "filter.x.smudge",
            "git-lfs smudge -- %f",
            &entries
        ));
    }
}
