//! CLI handlers for opt-in Git `pre-commit` hook management (`klens hook`).

use std::path::PathBuf;

use clap::{Args, Subcommand};
use klens_adapters::{
    current_binary_path, format_hook_install_text, format_hook_status_text,
    format_hook_uninstall_text, install_pre_commit_hook, pre_commit_hook_status,
    uninstall_pre_commit_hook,
};
use klens_core::KlensError;

use super::common::{CliError, resolve_project_root};

#[derive(Debug, Args)]
pub(crate) struct HookArgs {
    #[command(subcommand)]
    pub action: HookSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum HookSubcommand {
    /// Claude Code `PreToolUse` hook: reads the hook JSON on stdin and routes simple noisy
    /// commands (`cargo test`, `npm install`, ...) through `klens run`. Silent otherwise.
    /// Disable with `KLENS_HOOKS=off`.
    PreTool,

    /// Inspect `pre-commit` hook status and binary freshness (strictly read-only).
    Status {
        /// Target project root directory (defaults to current working directory).
        #[arg(long, value_name = "PATH")]
        project: Option<PathBuf>,

        /// Explicit `klens` binary path for freshness comparison (defaults to current executable).
        #[arg(long, value_name = "PATH")]
        binary: Option<PathBuf>,

        /// Emit deterministic JSON output.
        #[arg(long)]
        json: bool,
    },

    /// Idempotently install or update the managed `# klens:start ... # klens:end` block in `pre-commit`.
    Install {
        /// Target project root directory (defaults to current working directory).
        #[arg(long, value_name = "PATH")]
        project: Option<PathBuf>,

        /// Explicit `klens` binary path to invoke from the hook (defaults to current executable).
        #[arg(long, value_name = "PATH")]
        binary: Option<PathBuf>,

        /// Fail the commit on `warning` alerts as well as `error` alerts (`--fail-on warning`).
        #[arg(long)]
        fail_on_warning: bool,

        /// Preview planned hook changes without writing a single byte to disk.
        #[arg(long)]
        dry_run: bool,

        /// Emit deterministic JSON output.
        #[arg(long)]
        json: bool,
    },

    /// Surgically remove only the managed `# klens:start ... # klens:end` block from `pre-commit`.
    Uninstall {
        /// Target project root directory (defaults to current working directory).
        #[arg(long, value_name = "PATH")]
        project: Option<PathBuf>,

        /// Preview planned hook removal without modifying or deleting a single byte on disk.
        #[arg(long)]
        dry_run: bool,

        /// Emit deterministic JSON output.
        #[arg(long)]
        json: bool,
    },
}

fn resolve_binary(explicit: Option<PathBuf>) -> Result<PathBuf, CliError> {
    match explicit {
        Some(path) => Ok(path),
        None => Ok(current_binary_path()?),
    }
}

pub(crate) fn run_hook_cmd(args: HookArgs) -> Result<String, CliError> {
    match args.action {
        HookSubcommand::PreTool => Ok(super::claude_hook::run_pre_tool_hook()),
        HookSubcommand::Status {
            project,
            binary,
            json,
        } => {
            let project_root = resolve_project_root(None, project.as_deref())?;
            let bin = resolve_binary(binary)?;
            let report = pre_commit_hook_status(project_root.root(), &bin);
            if json {
                Ok(serde_json::to_string_pretty(&report).map_err(KlensError::Json)?)
            } else {
                Ok(format_hook_status_text(&report))
            }
        }
        HookSubcommand::Install {
            project,
            binary,
            fail_on_warning,
            dry_run,
            json,
        } => {
            let project_root = resolve_project_root(None, project.as_deref())?;
            let bin = resolve_binary(binary)?;
            let report =
                install_pre_commit_hook(project_root.root(), &bin, fail_on_warning, dry_run)?;
            if json {
                Ok(serde_json::to_string_pretty(&report).map_err(KlensError::Json)?)
            } else {
                Ok(format_hook_install_text(&report))
            }
        }
        HookSubcommand::Uninstall {
            project,
            dry_run,
            json,
        } => {
            let project_root = resolve_project_root(None, project.as_deref())?;
            let report = uninstall_pre_commit_hook(project_root.root(), dry_run, false)?;
            if json {
                Ok(serde_json::to_string_pretty(&report).map_err(KlensError::Json)?)
            } else {
                Ok(format_hook_uninstall_text(&report))
            }
        }
    }
}
