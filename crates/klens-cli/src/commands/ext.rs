//! CLI handlers for out-of-core optional extension management (`klens ext`).
//!
//! Delegates all catalog lookup, fail-closed ID validation, and atomic TOML
//! persistence to `klens_core::extensions` (single source of truth).

use std::path::PathBuf;

use clap::{Args, Subcommand};
use klens_adapters::{global_config_path_in, resolve_home_dir};
use klens_core::{
    ExtensionScope, format_extension_list_text, format_extension_toggle_text, list_extensions,
    set_extension_enabled,
};

use super::common::{CliError, resolve_project_root};

#[derive(Debug, Args)]
pub(crate) struct ExtArgs {
    #[command(subcommand)]
    pub action: ExtSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ExtSubcommand {
    /// List known out-of-core extensions and their global/project enabled status (read-only).
    List {
        /// Project root directory (defaults to current working directory).
        #[arg(long, value_name = "PATH")]
        root: Option<PathBuf>,

        /// Output structured JSON (`schema_version: 1`).
        #[arg(long)]
        json: bool,
    },

    /// Atomically enable a validated optional extension in project or global `config.toml`.
    Enable {
        /// Canonical extension ID (e.g. `ext-lsp-bridge`, `ext-live-docs`).
        name: String,

        /// Write to user-global `~/.klens/config.toml` instead of project `.klens/config.toml`.
        #[arg(long)]
        global: bool,

        /// Project root directory (defaults to current working directory when not `--global`).
        #[arg(long, value_name = "PATH")]
        root: Option<PathBuf>,

        /// Output structured JSON (`schema_version: 1`).
        #[arg(long)]
        json: bool,
    },

    /// Atomically disable a validated optional extension in project or global `config.toml`.
    Disable {
        /// Canonical extension ID (e.g. `ext-lsp-bridge`, `ext-live-docs`).
        name: String,

        /// Write to user-global `~/.klens/config.toml` instead of project `.klens/config.toml`.
        #[arg(long)]
        global: bool,

        /// Project root directory (defaults to current working directory when not `--global`).
        #[arg(long, value_name = "PATH")]
        root: Option<PathBuf>,

        /// Output structured JSON (`schema_version: 1`).
        #[arg(long)]
        json: bool,
    },
}

pub(crate) fn run_ext_cmd(args: ExtArgs) -> Result<String, CliError> {
    let home = resolve_home_dir()?;
    let global_cfg_path = global_config_path_in(&home);

    match args.action {
        ExtSubcommand::List { root, json } => {
            let project_root = resolve_project_root(None, root.as_deref())?;
            let report = list_extensions(&global_cfg_path, Some(&project_root))?;
            if json {
                Ok(serde_json::to_string_pretty(&report).map_err(klens_core::KlensError::Json)?)
            } else {
                Ok(format_extension_list_text(&report))
            }
        }
        ExtSubcommand::Enable {
            name,
            global,
            root,
            json,
        } => run_ext_toggle(&name, true, global, root.as_deref(), json, &global_cfg_path),
        ExtSubcommand::Disable {
            name,
            global,
            root,
            json,
        } => run_ext_toggle(
            &name,
            false,
            global,
            root.as_deref(),
            json,
            &global_cfg_path,
        ),
    }
}

fn run_ext_toggle(
    name: &str,
    enabled: bool,
    global: bool,
    root: Option<&std::path::Path>,
    json: bool,
    global_cfg_path: &std::path::Path,
) -> Result<String, CliError> {
    let (scope, project_root) = if global {
        (ExtensionScope::Global, None)
    } else {
        (
            ExtensionScope::Project,
            Some(resolve_project_root(None, root)?),
        )
    };

    let report =
        set_extension_enabled(name, enabled, scope, global_cfg_path, project_root.as_ref())?;

    if json {
        Ok(serde_json::to_string_pretty(&report).map_err(klens_core::KlensError::Json)?)
    } else {
        Ok(format_extension_toggle_text(&report))
    }
}
