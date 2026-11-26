use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Subcommand};
use klens_code::CodeIndex;
use klens_core::{ProjectRoot, RelPath, SymbolInfo};
use klens_exec::{
    ErrorSourceContext, ExecError, RelatedBugfixHint, RunOptions, create_checkpoint,
    enrich_error_context_symbols, execute_command, format_checkpoint_created_text,
    format_checkpoints_list_text, format_rollback_text, format_run_detail_text, format_run_text,
    format_runs_list_text, list_checkpoints, list_stored_runs, rollback_checkpoint,
    show_stored_run,
};
use klens_mcp::LazyCodeSymbolResolver;
use klens_memory::{DEFAULT_BUGFIX_MATCH_LIMIT, match_error};

use super::common::{CliError, CliOutcome, resolve_project_root};

#[derive(Debug, Args)]
pub(crate) struct RunArgs {
    /// Kill the command (and its descendant process tree) if it exceeds this many seconds.
    #[arg(long, value_name = "SEC")]
    pub timeout: Option<u64>,

    /// Return the redacted unfiltered raw terminal output instead of the filtered summary.
    #[arg(long)]
    pub raw: bool,

    /// Disable automatic source-code context snippets on failing commands.
    #[arg(long)]
    pub no_auto_context: bool,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,

    /// Command and arguments to execute (pass after `--`).
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RunsArgs {
    #[command(subcommand)]
    pub action: RunsAction,
}

#[derive(Debug, Subcommand)]
pub(crate) enum RunsAction {
    /// List recorded runs newest-first.
    List(RunsListArgs),
    /// Show filtered or raw output for a specific recorded run.
    Show(RunsShowArgs),
}

#[derive(Debug, Args)]
pub(crate) struct RunsListArgs {
    /// Maximum number of runs to show.
    #[arg(long)]
    pub limit: Option<usize>,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct RunsShowArgs {
    /// Run identifier (e.g. `20261122-213000-a1b2`).
    pub run_id: String,

    /// Show redacted raw log verbatim instead of filtered summary.
    #[arg(long)]
    pub raw: bool,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct CheckpointArgs {
    /// Optional human-readable note describing this safety point.
    pub note: Vec<String>,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct CheckpointsArgs {
    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct RollbackArgs {
    /// Target checkpoint ID (or unique prefix).
    pub id: String,

    /// Preview planned restores/reverts/deletions without modifying any file.
    #[arg(long)]
    pub dry_run: bool,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

pub(crate) fn run_exec_cmd(args: RunArgs) -> Result<CliOutcome, CliError> {
    let project_root = resolve_project_root(None, args.root.as_deref())?;
    let options = RunOptions {
        cwd: Some(project_root.root().to_path_buf()),
        timeout: args.timeout.map(Duration::from_secs),
        raw: args.raw,
        auto_context: !args.no_auto_context && !args.raw,
        ..RunOptions::default()
    };
    let mut envelope = execute_command(&project_root, &args.command, &options)?;
    let raw_code = envelope.data.meta.exit_code;

    if !envelope.data.error_contexts.is_empty() {
        attach_cli_error_context_symbols(&project_root, &mut envelope.data.error_contexts);
    }

    // Never hit the same bug twice: match failing runs against `kind: bugfix` notes
    // at the CLI layer without coupling `klens-exec` to `klens-memory`.
    if raw_code != 0 {
        let mut resolver = LazyCodeSymbolResolver::new(&project_root, true, None);
        if let Ok(matches) = match_error(
            &project_root,
            &envelope.data.output,
            DEFAULT_BUGFIX_MATCH_LIMIT,
            &mut resolver,
        ) {
            for m in matches {
                let freshness = m.freshness_label().to_string();
                envelope.data.related_bugfix_notes.push(RelatedBugfixHint {
                    id: m.id,
                    title: m.title,
                    path: m.rel_path,
                    freshness,
                    is_stale: m.is_stale,
                });
            }
        }
    }

    let exit_code = if raw_code == 0 {
        ExitCode::SUCCESS
    } else {
        let clamped = u8::try_from(raw_code).ok().filter(|&c| c != 0).unwrap_or(1);
        ExitCode::from(clamped)
    };

    let output = if args.json {
        envelope
            .to_deterministic_json_pretty()
            .map_err(ExecError::from)?
    } else {
        format_run_text(&envelope).trim_end().to_string()
    };

    Ok(CliOutcome {
        output: Some(output),
        exit_code,
    })
}

fn attach_cli_error_context_symbols(
    project_root: &ProjectRoot,
    contexts: &mut [ErrorSourceContext],
) {
    let Ok(mut index) = CodeIndex::open(project_root.clone(), true) else {
        return;
    };
    let mut cache: BTreeMap<RelPath, Vec<SymbolInfo>> = BTreeMap::new();
    enrich_error_context_symbols(contexts, |rel, line| {
        let symbols = cache.entry(rel.clone()).or_insert_with(|| {
            if index.sync_file(rel).is_err() {
                return Vec::new();
            }
            index.store().get_symbols_for_file(rel).unwrap_or_default()
        });
        symbols
            .iter()
            .filter(|s| s.start_line <= line && line <= s.end_line)
            .min_by(|a, b| {
                a.end_line
                    .saturating_sub(a.start_line)
                    .cmp(&b.end_line.saturating_sub(b.start_line))
                    .then_with(|| b.start_line.cmp(&a.start_line))
                    .then_with(|| a.qualified_name.cmp(&b.qualified_name))
            })
            .map(|s| s.qualified_name.clone())
    });
}

pub(crate) fn run_runs_cmd(args: RunsArgs) -> Result<String, CliError> {
    match args.action {
        RunsAction::List(list_args) => {
            let project_root = resolve_project_root(None, list_args.root.as_deref())?;
            let envelope = list_stored_runs(&project_root, list_args.limit)?;
            if list_args.json {
                Ok(envelope
                    .to_deterministic_json_pretty()
                    .map_err(ExecError::from)?)
            } else {
                Ok(format_runs_list_text(&envelope).trim_end().to_string())
            }
        }
        RunsAction::Show(show_args) => {
            let project_root = resolve_project_root(None, show_args.root.as_deref())?;
            let envelope = show_stored_run(&project_root, &show_args.run_id, show_args.raw)?;
            if show_args.json {
                Ok(envelope
                    .to_deterministic_json_pretty()
                    .map_err(ExecError::from)?)
            } else {
                Ok(format_run_detail_text(&envelope).trim_end().to_string())
            }
        }
    }
}

pub(crate) fn run_checkpoint_cmd(args: CheckpointArgs) -> Result<String, CliError> {
    let project_root = resolve_project_root(None, args.root.as_deref())?;
    let note_joined = args.note.join(" ");
    let note_opt = if note_joined.trim().is_empty() {
        None
    } else {
        Some(note_joined.as_str())
    };
    let envelope = create_checkpoint(&project_root, note_opt)?;
    if args.json {
        Ok(envelope
            .to_deterministic_json_pretty()
            .map_err(ExecError::from)?)
    } else {
        Ok(format_checkpoint_created_text(&envelope)
            .trim_end()
            .to_string())
    }
}

pub(crate) fn run_checkpoints_cmd(args: CheckpointsArgs) -> Result<String, CliError> {
    let project_root = resolve_project_root(None, args.root.as_deref())?;
    let envelope = list_checkpoints(&project_root)?;
    if args.json {
        Ok(envelope
            .to_deterministic_json_pretty()
            .map_err(ExecError::from)?)
    } else {
        Ok(format_checkpoints_list_text(&envelope)
            .trim_end()
            .to_string())
    }
}

pub(crate) fn run_rollback_cmd(args: RollbackArgs) -> Result<String, CliError> {
    let project_root = resolve_project_root(None, args.root.as_deref())?;
    let envelope = rollback_checkpoint(&project_root, &args.id, args.dry_run)?;
    if args.json {
        Ok(envelope
            .to_deterministic_json_pretty()
            .map_err(ExecError::from)?)
    } else {
        Ok(format_rollback_text(&envelope).trim_end().to_string())
    }
}
