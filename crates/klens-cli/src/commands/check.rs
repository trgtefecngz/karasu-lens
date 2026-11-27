//! `klens check`: syntax-check files right after an edit.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
use klens_code::{CheckTarget, CodeIndex, check_files, format_check_text};

use super::code::{DiffCheckArgs, run_diff_check_cmd};
use super::common::{CliError, CliOutcome, resolve_project_root};

#[derive(Debug, Args)]
#[command(after_help = "\
Examples:
  klens check src/lib.rs src/app.ts
  klens check diff
  klens check diff:staged --diff-check

Exit status is 1 when any file has syntax errors. Files without a built-in parser are listed
as not checked and do not fail the run.")]
pub(crate) struct CheckArgs {
    /// Files to check (relative to the project root), or `diff` / `diff:staged` for the files
    /// changed in the current git diff.
    #[arg(required = true)]
    pub paths: Vec<String>,

    /// Also print the `diff-check` summary (changed symbols, protected paths, secrets).
    #[arg(long)]
    pub diff_check: bool,

    /// Zero-footprint mode: never writes `.klens/` into the target project.
    #[arg(long)]
    pub read_only: bool,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

pub(crate) fn run_check_cmd(args: CheckArgs) -> Result<CliOutcome, CliError> {
    let target = CheckTarget::from_inputs(&args.paths).map_err(CliError::InvalidArgument)?;
    let project_root = resolve_project_root(None, args.root.as_deref())?;
    let mut index = CodeIndex::open(project_root.clone(), args.read_only)?;
    let envelope = check_files(&mut index, &target)?;
    drop(index);

    let mut rendered = if args.json {
        envelope
            .to_deterministic_json_pretty()
            .map_err(CliError::Core)?
    } else {
        format_check_text(&envelope).trim_end().to_string()
    };

    if args.diff_check {
        let diff = run_diff_check_cmd(DiffCheckArgs {
            path: None,
            staged: matches!(target, CheckTarget::Diff { staged: true }),
            fail_on: None,
            read_only: args.read_only,
            json: args.json,
            root: Some(project_root.root().to_path_buf()),
        })?;
        if let Some(diff_text) = diff.output {
            rendered = if args.json {
                format!("{{\n\"check\": {rendered},\n\"diff_check\": {diff_text}\n}}")
            } else {
                format!("{rendered}\n\n{diff_text}")
            };
        }
    }

    Ok(CliOutcome {
        output: Some(rendered),
        exit_code: if envelope.data.has_syntax_errors() {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        },
    })
}
