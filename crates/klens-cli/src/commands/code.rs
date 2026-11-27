use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, ValueEnum};
use klens_code::{
    BatchReadData, CodeError, CodeIndex, DEFAULT_FIND_LIMIT, DEFAULT_MAP_BUDGET_TOKENS, DiffAlert,
    DiffAlertKind, DiffCheckOptions, DiffCheckPayload, HealthCheck, ImpactOutputLimits, LineRange,
    MAX_CONTEXT_MEMORY_NOTES, ReadInclude, ReadMemoryNote, ReadResultData, ReadStatus, ReadTarget,
    TrafficLight, analyze_impact, attach_code_context_to_batch, attach_code_context_to_read,
    bound_impact_payload, build_code_graph, build_project_map_focused, find_in_workspace,
    format_batch_read_text, format_diff_check_text, format_find_text, format_graph_text,
    format_health_text, format_impact_text_with, format_map_text, format_outline_text,
    format_read_text, outline_path, read_batch, read_lines, read_symbol,
    run_diff_check_with_options, run_health_check, sanitize_memory_snippet,
};
use klens_core::{
    CheckSeverity, Omission, OmissionKind, ProjectRoot, ProvenanceEnvelope, RelPath, redact_secrets,
};
use klens_memory::{
    ExportedMemoryItem, MEMORY_DIR_REL, MemoryAnchor, MemoryExportFormat, MemoryExportRequest,
    export_memory, verify_all_notes,
};

use super::common::{
    BorrowedCodeSymbolResolver, CliOutcome, resolve_project_root, resolve_root_and_rel,
};

#[derive(Debug, Args)]
pub(crate) struct OutlineArgs {
    /// Target file or directory path.
    pub path: PathBuf,

    /// Optional token budget limit (omitted symbols/files are explicitly reported).
    #[arg(long)]
    pub budget: Option<usize>,

    /// Zero-footprint mode: never writes `.klens/` into the target project (cache in `~/.klens/readonly-cache/`).
    #[arg(long)]
    pub read_only: bool,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[command(after_help = "\
Examples:
  klens read src/lib.rs --symbol \"impl User::new\"
  klens read src/lib.rs --lines 14:28
  klens read --target \"src/lib.rs#fn init\" --target \"src/main.rs@1:20\"")]
pub(crate) struct ReadArgs {
    /// Target file path (required unless `--target` batch mode is used).
    #[arg(required_unless_present = "targets")]
    pub path: Option<PathBuf>,

    /// Exact qualified name (`impl User::new`) or short symbol name (`new`).
    #[arg(long, conflicts_with_all = ["lines", "targets"])]
    pub symbol: Option<String>,

    /// 1-based inclusive line range (`start:end`, e.g. `14:28`).
    #[arg(long, conflicts_with_all = ["symbol", "targets"])]
    pub lines: Option<String>,

    /// Batch targets (`<path>#<symbol>` or `<path>@<start:end>`), repeatable.
    #[arg(long = "target", value_name = "SPEC", conflicts_with_all = ["symbol", "lines"])]
    pub targets: Vec<String>,

    /// Extra context sections (`imports`, `memory`, `impact`; comma-separated or repeatable).
    #[arg(long = "include", value_delimiter = ',')]
    pub include: Vec<String>,

    /// Zero-footprint mode: never writes `.klens/` into the target project (cache in `~/.klens/readonly-cache/`).
    #[arg(long)]
    pub read_only: bool,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct MapArgs {
    /// Optional target project directory (defaults to current working directory).
    pub path: Option<PathBuf>,

    /// Optional relative subdirectory or file path to focus the map on.
    #[arg(long)]
    pub focus: Option<String>,

    /// Token budget limit for ranked file skeletons and dependency summary.
    #[arg(long, default_value_t = DEFAULT_MAP_BUDGET_TOKENS)]
    pub budget: usize,

    /// Zero-footprint mode: never writes `.klens/` into the target project (cache in `~/.klens/readonly-cache/`).
    #[arg(long)]
    pub read_only: bool,

    /// Emit deterministic `ProvenanceEnvelope` JSON (`schema_version = 1`).
    #[arg(long)]
    pub json: bool,

    /// Optional explicit project root directory.
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct FindArgs {
    /// Symbol name, identifier, or text/error query string.
    pub query: String,

    /// Maximum number of deduplicated hits to return.
    #[arg(long, default_value_t = DEFAULT_FIND_LIMIT)]
    pub limit: usize,

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

#[derive(Debug, Args)]
#[command(after_help = "\
Examples:
  klens impact src/auth.rs
  klens impact \"src/auth.rs#verify_token\"
  klens impact diff --budget 4000")]
pub(crate) struct ImpactArgs {
    /// Target relative file path, symbol name, qualified symbol, `<path>#<symbol>`,
    /// `diff` (working tree changes), or `diff:staged`.
    pub target: String,

    /// Max tokens of output (default 1500; 0 = no cap). With `--json`, caps the hit list.
    #[arg(long)]
    pub budget: Option<usize>,

    /// Max affected files listed. With `--json`, caps the hit list.
    #[arg(long)]
    pub limit: Option<usize>,

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

#[derive(Debug, Args)]
pub(crate) struct GraphArgs {
    /// Optional target project directory (defaults to current working directory).
    pub path: Option<PathBuf>,

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum CliFailOnSeverity {
    #[value(name = "error")]
    Error,
    #[value(name = "warning")]
    Warning,
}

#[derive(Debug, Args)]
pub(crate) struct DiffCheckArgs {
    /// Optional target project directory (defaults to current working directory).
    pub path: Option<PathBuf>,

    /// Inspect only staged git index changes (ideal for pre-commit hooks).
    #[arg(long)]
    pub staged: bool,

    /// Exit with non-zero status when alerts reach or exceed this severity (`error` or `warning`).
    #[arg(long, value_enum)]
    pub fail_on: Option<CliFailOnSeverity>,

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

#[derive(Debug, Args)]
pub(crate) struct HealthArgs {
    /// Optional target project directory (defaults to current working directory).
    pub path: Option<PathBuf>,

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

pub(crate) fn run_outline(args: OutlineArgs) -> Result<String, CodeError> {
    let (project_root, rel_opt) = resolve_root_and_rel(&args.path, args.root.as_deref())?;
    let mut index = CodeIndex::open(project_root, args.read_only)?;
    let envelope = outline_path(&mut index, rel_opt.as_ref(), args.budget)?;

    if args.json {
        Ok(envelope.to_deterministic_json_pretty()?)
    } else {
        Ok(format_outline_text(&envelope).trim_end().to_string())
    }
}

pub(crate) fn run_read(args: ReadArgs) -> Result<String, CodeError> {
    let includes = parse_cli_read_includes(&args.include)?;

    if !args.targets.is_empty() {
        let root_dir = match args.root {
            Some(r) => r,
            None => std::env::current_dir().map_err(|source| CodeError::Io {
                path: PathBuf::from("."),
                source,
            })?,
        };
        let project_root = ProjectRoot::new(root_dir)?;
        let mut index = CodeIndex::open(project_root.clone(), args.read_only)?;
        let parsed_targets = parse_cli_batch_targets(&args.targets)?;
        let mut envelope = read_batch(&mut index, &parsed_targets)?;
        if !includes.is_empty() {
            attach_code_context_to_batch(&mut index, &mut envelope, &includes)?;
            if includes.contains(&ReadInclude::Memory) {
                attach_cli_memory_context_to_batch(&project_root, &mut index, &mut envelope);
            }
        }
        return if args.json {
            Ok(envelope.to_deterministic_json_pretty()?)
        } else {
            Ok(format_batch_read_text(&envelope).trim_end().to_string())
        };
    }

    let path = args.path.ok_or(CodeError::InvalidReadTarget)?;
    let (project_root, rel_opt) = resolve_root_and_rel(&path, args.root.as_deref())?;
    let rel = rel_opt.ok_or_else(|| CodeError::NotAFile(path.display().to_string()))?;

    let mut index = CodeIndex::open(project_root.clone(), args.read_only)?;
    let mut envelope = match (args.symbol, args.lines) {
        (Some(sym), None) => read_symbol(&mut index, &rel, &sym)?,
        (None, Some(range_spec)) => {
            let range = LineRange::parse(&range_spec)?;
            read_lines(&index, &rel, range)?
        }
        _ => return Err(CodeError::InvalidReadTarget),
    };
    if !includes.is_empty() {
        attach_code_context_to_read(&mut index, &mut envelope, &includes)?;
        if includes.contains(&ReadInclude::Memory) {
            attach_cli_memory_context_to_read(&project_root, &mut index, &mut envelope);
        }
    }

    if args.json {
        Ok(envelope.to_deterministic_json_pretty()?)
    } else {
        Ok(format_read_text(&envelope).trim_end().to_string())
    }
}

pub(crate) fn run_map(args: MapArgs) -> Result<String, CodeError> {
    let project_root = resolve_project_root(args.path.as_deref(), args.root.as_deref())?;
    let focus_rel = match args.focus.as_deref().map(str::trim) {
        Some(raw) if !raw.is_empty() && raw != "." => Some(RelPath::normalize(raw)?),
        _ => None,
    };
    let mut index = CodeIndex::open(project_root, args.read_only)?;
    let envelope = build_project_map_focused(&mut index, args.budget, focus_rel.as_ref())?;

    if args.json {
        Ok(envelope.to_deterministic_json_pretty()?)
    } else {
        Ok(format_map_text(&envelope).trim_end().to_string())
    }
}

pub(crate) fn run_find(args: FindArgs) -> Result<String, CodeError> {
    let project_root = resolve_project_root(None, args.root.as_deref())?;
    let mut index = CodeIndex::open(project_root, args.read_only)?;
    let envelope = find_in_workspace(&mut index, &args.query, args.limit)?;

    if args.json {
        Ok(envelope.to_deterministic_json_pretty()?)
    } else {
        Ok(format_find_text(&envelope).trim_end().to_string())
    }
}

pub(crate) fn run_impact(args: ImpactArgs) -> Result<String, CodeError> {
    let project_root = resolve_project_root(None, args.root.as_deref())?;
    let target = args.target.trim();

    // Same targets as the MCP tool: `diff` / `diff:staged` run the git diff blast radius.
    if target == "diff" || target == "diff:staged" {
        let envelope =
            diff_check_with_memory(&project_root, args.read_only, target == "diff:staged")?;
        return if args.json {
            Ok(envelope.to_deterministic_json_pretty()?)
        } else {
            Ok(format_diff_check_text(&envelope).trim_end().to_string())
        };
    }

    let mut index = CodeIndex::open(project_root, args.read_only)?;
    let mut envelope = analyze_impact(&mut index, target)?;
    let limits = ImpactOutputLimits::from_request(args.budget, args.limit);

    if args.json {
        // JSON is the full list unless a cap was asked for explicitly.
        if args.budget.is_some() || args.limit.is_some() {
            bound_impact_payload(&mut envelope.data, limits);
        }
        Ok(envelope.to_deterministic_json_pretty()?)
    } else {
        Ok(format_impact_text_with(&envelope, limits)
            .trim_end()
            .to_string())
    }
}

pub(crate) fn run_graph(args: GraphArgs) -> Result<String, CodeError> {
    let project_root = resolve_project_root(args.path.as_deref(), args.root.as_deref())?;
    let mut index = CodeIndex::open(project_root, args.read_only)?;
    let envelope = build_code_graph(&mut index)?;

    if args.json {
        Ok(envelope.to_deterministic_json_pretty()?)
    } else {
        Ok(format_graph_text(&envelope).trim_end().to_string())
    }
}

pub(crate) fn run_diff_check_cmd(args: DiffCheckArgs) -> Result<CliOutcome, CodeError> {
    let project_root = resolve_project_root(args.path.as_deref(), args.root.as_deref())?;
    let envelope = diff_check_with_memory(&project_root, args.read_only, args.staged)?;

    let rendered = if args.json {
        envelope.to_deterministic_json_pretty()?
    } else {
        format_diff_check_text(&envelope).trim_end().to_string()
    };

    let should_fail = match args.fail_on {
        None => false,
        Some(CliFailOnSeverity::Error) => envelope.data.overall_severity >= CheckSeverity::Error,
        Some(CliFailOnSeverity::Warning) => {
            envelope.data.overall_severity >= CheckSeverity::Warning
        }
    };

    Ok(CliOutcome {
        output: Some(rendered),
        exit_code: if should_fail {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        },
    })
}

/// `git diff` check plus `.klens/memory/` staleness alerts (shared by `diff-check` and `impact diff`).
fn diff_check_with_memory(
    project_root: &ProjectRoot,
    read_only: bool,
    staged_only: bool,
) -> Result<ProvenanceEnvelope<DiffCheckPayload>, CodeError> {
    let mut index = CodeIndex::open(project_root.clone(), read_only)?;
    let mut envelope = run_diff_check_with_options(&mut index, DiffCheckOptions { staged_only })?;

    // Integrate verifiable `.klens/memory/` staleness detection without coupling `klens-code` to `klens-memory`.
    if project_root.root().join(MEMORY_DIR_REL).is_dir() {
        let mut resolver = BorrowedCodeSymbolResolver::new(&mut index);
        if let Ok(verify_env) = verify_all_notes(project_root, &mut resolver) {
            for warning in verify_env.warnings {
                envelope = envelope.with_warning(warning);
            }
            for stale in verify_env.data.stale_notes {
                let reasons = stale.stale_reasons.join(", ");
                envelope.data.add_alert(DiffAlert {
                    kind: DiffAlertKind::StaleMemory,
                    severity: CheckSeverity::Warning,
                    path: stale.rel_path,
                    line: None,
                    message: format!(
                        "STALE MEMORY: `{}` ({}) — {} (run `klens memory refresh {}`)",
                        stale.id, stale.title, reasons, stale.id
                    ),
                });
            }
        }
    }

    Ok(envelope)
}

pub(crate) fn run_health_cmd(args: HealthArgs) -> Result<String, CodeError> {
    let project_root = resolve_project_root(args.path.as_deref(), args.root.as_deref())?;
    let mut index = CodeIndex::open(project_root.clone(), args.read_only)?;
    let mut envelope = run_health_check(&mut index)?;

    // Report `.klens/memory/` BLAKE3 staleness and malformed `.md` files in `klens health`.
    if project_root.root().join(MEMORY_DIR_REL).is_dir() {
        let mut resolver = BorrowedCodeSymbolResolver::new(&mut index);
        if let Ok(verify_env) = verify_all_notes(&project_root, &mut resolver) {
            let data = verify_env.data;
            let parse_warnings: Vec<String> = verify_env
                .warnings
                .into_iter()
                .filter(|w| !w.contains("memory note(s) are STALE"))
                .collect();

            let check = if data.stale_count == 0 && parse_warnings.is_empty() {
                HealthCheck {
                    id: "memory_staleness".to_string(),
                    title: "Memory Anchors (.klens/memory/)".to_string(),
                    light: TrafficLight::Green,
                    summary: format!(
                        "{} memory note(s) verified fresh (0 stale)",
                        data.total_notes
                    ),
                    details: Vec::new(),
                }
            } else if data.stale_count == 0 {
                HealthCheck {
                    id: "memory_staleness".to_string(),
                    title: "Memory Anchors (.klens/memory/)".to_string(),
                    light: TrafficLight::Yellow,
                    summary: format!(
                        "{} malformed/unreadable memory file(s) detected ({} valid note(s) fresh)",
                        parse_warnings.len(),
                        data.total_notes
                    ),
                    details: parse_warnings,
                }
            } else {
                let mut details: Vec<String> = data
                    .stale_notes
                    .iter()
                    .map(|s| format!("{} ({}) — {}", s.id, s.rel_path, s.stale_reasons.join("; ")))
                    .collect();
                details.extend(parse_warnings);
                HealthCheck {
                    id: "memory_staleness".to_string(),
                    title: "Memory Anchors (.klens/memory/)".to_string(),
                    light: TrafficLight::Yellow,
                    summary: format!(
                        "{} stale memory note(s) out of {}",
                        data.stale_count, data.total_notes
                    ),
                    details,
                }
            };
            envelope.data.push_check(check);
        }
    }

    if args.json {
        Ok(envelope.to_deterministic_json_pretty()?)
    } else {
        Ok(format_health_text(&envelope).trim_end().to_string())
    }
}

fn parse_cli_read_includes(raw: &[String]) -> Result<Vec<ReadInclude>, CodeError> {
    let mut out = Vec::with_capacity(raw.len());
    for item in raw {
        let inc = ReadInclude::parse(item)?;
        if !out.contains(&inc) {
            out.push(inc);
        }
    }
    Ok(out)
}

fn attach_cli_memory_context_to_read(
    project_root: &ProjectRoot,
    index: &mut CodeIndex,
    envelope: &mut ProvenanceEnvelope<ReadResultData>,
) {
    if envelope.data.status != ReadStatus::Ok || !project_root.root().join(MEMORY_DIR_REL).is_dir()
    {
        return;
    }
    let mut resolver = BorrowedCodeSymbolResolver::new(index);
    let Ok(exported) = export_memory(
        project_root,
        MemoryExportRequest {
            format: MemoryExportFormat::Json,
            ..Default::default()
        },
        &mut resolver,
    ) else {
        return;
    };
    let (redactions, omission) =
        attach_cli_memory_notes_to_result(&exported.data.notes, &mut envelope.data);
    envelope.redactions_count += redactions;
    if let Some(om) = omission {
        envelope.omissions.push(om);
    }
}

fn attach_cli_memory_context_to_batch(
    project_root: &ProjectRoot,
    index: &mut CodeIndex,
    envelope: &mut ProvenanceEnvelope<BatchReadData>,
) {
    if !project_root.root().join(MEMORY_DIR_REL).is_dir()
        || !envelope
            .data
            .targets
            .iter()
            .any(|item| item.result.status == ReadStatus::Ok)
    {
        return;
    }
    let mut resolver = BorrowedCodeSymbolResolver::new(index);
    let Ok(exported) = export_memory(
        project_root,
        MemoryExportRequest {
            format: MemoryExportFormat::Json,
            ..Default::default()
        },
        &mut resolver,
    ) else {
        return;
    };
    for item in &mut envelope.data.targets {
        if item.result.status != ReadStatus::Ok {
            continue;
        }
        let (redactions, omission) =
            attach_cli_memory_notes_to_result(&exported.data.notes, &mut item.result);
        item.redactions_count += redactions;
        envelope.redactions_count += redactions;
        if let Some(om) = omission {
            envelope.omissions.push(om);
        }
    }
}

fn attach_cli_memory_notes_to_result(
    exported_notes: &[ExportedMemoryItem],
    result: &mut ReadResultData,
) -> (usize, Option<Omission>) {
    let mut matched = Vec::new();
    let mut redactions = 0usize;

    for item in exported_notes {
        let linked = item.note.frontmatter.anchors.iter().any(|anchor| {
            cli_anchor_matches_read(
                anchor,
                &result.path,
                result.qualified_name.as_deref(),
                result.query.as_deref(),
            )
        });
        if !linked {
            continue;
        }

        let title_red = redact_secrets(&item.note.frontmatter.title);
        redactions += title_red.redactions_count;
        let (snippet, snip_red) = sanitize_memory_snippet(&item.note.body);
        redactions += snip_red;

        let mut stale_reasons = Vec::with_capacity(item.verification.stale_reasons.len());
        for reason in &item.verification.stale_reasons {
            let red = redact_secrets(reason);
            redactions += red.redactions_count;
            stale_reasons.push(red.text);
        }

        matched.push(ReadMemoryNote {
            id: item.note.frontmatter.id.clone(),
            title: title_red.text,
            kind: item.note.frontmatter.kind.as_str().to_string(),
            trust: item.verification.trust,
            is_stale: !item.verification.fresh,
            stale_reasons,
            snippet,
        });
    }

    if matched.is_empty() {
        return (redactions, None);
    }

    matched.sort_by(|a, b| {
        (!a.is_stale)
            .cmp(&(!b.is_stale))
            .then_with(|| (a.kind != "feedback").cmp(&(b.kind != "feedback")))
            .then_with(|| a.id.cmp(&b.id))
    });

    let mut omission = None;
    let mut memory_omitted = None;
    if matched.len() > MAX_CONTEXT_MEMORY_NOTES {
        let omitted = matched.len() - MAX_CONTEXT_MEMORY_NOTES;
        matched.truncate(MAX_CONTEXT_MEMORY_NOTES);
        memory_omitted = Some(omitted);
        omission = Some(Omission {
            kind: OmissionKind::Items,
            path: Some(result.path.clone()),
            start_line: None,
            end_line: None,
            count: omitted,
            reason: "read_context_memory_limit".to_string(),
        });
    }

    let mut bundle = result.context.take().unwrap_or_default();
    bundle.memory = matched;
    bundle.memory_omitted = memory_omitted;
    if !bundle.is_empty() {
        result.context = Some(bundle);
    }

    (redactions, omission)
}

fn cli_anchor_matches_read(
    anchor: &MemoryAnchor,
    rel_path: &str,
    qualified_name: Option<&str>,
    query: Option<&str>,
) -> bool {
    let anchor_path = RelPath::normalize(&anchor.path)
        .map(|r| r.as_str().to_string())
        .unwrap_or_else(|_| anchor.path.replace('\\', "/"));
    if anchor_path != rel_path {
        return false;
    }
    let Some(anchor_sym) = anchor
        .symbol
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return true;
    };
    let Some(qname) = qualified_name.map(str::trim).filter(|s| !s.is_empty()) else {
        return true;
    };
    let sym_eq = |a: &str, b: &str| {
        a == b
            || ["::", ".", " "]
                .iter()
                .any(|sep| a.ends_with(&format!("{sep}{b}")) || b.ends_with(&format!("{sep}{a}")))
    };
    sym_eq(anchor_sym, qname)
        || query
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_some_and(|q| sym_eq(anchor_sym, q))
}

fn parse_cli_batch_targets(specs: &[String]) -> Result<Vec<ReadTarget>, CodeError> {
    let mut targets = Vec::with_capacity(specs.len());
    for spec in specs {
        if let Some((path, sym)) = spec.split_once('#') {
            if path.trim().is_empty() || sym.trim().is_empty() {
                return Err(CodeError::InvalidReadTarget);
            }
            targets.push(ReadTarget::symbol(path.trim(), sym.trim()));
        } else if let Some((path, range_str)) = spec.rsplit_once('@') {
            if path.trim().is_empty() || range_str.trim().is_empty() {
                return Err(CodeError::InvalidReadTarget);
            }
            let range = LineRange::parse(range_str.trim())?;
            targets.push(ReadTarget::lines(path.trim(), range));
        } else {
            return Err(CodeError::InvalidReadTarget);
        }
    }
    Ok(targets)
}
