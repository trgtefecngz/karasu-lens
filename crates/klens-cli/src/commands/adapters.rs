//! CLI handlers for Phase 3B host adapters, symmetric attach/detach, scan, and doctor.

use std::path::PathBuf;

use clap::{Args, ValueEnum};
use klens_adapters::{
    AdapterOptions, AdapterRegistry, ConciseLevel, HostTarget, SkillSelection, attach_project,
    current_binary_path, detach_project, detect_environment, disconnect_host, format_attach_text,
    format_detach_text, format_detect_text, format_disconnect_text, format_doctor_text,
    format_init_text, format_scan_text, format_uninstall_text, global_config_path_in, init_hosts,
    render_standard_mcp_json, resolve_home_dir, run_doctor, scan_directory, uninstall_all,
};
use klens_code::inspect_language_extensions_doctor;
use klens_core::{AdapterContext, CheckSeverity, DoctorCheck, KlensError, ProjectMode};
use klens_mcp::LazyCodeSymbolResolver;
use klens_memory::{MEMORY_DIR_REL, verify_all_notes};

use super::common::{CliError, resolve_project_root};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum CliHostTarget {
    #[value(name = "auto")]
    Auto,
    #[value(name = "antigravity")]
    Antigravity,
    #[value(name = "claude-code")]
    ClaudeCode,
    #[value(name = "codex")]
    Codex,
    #[value(name = "generic")]
    Generic,
    #[value(name = "all")]
    All,
}

impl From<CliHostTarget> for HostTarget {
    fn from(value: CliHostTarget) -> Self {
        match value {
            CliHostTarget::Auto => Self::Auto,
            CliHostTarget::Antigravity => Self::Single(klens_adapters::HostKind::Antigravity),
            CliHostTarget::ClaudeCode => Self::Single(klens_adapters::HostKind::ClaudeCode),
            CliHostTarget::Codex => Self::Single(klens_adapters::HostKind::Codex),
            CliHostTarget::Generic => Self::Single(klens_adapters::HostKind::Generic),
            CliHostTarget::All => Self::All,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum CliDisconnectHost {
    #[value(name = "antigravity")]
    Antigravity,
    #[value(name = "claude-code")]
    ClaudeCode,
    #[value(name = "codex")]
    Codex,
    #[value(name = "generic")]
    Generic,
    #[value(name = "all")]
    All,
}

impl From<CliDisconnectHost> for HostTarget {
    fn from(value: CliDisconnectHost) -> Self {
        match value {
            CliDisconnectHost::Antigravity => Self::Single(klens_adapters::HostKind::Antigravity),
            CliDisconnectHost::ClaudeCode => Self::Single(klens_adapters::HostKind::ClaudeCode),
            CliDisconnectHost::Codex => Self::Single(klens_adapters::HostKind::Codex),
            CliDisconnectHost::Generic => Self::Single(klens_adapters::HostKind::Generic),
            CliDisconnectHost::All => Self::All,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum CliConciseLevel {
    #[value(name = "off")]
    Off,
    #[value(name = "balanced")]
    Balanced,
    #[value(name = "ultra")]
    Ultra,
}

impl From<CliConciseLevel> for ConciseLevel {
    fn from(value: CliConciseLevel) -> Self {
        match value {
            CliConciseLevel::Off => Self::Off,
            CliConciseLevel::Balanced => Self::Balanced,
            CliConciseLevel::Ultra => Self::Ultra,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum CliProjectMode {
    #[value(name = "active")]
    Active,
    #[value(name = "read-only")]
    ReadOnly,
    #[value(name = "paused")]
    Paused,
}

impl From<CliProjectMode> for ProjectMode {
    fn from(value: CliProjectMode) -> Self {
        match value {
            CliProjectMode::Active => Self::Active,
            CliProjectMode::ReadOnly => Self::ReadOnly,
            CliProjectMode::Paused => Self::Paused,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct DetectArgs {
    /// Target project root directory (defaults to current working directory).
    #[arg(long, value_name = "PATH")]
    pub project: Option<PathBuf>,

    /// Explicit `klens` binary path for freshness comparison (defaults to current executable).
    #[arg(long, value_name = "PATH")]
    pub binary: Option<PathBuf>,

    /// Emit deterministic JSON output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ScanArgs {
    /// Directory to scan 1–2 levels deep (strictly read-only).
    #[arg(value_name = "DIR")]
    pub dir: PathBuf,

    /// Maximum scan depth (clamped to 1..=2).
    #[arg(long, default_value_t = 2)]
    pub depth: usize,

    /// Emit deterministic JSON output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub(crate) struct InitArgs {
    /// Target AI host (`auto`, `antigravity`, `claude-code`, `codex`, `generic`, `all`).
    #[arg(long, value_enum, default_value_t = CliHostTarget::Auto)]
    pub host: CliHostTarget,

    /// Target project root directory (defaults to current working directory).
    #[arg(long, value_name = "PATH")]
    pub project: Option<PathBuf>,

    /// Explicit `klens` binary path to register (defaults to current executable).
    #[arg(long, value_name = "PATH")]
    pub binary: Option<PathBuf>,

    /// Verbosity level for the optional `klens-concise` skill (`off`, `balanced`, `ultra`).
    #[arg(long, value_enum, default_value_t = CliConciseLevel::Balanced)]
    pub concise: CliConciseLevel,

    /// Also install the optional `klens-skill-forge` authoring template skill.
    #[arg(long)]
    pub skill_forge: bool,

    /// Disable reversible Claude Code `SessionStart` hook in `.claude/settings.json`.
    #[arg(long)]
    pub no_claude_hooks: bool,

    /// Enable optional Claude Code `PreToolUse` hook in `.claude/settings.json`.
    #[arg(long)]
    pub pre_tool_hook: bool,

    /// Print the standard `stdio` MCP JSON configuration snippet without writing any files.
    #[arg(long)]
    pub print_mcp_json: bool,

    /// Force rewriting configuration and skill files even when already up-to-date.
    #[arg(long)]
    pub force: bool,

    /// Preview planned file changes without writing a single byte to disk.
    #[arg(long)]
    pub dry_run: bool,

    /// Emit deterministic JSON output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub(crate) struct AttachArgs {
    /// Target project directory (defaults to current working directory).
    #[arg(value_name = "PROJECT")]
    pub project: Option<PathBuf>,

    /// Optional initial `.klens/config.toml` operating mode (`active`, `read-only`, `paused`).
    #[arg(long, value_enum)]
    pub mode: Option<CliProjectMode>,

    /// Preview planned changes without writing a single byte to disk.
    #[arg(long)]
    pub dry_run: bool,

    /// Emit deterministic JSON output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub(crate) struct DetachArgs {
    /// Target project directory (defaults to current working directory).
    #[arg(value_name = "PROJECT")]
    pub project: Option<PathBuf>,

    /// Also remove `.klens/` completely (including `blueprint/`, `memory/`, and `config.toml`).
    #[arg(long)]
    pub purge: bool,

    /// Preview planned removals without modifying or deleting a single byte on disk.
    #[arg(long)]
    pub dry_run: bool,

    /// Emit deterministic JSON output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub(crate) struct DisconnectArgs {
    /// AI host to disconnect (`antigravity`, `claude-code`, `codex`, `generic`, `all`).
    #[arg(long, value_enum)]
    pub host: CliDisconnectHost,

    /// Target project directory for project-local cleanup (defaults to current working directory).
    #[arg(long, value_name = "PATH")]
    pub project: Option<PathBuf>,

    /// Preview planned changes without creating backups or writing a single byte to disk.
    #[arg(long)]
    pub dry_run: bool,

    /// Emit deterministic JSON output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub(crate) struct UninstallArgs {
    /// Required safety confirmation to disconnect all hosts and delete `~/.klens/`.
    #[arg(long)]
    pub all: bool,

    /// Target project directory for project-local cleanup (defaults to current working directory).
    #[arg(long, value_name = "PATH")]
    pub project: Option<PathBuf>,

    /// Preview planned uninstall actions without modifying or deleting a single byte on disk.
    #[arg(long)]
    pub dry_run: bool,

    /// Emit deterministic JSON output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub(crate) struct DoctorArgs {
    /// Target project directory (defaults to current working directory).
    #[arg(long, value_name = "PATH")]
    pub project: Option<PathBuf>,

    /// Explicit `klens` binary path for freshness comparison (defaults to current executable).
    #[arg(long, value_name = "PATH")]
    pub binary: Option<PathBuf>,

    /// Emit deterministic JSON output.
    #[arg(long)]
    pub json: bool,
}

fn resolve_binary(explicit: Option<PathBuf>) -> Result<PathBuf, CliError> {
    match explicit {
        Some(path) => Ok(path),
        None => Ok(current_binary_path()?),
    }
}

fn encode_json_value(value: serde_json::Value) -> Result<String, CliError> {
    let encoded = serde_json::to_string_pretty(&value).map_err(KlensError::from)?;
    Ok(encoded)
}

pub(crate) fn run_detect_cmd(args: DetectArgs) -> Result<String, CliError> {
    let project_root = resolve_project_root(None, args.project.as_deref())?;
    let binary = resolve_binary(args.binary)?;
    let registry = AdapterRegistry::with_defaults(&AdapterOptions::default())?;
    let report = detect_environment(&registry, &project_root, &binary);
    if args.json {
        encode_json_value(serde_json::to_value(&report).map_err(KlensError::from)?)
    } else {
        Ok(format_detect_text(&report))
    }
}

pub(crate) fn run_scan_cmd(args: ScanArgs) -> Result<String, CliError> {
    let home = resolve_home_dir()?;
    let report = scan_directory(&args.dir, &home, args.depth)?;
    if args.json {
        encode_json_value(serde_json::to_value(&report).map_err(KlensError::from)?)
    } else {
        Ok(format_scan_text(&report))
    }
}

pub(crate) fn run_init_cmd(args: InitArgs) -> Result<String, CliError> {
    let binary = resolve_binary(args.binary)?;
    if args.print_mcp_json {
        return Ok(render_standard_mcp_json(&binary));
    }

    let project_root = resolve_project_root(None, args.project.as_deref())?;
    let options = AdapterOptions {
        skills: SkillSelection {
            concise: args.concise.into(),
            skill_forge: args.skill_forge,
            ..SkillSelection::default()
        },
        claude_session_hook: !args.no_claude_hooks,
        claude_pre_tool_hook: args.pre_tool_hook,
        force: args.force,
    };
    let registry = AdapterRegistry::with_defaults(&options)?;
    let ctx = AdapterContext {
        project_root: project_root.root().to_path_buf(),
        binary_path: binary,
        dry_run: args.dry_run,
    };

    let report = init_hosts(&registry, args.host.into(), &ctx)?;
    if args.json {
        encode_json_value(serde_json::to_value(&report).map_err(KlensError::from)?)
    } else {
        Ok(format_init_text(&report))
    }
}

pub(crate) fn run_attach_cmd(args: AttachArgs) -> Result<String, CliError> {
    let project_root = resolve_project_root(args.project.as_deref(), None)?;
    let home = resolve_home_dir()?;
    let report = attach_project(
        &home,
        &project_root,
        args.mode.map(Into::into),
        args.dry_run,
    )?;
    if args.json {
        encode_json_value(serde_json::to_value(&report).map_err(KlensError::from)?)
    } else {
        Ok(format_attach_text(&report))
    }
}

pub(crate) fn run_detach_cmd(args: DetachArgs) -> Result<String, CliError> {
    let project_root = resolve_project_root(args.project.as_deref(), None)?;
    let registry = AdapterRegistry::with_defaults(&AdapterOptions::default())?;
    let report = detach_project(&registry, &project_root, args.purge, args.dry_run)?;
    if args.json {
        encode_json_value(serde_json::to_value(&report).map_err(KlensError::from)?)
    } else {
        Ok(format_detach_text(&report))
    }
}

pub(crate) fn run_disconnect_cmd(args: DisconnectArgs) -> Result<String, CliError> {
    let project_root = resolve_project_root(None, args.project.as_deref())?;
    let registry = AdapterRegistry::with_defaults(&AdapterOptions::default())?;
    let ctx = AdapterContext {
        project_root: project_root.root().to_path_buf(),
        binary_path: current_binary_path()?,
        dry_run: args.dry_run,
    };
    let report = disconnect_host(&registry, args.host.into(), &ctx)?;
    if args.json {
        encode_json_value(serde_json::to_value(&report).map_err(KlensError::from)?)
    } else {
        Ok(format_disconnect_text(&report))
    }
}

pub(crate) fn run_uninstall_cmd(args: UninstallArgs) -> Result<String, CliError> {
    let project_root = resolve_project_root(None, args.project.as_deref())?;
    let registry = AdapterRegistry::with_defaults(&AdapterOptions::default())?;
    let ctx = AdapterContext {
        project_root: project_root.root().to_path_buf(),
        binary_path: current_binary_path()?,
        dry_run: args.dry_run,
    };
    let report = uninstall_all(&registry, &ctx, args.all)?;
    if args.json {
        encode_json_value(serde_json::to_value(&report).map_err(KlensError::from)?)
    } else {
        Ok(format_uninstall_text(&report))
    }
}

pub(crate) fn run_doctor_cmd(args: DoctorArgs) -> Result<String, CliError> {
    let project_root = resolve_project_root(None, args.project.as_deref())?;
    let binary = resolve_binary(args.binary)?;
    let registry = AdapterRegistry::with_defaults(&AdapterOptions::default())?;
    let mut report = run_doctor(&registry, &project_root, &binary);

    // Upgrade memory staleness check with AST-aware `klens_memory::verify_all_notes` (read-only)
    // so `klens doctor`, `klens health`, `klens memory verify`, and `klens handoff` agree 100%.
    if project_root.root().join(MEMORY_DIR_REL).is_dir() {
        let mut resolver = LazyCodeSymbolResolver::new(&project_root, true, None);
        if let Ok(verify_env) = verify_all_notes(&project_root, &mut resolver) {
            let data = verify_env.data;
            let parse_warnings: Vec<String> = verify_env
                .warnings
                .into_iter()
                .filter(|w| !w.contains("memory note(s) are STALE"))
                .collect();

            let upgraded = if data.stale_count == 0 && parse_warnings.is_empty() {
                DoctorCheck {
                    name: "Memory staleness (.klens/memory/)".to_string(),
                    severity: CheckSeverity::Ok,
                    message: format!("{} memory note(s) checked, 0 stale", data.total_notes),
                }
            } else if data.stale_count == 0 {
                DoctorCheck {
                    name: "Memory staleness (.klens/memory/)".to_string(),
                    severity: CheckSeverity::Warning,
                    message: format!(
                        "{} malformed/unreadable memory file(s) detected ({} valid note(s) fresh): {}",
                        parse_warnings.len(),
                        data.total_notes,
                        parse_warnings.join("; ")
                    ),
                }
            } else {
                let mut items: Vec<String> =
                    data.stale_notes.iter().map(|s| s.id.clone()).collect();
                items.extend(parse_warnings);
                DoctorCheck {
                    name: "Memory staleness (.klens/memory/)".to_string(),
                    severity: CheckSeverity::Warning,
                    message: format!(
                        "{} stale memory note(s) out of {}: {}",
                        data.stale_count,
                        data.total_notes,
                        items.join(", ")
                    ),
                }
            };

            if let Some(existing) = report
                .checks
                .iter_mut()
                .find(|c| c.name == "Memory staleness (.klens/memory/)")
            {
                *existing = upgraded;
            } else {
                report.checks.push(upgraded);
            }
            report.overall = report
                .checks
                .iter()
                .map(|c| c.severity)
                .max()
                .unwrap_or(CheckSeverity::Ok);
        }
    }

    if let Ok(home) = resolve_home_dir() {
        let global_cfg_path = global_config_path_in(&home);
        let sidecar_checks = inspect_language_extensions_doctor(&global_cfg_path, &project_root);
        report.checks.extend(sidecar_checks);
        report.overall = report
            .checks
            .iter()
            .map(|c| c.severity)
            .max()
            .unwrap_or(CheckSeverity::Ok);
    }

    if args.json {
        encode_json_value(serde_json::to_value(&report).map_err(KlensError::from)?)
    } else {
        Ok(format_doctor_text(&report))
    }
}
