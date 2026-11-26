use std::path::PathBuf;

use clap::{Args, ValueEnum};
use klens_core::ProjectRoot;
use klens_core::telemetry::{StatsQuery, StatsRange, compute_stats, format_stats_text};
use klens_mcp::{McpServer, McpServerConfig};

use super::common::{CliError, CliOutcome, resolve_project_root};

#[derive(Debug, Args)]
pub(crate) struct McpArgs {
    /// Target project root directory (defaults to current working directory).
    #[arg(long, value_name = "PATH")]
    pub project: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum CliStatsRange {
    #[value(name = "today")]
    Today,
    #[value(name = "7d")]
    Days7,
    #[value(name = "30d")]
    Days30,
    #[value(name = "all")]
    All,
}

impl From<CliStatsRange> for StatsRange {
    fn from(value: CliStatsRange) -> Self {
        match value {
            CliStatsRange::Today => Self::Today,
            CliStatsRange::Days7 => Self::Days7,
            CliStatsRange::Days30 => Self::Days30,
            CliStatsRange::All => Self::All,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct StatsArgs {
    /// Time window filter (`today`, `7d`, `30d`, `all`).
    #[arg(long, value_enum, default_value_t = CliStatsRange::Days7)]
    pub range: CliStatsRange,

    /// Filter stats to a specific project path or project name.
    #[arg(long, value_name = "PATH")]
    pub project: Option<PathBuf>,

    /// Emit deterministic JSON matching `docs/02-DATA-SCHEMAS.md` Section 7.
    #[arg(long)]
    pub json: bool,
}

pub(crate) fn run_mcp_cmd(args: McpArgs) -> Result<CliOutcome, CliError> {
    let project_root = resolve_project_root(None, args.project.as_deref())?;
    let mut server = McpServer::new(McpServerConfig::new(project_root));
    server.serve_stdio()?;
    Ok(CliOutcome::silent_ok())
}

pub(crate) fn run_stats_cmd(args: StatsArgs) -> Result<String, CliError> {
    let mut query = StatsQuery {
        range: args.range.into(),
        ..StatsQuery::default()
    };

    if let Some(proj) = args.project {
        if proj.is_dir() {
            let root = ProjectRoot::new(&proj).map_err(klens_core::KlensError::from)?;
            query.project_id_filter = Some(root.project_id().to_string());
            query.project_filter = root
                .root()
                .file_name()
                .and_then(|s| s.to_str())
                .map(ToOwned::to_owned);
        } else {
            query.project_filter = Some(proj.to_string_lossy().into_owned());
        }
    }

    let report = compute_stats(&query)?;
    if args.json {
        let value = serde_json::to_value(&report).map_err(klens_core::KlensError::from)?;
        let encoded = serde_json::to_string_pretty(&value).map_err(klens_core::KlensError::from)?;
        Ok(encoded)
    } else {
        Ok(format_stats_text(&report))
    }
}
