#![deny(clippy::print_stdout)]
#![forbid(unsafe_code)]

mod commands;

use std::io::{self, Write};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::commands::adapters::{
    AttachArgs, DetachArgs, DetectArgs, DisconnectArgs, DoctorArgs, InitArgs, ScanArgs, SetupArgs,
    UninstallArgs, run_attach_cmd, run_detach_cmd, run_detect_cmd, run_disconnect_cmd,
    run_doctor_cmd, run_init_cmd, run_scan_cmd, run_setup_cmd, run_uninstall_cmd,
};
use crate::commands::blueprint::{BlueprintArgs, HandoffArgs, run_blueprint_cmd, run_handoff_cmd};
use crate::commands::code::{
    DiffCheckArgs, FindArgs, GraphArgs, HealthArgs, ImpactArgs, MapArgs, OutlineArgs, ReadArgs,
    run_diff_check_cmd, run_find, run_graph, run_health_cmd, run_impact, run_map, run_outline,
    run_read,
};
use crate::commands::common::{CliError, CliOutcome};
use crate::commands::exec::{
    CheckpointArgs, CheckpointsArgs, RollbackArgs, RunArgs, RunsArgs, run_checkpoint_cmd,
    run_checkpoints_cmd, run_exec_cmd, run_rollback_cmd, run_runs_cmd,
};
use crate::commands::ext::{ExtArgs, run_ext_cmd};
use crate::commands::hook::{HookArgs, run_hook_cmd};
use crate::commands::mcp_stats::{McpArgs, StatsArgs, run_mcp_cmd, run_stats_cmd};
use crate::commands::memory::{MemoryArgs, run_memory_cmd};
use crate::commands::ui::{UiArgs, run_ui_cmd};

/// Karasu Lens (`klens`) — local, deterministic code lens and verifiable memory for AI agents.
#[derive(Debug, Parser)]
#[command(
    name = "klens",
    version,
    about = "Karasu Lens — deterministic code lens, terminal filter, and verifiable memory for AI coding agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Extract a deterministic AST symbol outline for a file or directory.
    Outline(OutlineArgs),
    /// Surgically read a symbol or line range (or batch targets) with provenance and line numbers.
    Read(ReadArgs),
    /// Build a deterministic PageRank project map fitted into a token budget.
    Map(MapArgs),
    /// Fast `.gitignore`-compliant FTS5 + symbol search with exact line numbers.
    Find(FindArgs),
    /// Analyze blast radius (dependents & callers) for a file or symbol with confidence tags.
    Impact(ImpactArgs),
    /// Build a deterministic Graphify-inspired code graph with clusters, God Nodes, and cycles.
    Graph(GraphArgs),
    /// Inspect `git diff` mapped to AST symbols, protected paths, new dependencies, secrets, and impact.
    DiffCheck(DiffCheckArgs),
    /// Run 5 deterministic traffic-light project health checks.
    Health(HealthArgs),
    /// Execute a terminal command with ANSI cleaning, block-aware filtering, zero error loss, and raw log capture.
    Run(RunArgs),
    /// Inspect recorded terminal run logs and metadata under `.klens/runs/`.
    Runs(RunsArgs),
    /// Save a safe Git working-tree snapshot (`refs/klens/checkpoints/<id>`) without polluting the main branch.
    Checkpoint(CheckpointArgs),
    /// List saved Git safety checkpoints with timestamps and notes.
    Checkpoints(CheckpointsArgs),
    /// Safely roll back the working tree to a saved checkpoint (supports `--dry-run` preview).
    Rollback(RollbackArgs),
    /// Start the ultra-lightweight universal `stdio` MCP server (JSON-RPC 2.0).
    Mcp(McpArgs),
    /// Display 2-layer telemetry statistics (universal `klens` savings + optional host logs).
    Stats(StatsArgs),
    /// Read-only scan of standard AI host paths and project-local vs global access visibility.
    Detect(DetectArgs),
    /// Read-only discovery of candidate projects 1–2 levels under a directory (writes zero files).
    Scan(ScanArgs),
    /// Idempotently install or update `klens` MCP/skills for Antigravity, Claude Code, Codex, or Generic.
    Init(InitArgs),
    /// Register `klens` once, at user scope, for every installed AI host (works in every project).
    Setup(SetupArgs),
    /// Register a project in `~/.klens/config.toml`, initialize `.klens/config.toml`, and update `.gitignore`.
    Attach(AttachArgs),
    /// Surgically remove project-local `klens` artifacts (preserves `blueprint/` and `memory/` unless `--purge`).
    Detach(DetachArgs),
    /// Back up host configs and cleanly remove `klens` entries for a specific host or all hosts.
    Disconnect(DisconnectArgs),
    /// Disconnect all AI hosts and delete `~/.klens/` global state (requires `--all`).
    Uninstall(UninstallArgs),
    /// Verify installed adapters, binary path freshness, SQLite cache, memory staleness, and `.gitignore`.
    Doctor(DoctorArgs),
    /// Manage Obsidian-compatible `.klens/memory/` notes with BLAKE3 anchor staleness verification.
    Memory(MemoryArgs),
    /// Manage Blueprint decisions, deterministic conflict checks, `USER_LOCKED` contracts, and task queues.
    Blueprint(BlueprintArgs),
    /// Generate a deterministic, budget-fitted session handoff summary from verified project facts.
    Handoff(HandoffArgs),
    /// Manage opt-in out-of-core optional extensions (`list`, `enable`, `disable`).
    Ext(ExtArgs),
    /// Manage optional Git `pre-commit` hook (`status`, `install`, `uninstall`).
    Hook(HookArgs),
    /// Start the lightweight local Web UI on `127.0.0.1` (default action when launched without arguments).
    Ui(UiArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(outcome) => {
            if let Some(output) = outcome.output {
                let mut stdout = io::stdout().lock();
                if writeln!(stdout, "{output}").is_err() {
                    return ExitCode::FAILURE;
                }
            }
            outcome.exit_code
        }
        Err(err) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<CliOutcome, CliError> {
    let Some(command) = cli.command else {
        return run_ui_cmd(UiArgs {
            background: true,
            ..UiArgs::default()
        });
    };
    match command {
        Commands::Outline(args) => Ok(CliOutcome::ok(run_outline(args)?)),
        Commands::Read(args) => Ok(CliOutcome::ok(run_read(args)?)),
        Commands::Map(args) => Ok(CliOutcome::ok(run_map(args)?)),
        Commands::Find(args) => Ok(CliOutcome::ok(run_find(args)?)),
        Commands::Impact(args) => Ok(CliOutcome::ok(run_impact(args)?)),
        Commands::Graph(args) => Ok(CliOutcome::ok(run_graph(args)?)),
        Commands::DiffCheck(args) => Ok(run_diff_check_cmd(args)?),
        Commands::Health(args) => Ok(CliOutcome::ok(run_health_cmd(args)?)),
        Commands::Run(args) => run_exec_cmd(args),
        Commands::Runs(args) => Ok(CliOutcome::ok(run_runs_cmd(args)?)),
        Commands::Checkpoint(args) => Ok(CliOutcome::ok(run_checkpoint_cmd(args)?)),
        Commands::Checkpoints(args) => Ok(CliOutcome::ok(run_checkpoints_cmd(args)?)),
        Commands::Rollback(args) => Ok(CliOutcome::ok(run_rollback_cmd(args)?)),
        Commands::Mcp(args) => run_mcp_cmd(args),
        Commands::Stats(args) => Ok(CliOutcome::ok(run_stats_cmd(args)?)),
        Commands::Detect(args) => Ok(CliOutcome::ok(run_detect_cmd(args)?)),
        Commands::Scan(args) => Ok(CliOutcome::ok(run_scan_cmd(args)?)),
        Commands::Init(args) => Ok(CliOutcome::ok(run_init_cmd(args)?)),
        Commands::Setup(args) => Ok(CliOutcome::ok(run_setup_cmd(args)?)),
        Commands::Attach(args) => Ok(CliOutcome::ok(run_attach_cmd(args)?)),
        Commands::Detach(args) => Ok(CliOutcome::ok(run_detach_cmd(args)?)),
        Commands::Disconnect(args) => Ok(CliOutcome::ok(run_disconnect_cmd(args)?)),
        Commands::Uninstall(args) => Ok(CliOutcome::ok(run_uninstall_cmd(args)?)),
        Commands::Doctor(args) => Ok(CliOutcome::ok(run_doctor_cmd(args)?)),
        Commands::Memory(args) => Ok(CliOutcome::ok(run_memory_cmd(args)?)),
        Commands::Blueprint(args) => Ok(CliOutcome::ok(run_blueprint_cmd(args)?)),
        Commands::Handoff(args) => Ok(CliOutcome::ok(run_handoff_cmd(args)?)),
        Commands::Ext(args) => Ok(CliOutcome::ok(run_ext_cmd(args)?)),
        Commands::Hook(args) => {
            let output = run_hook_cmd(args)?;
            // A silent hook must print nothing at all (not even a newline).
            Ok(CliOutcome {
                output: (!output.is_empty()).then_some(output),
                exit_code: ExitCode::SUCCESS,
            })
        }
        Commands::Ui(args) => run_ui_cmd(args),
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Cli;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
