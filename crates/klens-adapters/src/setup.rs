//! `klens setup`: one-time, user-scope MCP registration for every installed AI host.
//!
//! Per-project `klens init` writes project files; `setup` only touches each host's own user
//! configuration, so klens is available in every project with no per-project files. It reuses
//! the safe config writers (order-preserving, re-checked before write) and is undone by
//! `klens disconnect`.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::adapters::codex_toml::upsert_codex_toml_mcp;
use crate::adapters::common::{McpUpsertOutcome, clean_binary_path_string, upsert_json_mcp_server};
use crate::adapters::{AdapterRegistry, HostKind, HostTarget};
use crate::error::AdapterError;
use crate::text_format::{FileOpOutcome, MarkerStyle, upsert_marked_file};

/// Block written into Claude Code's user instructions (`~/.claude/CLAUDE.md`). Decision rules
/// with measured numbers, and when the built-in tools are the better choice.
pub const CLAUDE_USER_GUIDE: &str = "\
## Karasu Lens (klens): when to use its tools

The `klens_*` MCP tools are available in every project. Use them when they save context:

- File over ~200 lines: `klens_outline` first, then `klens_read` with a `symbol` (often ~90% \
fewer tokens than reading the whole file). `klens_read` with only a `path` shows the first 200 \
lines.
- Tests, builds, installs, linters: `klens_run` (passing runs shrink ~85-95%; failures keep every \
error line and a raw log).
- Before changing a shared function: `klens_impact` with `path#symbol`.
- Finding code: `klens_find` (full text and symbols with line numbers).
- The built-in Read and Grep are fine for files under ~150 lines and when you need the exact text \
to edit. Absolute paths inside the project are accepted.";

/// Result of registering one host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupStatus {
    Registered,
    Updated,
    Unchanged,
    NotInstalled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetupEntry {
    pub host: String,
    pub config_path: String,
    pub status: SetupStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetupReport {
    pub binary: String,
    pub dry_run: bool,
    pub entries: Vec<SetupEntry>,
    /// Set when the registered binary lives in a build output folder that `cargo` may replace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_warning: Option<String>,
}

/// Register `binary` as the `klens` MCP server in each selected host's user configuration.
///
/// `Auto`/`All` select every host with user-scope MCP support (Claude Code, Codex,
/// Antigravity); a host whose home folder does not exist is reported as `NotInstalled` and left
/// untouched. The generic host has no user configuration and is skipped.
pub fn setup_user_scope(
    registry: &AdapterRegistry,
    target: HostTarget,
    binary: &Path,
    dry_run: bool,
    install_hook: bool,
) -> Result<SetupReport, AdapterError> {
    let hosts: Vec<HostKind> = match target {
        HostTarget::Single(kind) => vec![kind],
        HostTarget::Auto | HostTarget::All => {
            vec![HostKind::ClaudeCode, HostKind::Codex, HostKind::Antigravity]
        }
    };

    let mut entries = Vec::new();
    for host in hosts {
        let Some((label, installed, config_path)) = user_config_for(registry, host) else {
            continue;
        };
        let status = if installed {
            let outcome = match host {
                HostKind::Codex => upsert_codex_toml_mcp(&config_path, binary, dry_run, false)?,
                _ => upsert_json_mcp_server(&config_path, binary, dry_run, false)?,
            };
            status_of(&outcome)
        } else {
            SetupStatus::NotInstalled
        };
        entries.push(SetupEntry {
            host: label.to_string(),
            config_path: clean_binary_path_string(&config_path),
            status,
        });

        // Claude Code reads `~/.claude/CLAUDE.md` in every project: a short, marker-delimited
        // guide tells the agent when a klens tool beats the built-in one.
        if host == HostKind::ClaudeCode && installed {
            let guide_path = registry.claude_code.global_guide_path();
            let outcome = upsert_marked_file(
                &guide_path,
                MarkerStyle::Html,
                CLAUDE_USER_GUIDE,
                dry_run,
                false,
            )?;
            entries.push(SetupEntry {
                host: "Claude Code guide".to_string(),
                config_path: clean_binary_path_string(&guide_path),
                status: file_status(&outcome),
            });

            // `PreToolUse` hook: simple noisy commands go through `klens run` (off switch:
            // `KLENS_HOOKS=off`; never auto-approves anything). `--no-hook` skips it and leaves
            // `~/.claude/settings.json` untouched.
            if install_hook {
                let outcome = registry
                    .claude_code
                    .install_global_pre_tool_hook(binary, dry_run)?;
                entries.push(SetupEntry {
                    host: "Claude Code hook".to_string(),
                    config_path: clean_binary_path_string(
                        &registry.claude_code.global_settings_path(),
                    ),
                    status: file_status(&outcome),
                });
            }
        }
    }

    Ok(SetupReport {
        binary: clean_binary_path_string(binary),
        dry_run,
        entries,
        binary_warning: build_output_warning(binary).or_else(|| hook_path_warning(binary)),
    })
}

/// `(label, host installed?, user config path)`; `None` for hosts without user-scope MCP.
fn user_config_for(
    registry: &AdapterRegistry,
    host: HostKind,
) -> Option<(&'static str, bool, PathBuf)> {
    let home = &registry.home_dir;
    match host {
        HostKind::ClaudeCode => {
            let path = registry.claude_code.global_mcp_path();
            let installed = path.is_file() || home.join(".claude").is_dir();
            Some(("Claude Code", installed, path))
        }
        HostKind::Codex => Some((
            "Codex",
            home.join(".codex").is_dir(),
            registry.codex.global_config_path(),
        )),
        HostKind::Antigravity => Some((
            "Antigravity",
            home.join(".gemini").is_dir(),
            registry.antigravity.mcp_config_path(),
        )),
        HostKind::Generic => None,
    }
}

fn file_status(outcome: &FileOpOutcome) -> SetupStatus {
    match outcome {
        FileOpOutcome::Unchanged => SetupStatus::Unchanged,
        _ => SetupStatus::Registered,
    }
}

fn status_of(outcome: &McpUpsertOutcome) -> SetupStatus {
    match outcome.file_outcome {
        FileOpOutcome::Unchanged => SetupStatus::Unchanged,
        _ if outcome.previous_binary.is_some() => SetupStatus::Updated,
        _ => SetupStatus::Registered,
    }
}

/// The Claude Code hook embeds the klens path in a command line and only does so for plain
/// paths (letters, digits, `-_./:=@%+,`, spaces; `\` on Windows). Say so when it cannot.
fn hook_path_warning(binary: &Path) -> Option<String> {
    let text = binary.to_string_lossy();
    let plain = text.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '-' | '_' | '.' | '/' | ':' | '=' | '@' | '%' | '+' | ',' | ' '
            )
            || (cfg!(windows) && c == '\\')
    });
    (!plain).then(|| {
        "the klens path contains characters the Claude Code hook cannot embed safely, so the \
         hook will leave commands unchanged; install klens under a plain path to use it"
            .to_string()
    })
}

fn build_output_warning(binary: &Path) -> Option<String> {
    let text = binary.to_string_lossy().replace('\\', "/");
    (text.contains("/target/debug/") || text.contains("/target/release/")).then(|| {
        "the registered binary is a build output that `cargo build` can replace or remove; \
         install it with `cargo install --path crates/klens-cli --locked` and run `klens setup` \
         again"
            .to_string()
    })
}

/// Human-readable report.
pub fn format_setup_text(report: &SetupReport) -> String {
    let mut out = String::new();
    let mode = if report.dry_run {
        " (dry run, nothing written)"
    } else {
        ""
    };
    out.push_str(&format!(
        "Karasu Lens — Setup{mode}\nBinary: {}\n\n",
        report.binary
    ));
    for entry in &report.entries {
        let status = match (&entry.status, report.dry_run) {
            (SetupStatus::Registered, false) => "registered",
            (SetupStatus::Registered, true) => "would register",
            (SetupStatus::Updated, false) => "updated",
            (SetupStatus::Updated, true) => "would update",
            (SetupStatus::Unchanged, _) => "already registered",
            (SetupStatus::NotInstalled, _) => "not installed, skipped",
        };
        out.push_str(&format!(
            "[{}] {status} — {}\n",
            entry.host, entry.config_path
        ));
    }
    if let Some(warning) = &report.binary_warning {
        out.push_str(&format!("\nWARNING: {warning}\n"));
    }
    if !report.dry_run {
        out.push_str(
            "\nklens is now available to these hosts in every project (restart the host to load \
             it).\nUndo with `klens disconnect --host all`, run from a project folder (not your \
             home folder).\n",
        );
    }
    out
}
