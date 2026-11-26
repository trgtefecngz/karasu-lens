//! Shared leaf helpers used by all host adapters (`antigravity`, `claude_code`, `codex`, `generic`).
//!
//! Architectural invariant (`docs/01-ARCHITECTURE.md` Section 6):
//! All shared adapter logic lives in this leaf module so `adapters/mod.rs` and the 4 host
//! adapter modules have **0 circular dependencies**.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use klens_core::telemetry::{
    DEFAULT_MAX_LINE_BYTES, LineReadOutcome, MetricEvent, read_bounded_line,
};
use klens_core::{CheckSeverity, DoctorCheck};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::error::AdapterError;
use crate::text_format::{
    FileOpOutcome, TextFormat, apply_config_delete, apply_config_write, read_text_file,
    retry_config_edit,
};

/// Canonical server key registered in MCP configuration files (`mcpServers.klens` / `[mcp_servers.klens]`).
pub const MCP_SERVER_KEY: &str = "klens";

/// Scope at which a host adapter registration grants access to a project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessScope {
    /// Configured directly inside the project directory (`.mcp.json`, `.claude/`, `AGENTS.md`, `KLENS.md`).
    ProjectLocal,
    /// Configured in the user's home directory (`~/.gemini/config/`, `~/.claude.json`, `~/.codex/config.toml`).
    Global,
}

impl AccessScope {
    pub const fn label_tr(self) -> &'static str {
        match self {
            Self::ProjectLocal => "proje içi",
            Self::Global => "global MCP üzerinden erişebilir",
        }
    }

    pub const fn label_en(self) -> &'static str {
        match self {
            Self::ProjectLocal => "project-local",
            Self::Global => "global-mcp",
        }
    }
}

/// Configured access registration discovered for a host (Layer 1 of honest visibility).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfiguredAccessEntry {
    pub host_id: String,
    pub display_name: String,
    pub scope: AccessScope,
    pub scope_label: String,
    pub config_path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configured_binary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_matches_current: Option<bool>,
}

/// Real MCP client usage observed in `~/.klens/metrics.jsonl` (Layer 2 of honest visibility).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedClientAccess {
    pub client_name: String,
    pub client_version: String,
    pub tool_calls: u64,
    pub last_seen_utc: String,
}

/// Resolve the user home directory using the same precedence as `klens_core::GlobalConfig`.
pub fn resolve_home_dir() -> Result<PathBuf, AdapterError> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .ok_or(AdapterError::HomeDirUnavailable)
}

/// Resolve `~/.klens/config.toml` relative to an explicit `home_dir`.
pub fn global_config_path_in(home_dir: &Path) -> PathBuf {
    home_dir.join(".klens").join("config.toml")
}

/// Resolve `~/.klens/metrics.jsonl` relative to an explicit `home_dir`.
pub fn metrics_path_in(home_dir: &Path) -> PathBuf {
    home_dir.join(".klens").join("metrics.jsonl")
}

/// Clean a filesystem or binary path for display and config serialization.
///
/// Strips Windows verbatim prefixes cleanly:
/// - `\\?\UNC\server\share\...` -> `\\server\share\...`
/// - `\\?\C:\...` -> `C:\...`
pub fn clean_binary_path_string(path: &Path) -> String {
    strip_windows_verbatim(&path.to_string_lossy())
}

fn strip_windows_verbatim(raw: &str) -> String {
    if let Some(unc_rest) = raw.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc_rest}")
    } else if let Some(stripped) = raw.strip_prefix(r"\\?\") {
        stripped.to_string()
    } else {
        raw.to_string()
    }
}

/// Normalize a path string for cross-platform equivalence comparison (e.g. detecting moved `.exe`).
pub fn paths_equivalent(a: &str, b: &Path) -> bool {
    let norm = |s: &str| -> String {
        let cleaned = strip_windows_verbatim(s.trim());
        let slashed = cleaned.replace('\\', "/");
        if cfg!(windows) {
            slashed.to_ascii_lowercase()
        } else {
            slashed
        }
    };
    let b_str = b.to_string_lossy();
    norm(a) == norm(&b_str)
}

/// Render the standard `stdio` MCP JSON snippet for `--print-mcp-json` and `KLENS.md`.
pub fn render_standard_mcp_json(binary_path: &Path) -> String {
    let cmd = clean_binary_path_string(binary_path);
    let doc = json!({
        "mcpServers": {
            MCP_SERVER_KEY: {
                "command": cmd,
                "args": ["mcp"]
            }
        }
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

/// Outcome of inspecting a JSON or TOML MCP configuration file for `klens`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpInspection {
    MissingFile,
    NotRegistered,
    Registered { command: String, args: Vec<String> },
    CorruptConfig(String),
}

/// Inspect a JSON config file containing `"mcpServers": { "klens": { ... } }`.
pub fn inspect_json_mcp_server(config_path: &Path) -> McpInspection {
    let (fmt_res, normalized) = match read_text_file(config_path) {
        Ok(Some((fmt, lf, _))) => (fmt, lf),
        Ok(None) => return McpInspection::MissingFile,
        Err(err) => return McpInspection::CorruptConfig(err.to_string()),
    };
    let _ = fmt_res;

    if normalized.trim().is_empty() {
        return McpInspection::NotRegistered;
    }

    let root: Value = match serde_json::from_str(&normalized) {
        Ok(v) => v,
        Err(err) => return McpInspection::CorruptConfig(err.to_string()),
    };

    let Some(entry) = root
        .get("mcpServers")
        .and_then(Value::as_object)
        .and_then(|servers| servers.get(MCP_SERVER_KEY))
        .and_then(Value::as_object)
    else {
        return McpInspection::NotRegistered;
    };

    let command = entry
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let args = entry
        .get("args")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();

    McpInspection::Registered { command, args }
}

/// Detailed result of upserting an MCP entry into JSON or TOML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpUpsertOutcome {
    pub file_outcome: FileOpOutcome,
    pub previous_binary: Option<String>,
    pub updated_binary_path: bool,
}

/// Idempotently upsert `mcpServers.klens` inside a JSON config file, preserving all other
/// top-level keys (in their original order), other MCP servers, UTF-8 BOM, and CRLF/LF line
/// endings. If the host rewrites the file mid-edit, the edit is redone on the newer content.
pub fn upsert_json_mcp_server(
    config_path: &Path,
    binary_path: &Path,
    dry_run: bool,
    force: bool,
) -> Result<McpUpsertOutcome, AdapterError> {
    retry_config_edit(|| upsert_json_mcp_server_once(config_path, binary_path, dry_run, force))
}

fn upsert_json_mcp_server_once(
    config_path: &Path,
    binary_path: &Path,
    dry_run: bool,
    force: bool,
) -> Result<McpUpsertOutcome, AdapterError> {
    let existing = read_text_file(config_path)?;
    let original = existing.as_ref().map(|(_, _, bytes)| bytes.clone());
    let (fmt, mut root_map) =
        match existing {
            Some((fmt, lf, _)) => {
                let trimmed = lf.trim();
                if trimmed.is_empty() {
                    (fmt, Map::new())
                } else {
                    let parsed: Value = serde_json::from_str(trimmed).map_err(|err| {
                        AdapterError::InvalidJsonConfig {
                            path: config_path.to_path_buf(),
                            reason: err.to_string(),
                        }
                    })?;
                    let obj = parsed.as_object().cloned().ok_or_else(|| {
                        AdapterError::InvalidJsonConfig {
                            path: config_path.to_path_buf(),
                            reason: "expected top-level JSON object".to_string(),
                        }
                    })?;
                    (fmt, obj)
                }
            }
            None => (TextFormat::default(), Map::new()),
        };

    let servers_val = root_map
        .entry("mcpServers".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let servers_obj =
        servers_val
            .as_object_mut()
            .ok_or_else(|| AdapterError::InvalidJsonConfig {
                path: config_path.to_path_buf(),
                reason: "`mcpServers` must be a JSON object".to_string(),
            })?;

    let desired_cmd = clean_binary_path_string(binary_path);
    let desired_args = vec![Value::String("mcp".to_string())];

    let previous_binary = servers_obj
        .get(MCP_SERVER_KEY)
        .and_then(Value::as_object)
        .and_then(|m| m.get("command"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);

    let existing_args_match = servers_obj
        .get(MCP_SERVER_KEY)
        .and_then(Value::as_object)
        .and_then(|m| m.get("args"))
        .and_then(Value::as_array)
        .is_some_and(|a| *a == desired_args);

    let binary_same = previous_binary
        .as_deref()
        .is_some_and(|old| paths_equivalent(old, binary_path));

    if !force && binary_same && existing_args_match {
        return Ok(McpUpsertOutcome {
            file_outcome: FileOpOutcome::Unchanged,
            previous_binary,
            updated_binary_path: false,
        });
    }

    let updated_binary_path = previous_binary.is_some() && !binary_same;

    // Preserve any extra user fields on `mcpServers.klens` (e.g. `env`, `disabled`) while
    // updating `command` and `args`.
    let mut klens_obj = servers_obj
        .get(MCP_SERVER_KEY)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    klens_obj.insert("command".to_string(), Value::String(desired_cmd));
    klens_obj.insert("args".to_string(), Value::Array(desired_args));
    servers_obj.insert(MCP_SERVER_KEY.to_string(), Value::Object(klens_obj));

    let mut rendered = serde_json::to_string_pretty(&Value::Object(root_map)).map_err(|err| {
        AdapterError::InvalidJsonConfig {
            path: config_path.to_path_buf(),
            reason: err.to_string(),
        }
    })?;
    rendered.push('\n');

    let encoded = fmt.encode(&rendered);
    let file_outcome = apply_config_write(
        config_path,
        original.as_deref(),
        &encoded,
        dry_run,
        false,
        force,
    )?;

    Ok(McpUpsertOutcome {
        file_outcome,
        previous_binary,
        updated_binary_path,
    })
}

/// Surgically remove `mcpServers.klens` from a JSON config file, preserving all other keys,
/// UTF-8 BOM, and CRLF/LF line endings.
///
/// When `delete_if_empty == true` (e.g. project-local `.mcp.json`), deletes the file if
/// removing `klens` leaves no remaining MCP servers or other top-level keys.
pub fn remove_json_mcp_server(
    config_path: &Path,
    dry_run: bool,
    backup_existing: bool,
    delete_if_empty: bool,
) -> Result<FileOpOutcome, AdapterError> {
    retry_config_edit(|| {
        remove_json_mcp_server_once(config_path, dry_run, backup_existing, delete_if_empty)
    })
}

fn remove_json_mcp_server_once(
    config_path: &Path,
    dry_run: bool,
    backup_existing: bool,
    delete_if_empty: bool,
) -> Result<FileOpOutcome, AdapterError> {
    let Some((fmt, lf, original)) = read_text_file(config_path)? else {
        return Ok(FileOpOutcome::Unchanged);
    };
    if lf.trim().is_empty() {
        return Ok(FileOpOutcome::Unchanged);
    }

    let parsed: Value =
        serde_json::from_str(lf.trim()).map_err(|err| AdapterError::InvalidJsonConfig {
            path: config_path.to_path_buf(),
            reason: err.to_string(),
        })?;
    let mut root_map =
        parsed
            .as_object()
            .cloned()
            .ok_or_else(|| AdapterError::InvalidJsonConfig {
                path: config_path.to_path_buf(),
                reason: "expected top-level JSON object".to_string(),
            })?;

    let removed = root_map
        .get_mut("mcpServers")
        .and_then(Value::as_object_mut)
        .is_some_and(|servers| servers.shift_remove(MCP_SERVER_KEY).is_some());

    if !removed {
        return Ok(FileOpOutcome::Unchanged);
    }

    let servers_empty = root_map
        .get("mcpServers")
        .and_then(Value::as_object)
        .is_some_and(Map::is_empty);

    if delete_if_empty && servers_empty && root_map.len() == 1 {
        return apply_config_delete(config_path, &original, dry_run, backup_existing);
    }

    let mut rendered = serde_json::to_string_pretty(&Value::Object(root_map)).map_err(|err| {
        AdapterError::InvalidJsonConfig {
            path: config_path.to_path_buf(),
            reason: err.to_string(),
        }
    })?;
    rendered.push('\n');
    let encoded = fmt.encode(&rendered);
    apply_config_write(
        config_path,
        Some(&original),
        &encoded,
        dry_run,
        backup_existing,
        false,
    )
}

/// Build a standardized [`DoctorCheck`] for an MCP registration entry.
pub fn doctor_check_mcp_registration(
    host_label: &str,
    scope: AccessScope,
    config_path: &Path,
    inspection: &McpInspection,
    current_binary: &Path,
) -> DoctorCheck {
    let name = format!("{host_label} ({})", scope.label_en());
    let clean_cfg = clean_binary_path_string(config_path);
    match inspection {
        McpInspection::MissingFile | McpInspection::NotRegistered => DoctorCheck {
            name,
            severity: CheckSeverity::Ok,
            message: format!("not registered at {clean_cfg}"),
        },
        McpInspection::CorruptConfig(reason) => DoctorCheck {
            name,
            severity: CheckSeverity::Error,
            message: format!("corrupt config at {clean_cfg}: {reason}"),
        },
        McpInspection::Registered { command, .. } => {
            if paths_equivalent(command, current_binary) {
                DoctorCheck {
                    name,
                    severity: CheckSeverity::Ok,
                    message: format!(
                        "registered [{}] -> `{command}` ({clean_cfg})",
                        scope.label_en()
                    ),
                }
            } else {
                let current_str = clean_binary_path_string(current_binary);
                DoctorCheck {
                    name,
                    severity: CheckSeverity::Warning,
                    message: format!(
                        "stale binary path [{}]: configured `{command}`, current `{current_str}` — run `klens init` to update ({clean_cfg})",
                        scope.label_en()
                    ),
                }
            }
        }
    }
}

/// Stream `~/.klens/metrics.jsonl` using bounded `BufReader` I/O to compute Layer 2
/// observed client access audit for `project_id`.
pub fn load_observed_client_access(
    metrics_path: &Path,
    project_id: &str,
) -> Vec<ObservedClientAccess> {
    if !metrics_path.is_file() {
        return Vec::new();
    }
    let Ok(file) = File::open(metrics_path) else {
        return Vec::new();
    };
    let mut reader = BufReader::new(file);
    let mut buf = Vec::new();
    let mut by_client: BTreeMap<String, ObservedClientAccess> = BTreeMap::new();

    loop {
        match read_bounded_line(&mut reader, &mut buf, DEFAULT_MAX_LINE_BYTES) {
            Ok(LineReadOutcome::Eof) | Err(_) => break,
            Ok(LineReadOutcome::Truncated { .. }) => continue,
            Ok(LineReadOutcome::Complete) => {
                let Ok(text) = std::str::from_utf8(&buf) else {
                    continue;
                };
                let trimmed = text.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let Ok(event) = serde_json::from_str::<MetricEvent>(trimmed) else {
                    continue;
                };
                if !event.project_id.eq_ignore_ascii_case(project_id) {
                    continue;
                }
                let client = event.client_name.trim();
                if client.is_empty() {
                    continue;
                }
                let entry =
                    by_client
                        .entry(client.to_string())
                        .or_insert_with(|| ObservedClientAccess {
                            client_name: client.to_string(),
                            client_version: event.client_version.clone(),
                            tool_calls: 0,
                            last_seen_utc: event.timestamp_utc.clone(),
                        });
                entry.tool_calls = entry.tool_calls.saturating_add(1);
                if event.timestamp_utc >= entry.last_seen_utc {
                    entry.last_seen_utc = event.timestamp_utc;
                    if !event.client_version.is_empty() {
                        entry.client_version = event.client_version;
                    }
                }
            }
        }
    }

    by_client.into_values().collect()
}
