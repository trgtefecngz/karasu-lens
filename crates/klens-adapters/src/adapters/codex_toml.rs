//! Codex `~/.codex/config.toml` MCP registration helpers (`[mcp_servers.klens]`).
//!
//! Leaf module: depends only on `common` and `text_format`, used by the Codex adapter.

use std::path::Path;

use super::common::{
    MCP_SERVER_KEY, McpInspection, McpUpsertOutcome, clean_binary_path_string, paths_equivalent,
};
use crate::error::AdapterError;
use crate::text_format::{
    FileOpOutcome, TextFormat, apply_config_write, read_text_file, retry_config_edit,
};

/// Inspect Codex `~/.codex/config.toml` for `[mcp_servers.klens]`.
pub fn inspect_codex_toml_mcp(config_path: &Path) -> McpInspection {
    let (_fmt, normalized) = match read_text_file(config_path) {
        Ok(Some((fmt, lf, _))) => (fmt, lf),
        Ok(None) => return McpInspection::MissingFile,
        Err(err) => return McpInspection::CorruptConfig(err.to_string()),
    };

    if normalized.trim().is_empty() {
        return McpInspection::NotRegistered;
    }

    let table: toml::Table = match toml::from_str(&normalized) {
        Ok(t) => t,
        Err(err) => return McpInspection::CorruptConfig(err.to_string()),
    };

    let Some(entry) = table
        .get("mcp_servers")
        .and_then(toml::Value::as_table)
        .and_then(|servers| servers.get(MCP_SERVER_KEY))
        .and_then(toml::Value::as_table)
    else {
        return McpInspection::NotRegistered;
    };

    let command = entry
        .get("command")
        .and_then(toml::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let args = entry
        .get("args")
        .and_then(toml::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(toml::Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();

    McpInspection::Registered { command, args }
}

/// Locate the byte range `[start, end)` of an explicit `[<header>]` section in normalized LF TOML
/// text (strictly on line boundaries -> UTF-8 safe).
///
/// - When `include_subtables == false`, stops at ANY following `[...]` header so sibling/child
///   tables like `[mcp_servers.klens.env]` are preserved during updates.
/// - When `include_subtables == true`, includes `[<header>.*]` child tables so removals clean up
///   the entire `klens` subtree.
fn find_toml_section_span(
    normalized_lf: &str,
    header: &str,
    include_subtables: bool,
) -> Option<(usize, usize)> {
    let mut offset = 0usize;
    let mut section_start: Option<usize> = None;
    let exact_header = format!("[{header}]");
    let subtable_prefix = format!("[{header}.");

    for segment in normalized_lf.split_inclusive('\n') {
        let trimmed = segment.trim_end_matches('\n').trim();
        let next_offset = offset + segment.len();

        if let Some(start) = section_start {
            if trimmed.starts_with('[')
                && (!include_subtables || !trimmed.starts_with(&subtable_prefix))
            {
                return Some((start, offset));
            }
        } else if trimmed == exact_header {
            section_start = Some(offset);
        }

        offset = next_offset;
    }

    section_start.map(|start| (start, normalized_lf.len()))
}

fn render_codex_klens_section(binary_path: &Path) -> String {
    let cmd = toml::Value::String(clean_binary_path_string(binary_path)).to_string();
    format!("[mcp_servers.{MCP_SERVER_KEY}]\ncommand = {cmd}\nargs = [\"mcp\"]\n")
}

/// Idempotently upsert `[mcp_servers.klens]` in Codex `config.toml`, preserving user keys,
/// comments, UTF-8 BOM, and CRLF/LF line endings.
pub fn upsert_codex_toml_mcp(
    config_path: &Path,
    binary_path: &Path,
    dry_run: bool,
    force: bool,
) -> Result<McpUpsertOutcome, AdapterError> {
    retry_config_edit(|| upsert_codex_toml_mcp_once(config_path, binary_path, dry_run, force))
}

fn upsert_codex_toml_mcp_once(
    config_path: &Path,
    binary_path: &Path,
    dry_run: bool,
    force: bool,
) -> Result<McpUpsertOutcome, AdapterError> {
    let existing = read_text_file(config_path)?;
    let (fmt, normalized_lf, original) = match existing {
        Some((fmt, lf, bytes)) => (fmt, lf, Some(bytes)),
        None => (TextFormat::default(), String::new(), None),
    };

    let parsed: toml::Table = if normalized_lf.trim().is_empty() {
        toml::Table::new()
    } else {
        toml::from_str(&normalized_lf).map_err(|err| AdapterError::InvalidTomlConfig {
            path: config_path.to_path_buf(),
            reason: err.to_string(),
        })?
    };

    let existing_entry = parsed
        .get("mcp_servers")
        .and_then(toml::Value::as_table)
        .and_then(|servers| servers.get(MCP_SERVER_KEY))
        .and_then(toml::Value::as_table);

    let previous_binary = existing_entry
        .and_then(|e| e.get("command"))
        .and_then(toml::Value::as_str)
        .map(ToOwned::to_owned);

    let args_match = existing_entry
        .and_then(|e| e.get("args"))
        .and_then(toml::Value::as_array)
        .is_some_and(|arr| arr.len() == 1 && arr[0].as_str() == Some("mcp"));

    let binary_same = previous_binary
        .as_deref()
        .is_some_and(|old| paths_equivalent(old, binary_path));

    if !force && binary_same && args_match {
        return Ok(McpUpsertOutcome {
            file_outcome: FileOpOutcome::Unchanged,
            previous_binary,
            updated_binary_path: false,
        });
    }

    let updated_binary_path = previous_binary.is_some() && !binary_same;
    let section = render_codex_klens_section(binary_path);

    let updated_lf = if let Some((start, end)) =
        find_toml_section_span(&normalized_lf, "mcp_servers.klens", false)
    {
        let mut out = String::with_capacity(normalized_lf.len() + section.len());
        out.push_str(&normalized_lf[..start]);
        out.push_str(&section);
        let tail = &normalized_lf[end..];
        if !tail.is_empty() && !tail.starts_with('\n') {
            out.push('\n');
        }
        out.push_str(tail);
        out
    } else if existing_entry.is_some() {
        // Inline-table fallback (`[mcp_servers]\nklens = { ... }`): update cleanly via Table.
        let mut table = parsed;
        let servers = table
            .entry("mcp_servers".to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        let servers_tbl =
            servers
                .as_table_mut()
                .ok_or_else(|| AdapterError::InvalidTomlConfig {
                    path: config_path.to_path_buf(),
                    reason: "`mcp_servers` must be a TOML table".to_string(),
                })?;
        let mut klens_tbl = servers_tbl
            .get(MCP_SERVER_KEY)
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default();
        klens_tbl.insert(
            "command".to_string(),
            toml::Value::String(clean_binary_path_string(binary_path)),
        );
        klens_tbl.insert(
            "args".to_string(),
            toml::Value::Array(vec![toml::Value::String("mcp".to_string())]),
        );
        servers_tbl.insert(MCP_SERVER_KEY.to_string(), toml::Value::Table(klens_tbl));
        toml::to_string_pretty(&table).map_err(|err| AdapterError::InvalidTomlConfig {
            path: config_path.to_path_buf(),
            reason: err.to_string(),
        })?
    } else if normalized_lf.is_empty() {
        section
    } else {
        let mut out = normalized_lf;
        out.push('\n');
        out.push_str(&section);
        out
    };

    // Fail-closed validation: guarantee generated TOML parses cleanly before writing.
    toml::from_str::<toml::Table>(&updated_lf).map_err(|err| AdapterError::InvalidTomlConfig {
        path: config_path.to_path_buf(),
        reason: format!("generated TOML failed validation: {err}"),
    })?;

    let encoded = fmt.encode(&updated_lf);
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

/// Surgically remove `[mcp_servers.klens]` from Codex `config.toml`, preserving all other
/// user keys, comments, UTF-8 BOM, and CRLF/LF line endings.
pub fn remove_codex_toml_mcp(
    config_path: &Path,
    dry_run: bool,
    backup_existing: bool,
) -> Result<FileOpOutcome, AdapterError> {
    retry_config_edit(|| remove_codex_toml_mcp_once(config_path, dry_run, backup_existing))
}

fn remove_codex_toml_mcp_once(
    config_path: &Path,
    dry_run: bool,
    backup_existing: bool,
) -> Result<FileOpOutcome, AdapterError> {
    let Some((fmt, normalized_lf, original)) = read_text_file(config_path)? else {
        return Ok(FileOpOutcome::Unchanged);
    };
    if normalized_lf.trim().is_empty() {
        return Ok(FileOpOutcome::Unchanged);
    }

    let mut table: toml::Table =
        toml::from_str(&normalized_lf).map_err(|err| AdapterError::InvalidTomlConfig {
            path: config_path.to_path_buf(),
            reason: err.to_string(),
        })?;

    let has_klens = table
        .get("mcp_servers")
        .and_then(toml::Value::as_table)
        .is_some_and(|servers| servers.contains_key(MCP_SERVER_KEY));
    if !has_klens {
        return Ok(FileOpOutcome::Unchanged);
    }

    let updated_lf = if let Some((start, end)) =
        find_toml_section_span(&normalized_lf, "mcp_servers.klens", true)
    {
        let mut before = &normalized_lf[..start];
        let mut after = &normalized_lf[end..];
        if !before.is_empty() {
            if let Some(stripped) = before.strip_suffix('\n') {
                before = stripped;
            }
        } else if let Some(stripped) = after.strip_prefix('\n') {
            after = stripped;
        }
        let mut out = String::with_capacity(before.len() + after.len());
        out.push_str(before);
        out.push_str(after);
        out
    } else {
        if let Some(servers) = table
            .get_mut("mcp_servers")
            .and_then(toml::Value::as_table_mut)
        {
            servers.remove(MCP_SERVER_KEY);
        }
        toml::to_string_pretty(&table).map_err(|err| AdapterError::InvalidTomlConfig {
            path: config_path.to_path_buf(),
            reason: err.to_string(),
        })?
    };

    // Validate resulting TOML before touching disk.
    if !updated_lf.trim().is_empty() {
        toml::from_str::<toml::Table>(&updated_lf).map_err(|err| {
            AdapterError::InvalidTomlConfig {
                path: config_path.to_path_buf(),
                reason: format!("resulting TOML after removal failed validation: {err}"),
            }
        })?;
    }

    let encoded = fmt.encode(&updated_lf);
    apply_config_write(
        config_path,
        Some(&original),
        &encoded,
        dry_run,
        backup_existing,
        false,
    )
}
