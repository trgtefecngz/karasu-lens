//! Execution handler for the 7th MCP tool (`klens_memory`) and `klens_run` error→bugfix bridge.
//!
//! Preserves strict crate isolation: `klens-memory` never depends on `klens-code` or `klens-exec`.
//! Instead, this module supplies a lazy Tree-sitter AST-backed [`SymbolResolver`] and combines
//! `klens_memory::match_error` with failing `klens_run` outputs at the MCP layer.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use klens_code::{
    BatchReadData, CodeIndex, DiffAlert, DiffAlertKind, DiffCheckPayload, FileSyncOutcome,
    MAX_CONTEXT_MEMORY_NOTES, ParseStatus, ReadMemoryNote, ReadResultData, ReadStatus,
    sanitize_memory_snippet,
};
use klens_core::{
    CheckSeverity, Omission, OmissionKind, ProjectMode, ProjectRoot, ProvenanceEnvelope, RelPath,
    TrustLevel, estimate_tokens, normalize_line_endings, redact_secrets,
};
use klens_exec::{RelatedBugfixHint, RunResponse};
use klens_memory::{
    AddMemoryRequest, AnchorSpec, DEFAULT_BUGFIX_MATCH_LIMIT, ExportedMemoryItem, MEMORY_DIR_REL,
    MemoryAnchor, MemoryExportFormat, MemoryExportRequest, MemoryKind, MemoryStatus,
    SymbolLookupResult, SymbolResolver, UpdateMemoryRequest, add_memory, delete_memory,
    export_memory, format_memory_delete_text, format_memory_get_text, format_memory_index_text,
    format_memory_search_text, format_memory_verify_text, format_memory_write_text, get_memory,
    list_memory_index_with_tags, match_error, refresh_memory, search_memory, update_memory,
    verify_all_notes,
};
use serde_json::Value;

use crate::error::McpError;
use crate::handler_common::{
    OutputFormat, ToolContext, ToolExecution, parse_format, parse_optional_bool,
    parse_optional_string, parse_optional_usize,
};
use crate::protocol::CallToolResult;

/// Lazy Tree-sitter AST symbol resolver bridging `klens-memory` and `klens-code`.
///
/// Defers opening SQLite `CodeIndex` until an anchor with `symbol: Some(...)` is resolved,
/// keeping file-only anchor verification and empty-vault checks zero-overhead.
pub struct LazyCodeSymbolResolver<'a> {
    project_root: &'a ProjectRoot,
    read_only: bool,
    readonly_cache_dir: Option<&'a Path>,
    index: Option<CodeIndex>,
}

impl<'a> LazyCodeSymbolResolver<'a> {
    pub fn new(
        project_root: &'a ProjectRoot,
        read_only: bool,
        readonly_cache_dir: Option<&'a Path>,
    ) -> Self {
        Self {
            project_root,
            read_only,
            readonly_cache_dir,
            index: None,
        }
    }

    fn ensure_index(&mut self) -> Option<&mut CodeIndex> {
        if self.index.is_none() {
            let opened = match self.readonly_cache_dir {
                Some(dir) => CodeIndex::open_with_readonly_cache_dir(
                    self.project_root.clone(),
                    self.read_only,
                    dir,
                )
                .ok(),
                None => CodeIndex::open(self.project_root.clone(), self.read_only).ok(),
            };
            self.index = opened;
        }
        self.index.as_mut()
    }
}

impl SymbolResolver for LazyCodeSymbolResolver<'_> {
    fn resolve_symbol(&mut self, path: &RelPath, symbol: &str) -> SymbolLookupResult {
        let Some(index) = self.ensure_index() else {
            return SymbolLookupResult::Unparsed("failed to open AST index".to_string());
        };

        match index.sync_file(path) {
            Ok(FileSyncOutcome::SkippedBinary) => {
                return SymbolLookupResult::Unparsed("binary or non-UTF-8 file".to_string());
            }
            Ok(FileSyncOutcome::Parsed | FileSyncOutcome::Unchanged) => {}
            Err(err) => return SymbolLookupResult::Unparsed(err.to_string()),
        }

        if let Ok(Some(rec)) = index.store().get_file(path)
            && rec.parse_status == ParseStatus::Fallback
        {
            return SymbolLookupResult::Unparsed(
                rec.parse_warning
                    .unwrap_or_else(|| "unsupported language or syntax error".to_string()),
            );
        }

        let Ok(symbols) = index.store().get_symbols_for_file(path) else {
            return SymbolLookupResult::Missing;
        };

        let query = symbol.trim();
        let exact: Vec<_> = symbols
            .iter()
            .filter(|s| s.qualified_name == query)
            .collect();
        let candidates = if !exact.is_empty() {
            exact
        } else {
            symbols.iter().filter(|s| s.name == query).collect()
        };

        match candidates.as_slice() {
            [] => SymbolLookupResult::Missing,
            [sym] => {
                let Ok((abs, _)) = self.project_root.resolve_existing(path.as_str()) else {
                    return SymbolLookupResult::Missing;
                };
                let Ok(raw) = fs::read_to_string(&abs) else {
                    return SymbolLookupResult::Missing;
                };
                let normalized = normalize_line_endings(&raw);
                let lines: Vec<&str> = normalized.lines().collect();
                if sym.start_line == 0
                    || sym.end_line < sym.start_line
                    || sym.end_line > lines.len()
                {
                    return SymbolLookupResult::Missing;
                }
                let snippet = lines[sym.start_line - 1..sym.end_line].join("\n");
                SymbolLookupResult::Found {
                    qualified_name: sym.qualified_name.clone(),
                    source_snippet: snippet,
                    start_line: sym.start_line,
                    end_line: sym.end_line,
                }
            }
            many => SymbolLookupResult::Ambiguous(
                many.iter().map(|s| s.qualified_name.clone()).collect(),
            ),
        }
    }
}

/// Dispatch `klens_memory` actions (`index`, `get`, `search`, `add`, `update`, `delete`, `verify`, `refresh`).
pub(crate) fn handle_memory(
    ctx: &ToolContext<'_>,
    args: &Value,
) -> Result<ToolExecution, McpError> {
    let format = parse_format(args)?;
    let action = args
        .get("action")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            McpError::InvalidParams("`action` is required for `klens_memory`".to_string())
        })?;

    let read_only = ctx.mode == ProjectMode::ReadOnly;
    let mut resolver =
        LazyCodeSymbolResolver::new(ctx.project_root, read_only, ctx.readonly_cache_dir);

    match action {
        "index" | "list" => {
            let kind = parse_optional_kind(args)?;
            let mut tags_filter = parse_optional_string_array(args, "tags")?.unwrap_or_default();
            if let Some(single_tag) = optional_non_empty_string(args, "tag")? {
                tags_filter.push(single_tag);
            }
            let stale_only = parse_optional_bool(args, "stale_only")?.unwrap_or(false);

            let env = list_memory_index_with_tags(
                ctx.project_root,
                kind,
                &tags_filter,
                stale_only,
                &mut resolver,
            )?;
            let stale_caught = env.data.stale_count as u64;
            let text = match format {
                OutputFormat::Text => format_memory_index_text(&env).trim_end().to_string(),
                OutputFormat::Json => env.to_deterministic_json()?,
            };
            let tokens = estimate_tokens(&text) as u64;
            Ok(ToolExecution {
                result: CallToolResult::text(text),
                raw_est_tokens: tokens,
                filtered_est_tokens: tokens,
                is_run_filtered: false,
                stale_memories_caught: stale_caught,
            })
        }
        "get" => {
            let id = require_string(args, "id")?;
            let env = get_memory(ctx.project_root, id, &mut resolver)?;
            let stale_caught = u64::from(env.trust == TrustLevel::Stale);
            let text = match format {
                OutputFormat::Text => format_memory_get_text(&env).trim_end().to_string(),
                OutputFormat::Json => env.to_deterministic_json()?,
            };
            let tokens = estimate_tokens(&text) as u64;
            Ok(ToolExecution {
                result: CallToolResult::text(text),
                raw_est_tokens: tokens,
                filtered_est_tokens: tokens,
                is_run_filtered: false,
                stale_memories_caught: stale_caught,
            })
        }
        "search" => {
            let query = require_string(args, "query")?;
            let kind = parse_optional_kind(args)?;
            let limit = parse_optional_usize(args, "limit")?;
            let env = search_memory(ctx.project_root, query, kind, limit, &mut resolver)?;
            let stale_caught = env
                .data
                .hits
                .iter()
                .filter(|h| h.entry.trust == TrustLevel::Stale)
                .count() as u64;
            let text = match format {
                OutputFormat::Text => format_memory_search_text(&env).trim_end().to_string(),
                OutputFormat::Json => env.to_deterministic_json()?,
            };
            let tokens = estimate_tokens(&text) as u64;
            Ok(ToolExecution {
                result: CallToolResult::text(text),
                raw_est_tokens: tokens,
                filtered_est_tokens: tokens,
                is_run_filtered: false,
                stale_memories_caught: stale_caught,
            })
        }
        "verify" => {
            let env = verify_all_notes(ctx.project_root, &mut resolver)?;
            let stale_caught = env.data.stale_count as u64;
            let text = match format {
                OutputFormat::Text => format_memory_verify_text(&env).trim_end().to_string(),
                OutputFormat::Json => env.to_deterministic_json()?,
            };
            let tokens = estimate_tokens(&text) as u64;
            Ok(ToolExecution {
                result: CallToolResult::text(text),
                raw_est_tokens: tokens,
                filtered_est_tokens: tokens,
                is_run_filtered: false,
                stale_memories_caught: stale_caught,
            })
        }
        "add" => {
            let title = require_string(args, "title")?.to_string();
            let id = optional_non_empty_string(args, "id")?;
            let kind = parse_optional_kind(args)?.unwrap_or(MemoryKind::Decision);
            let body = parse_optional_string(args, "body")?.unwrap_or_default();
            let anchors = parse_optional_anchors(args)?.unwrap_or_default();
            let tags = parse_optional_string_array(args, "tags")?.unwrap_or_default();

            let env = add_memory(
                ctx.project_root,
                AddMemoryRequest {
                    id,
                    title,
                    kind,
                    body,
                    anchors,
                    tags,
                },
                &mut resolver,
            )?;
            let text = match format {
                OutputFormat::Text => format_memory_write_text(&env).trim_end().to_string(),
                OutputFormat::Json => env.to_deterministic_json()?,
            };
            let tokens = estimate_tokens(&text) as u64;
            Ok(ToolExecution {
                result: CallToolResult::text(text),
                raw_est_tokens: tokens,
                filtered_est_tokens: tokens,
                is_run_filtered: false,
                stale_memories_caught: 0,
            })
        }
        "update" => {
            let id = require_string(args, "id")?.to_string();
            let title = optional_non_empty_string(args, "title")?;
            let kind = parse_optional_kind(args)?;
            let status = match optional_non_empty_string(args, "status")? {
                Some(s) => Some(MemoryStatus::parse(&s)?),
                None => None,
            };
            let body = parse_optional_string(args, "body")?;
            let anchors = parse_optional_anchors(args)?;
            let tags = parse_optional_string_array(args, "tags")?;

            let env = update_memory(
                ctx.project_root,
                UpdateMemoryRequest {
                    id,
                    title,
                    kind,
                    status,
                    body,
                    anchors,
                    tags,
                    refresh_anchors: false,
                },
                &mut resolver,
            )?;
            let stale_caught = u64::from(env.trust == TrustLevel::Stale);
            let text = match format {
                OutputFormat::Text => format_memory_write_text(&env).trim_end().to_string(),
                OutputFormat::Json => env.to_deterministic_json()?,
            };
            let tokens = estimate_tokens(&text) as u64;
            Ok(ToolExecution {
                result: CallToolResult::text(text),
                raw_est_tokens: tokens,
                filtered_est_tokens: tokens,
                is_run_filtered: false,
                stale_memories_caught: stale_caught,
            })
        }
        "refresh" => {
            let id = require_string(args, "id")?;
            let env = refresh_memory(ctx.project_root, id, &mut resolver)?;
            let text = match format {
                OutputFormat::Text => format_memory_write_text(&env).trim_end().to_string(),
                OutputFormat::Json => env.to_deterministic_json()?,
            };
            let tokens = estimate_tokens(&text) as u64;
            Ok(ToolExecution {
                result: CallToolResult::text(text),
                raw_est_tokens: tokens,
                filtered_est_tokens: tokens,
                is_run_filtered: false,
                stale_memories_caught: 0,
            })
        }
        "delete" => {
            let id = require_string(args, "id")?;
            let env = delete_memory(ctx.project_root, id)?;
            let text = match format {
                OutputFormat::Text => format_memory_delete_text(&env).trim_end().to_string(),
                OutputFormat::Json => env.to_deterministic_json()?,
            };
            let tokens = estimate_tokens(&text) as u64;
            Ok(ToolExecution {
                result: CallToolResult::text(text),
                raw_est_tokens: tokens,
                filtered_est_tokens: tokens,
                is_run_filtered: false,
                stale_memories_caught: 0,
            })
        }
        other => Err(McpError::InvalidParams(format!(
            "unsupported `klens_memory` action `{other}` (expected index|get|search|add|update|delete|verify|refresh)"
        ))),
    }
}

/// Match failing `klens_run` error output against `kind: bugfix` notes via `klens_memory::match_error`
/// and attach verified hints onto `envelope.data.related_bugfix_notes`.
///
/// Returns the number of stale bugfix notes caught (for Layer 1 telemetry).
pub(crate) fn attach_bugfix_matches_to_run(
    ctx: &ToolContext<'_>,
    envelope: &mut ProvenanceEnvelope<RunResponse>,
) -> u64 {
    if envelope.data.meta.exit_code == 0 {
        return 0;
    }

    let read_only = ctx.mode == ProjectMode::ReadOnly;
    let mut resolver =
        LazyCodeSymbolResolver::new(ctx.project_root, read_only, ctx.readonly_cache_dir);

    let Ok(matches) = match_error(
        ctx.project_root,
        &envelope.data.output,
        DEFAULT_BUGFIX_MATCH_LIMIT,
        &mut resolver,
    ) else {
        return 0;
    };

    let mut stale_caught = 0u64;
    for m in matches {
        if m.is_stale {
            stale_caught += 1;
        }
        let freshness = m.freshness_label().to_string();
        envelope.data.related_bugfix_notes.push(RelatedBugfixHint {
            id: m.id,
            title: m.title,
            path: m.rel_path,
            freshness,
            is_stale: m.is_stale,
        });
    }
    stale_caught
}

/// Attach BLAKE3-verified linked memory notes onto a single `klens_read` envelope (zero disk writes).
///
/// Returns the number of distinct stale notes surfaced (for Layer 1 telemetry).
pub(crate) fn attach_memory_context_to_read(
    ctx: &ToolContext<'_>,
    envelope: &mut ProvenanceEnvelope<ReadResultData>,
) -> u64 {
    if envelope.data.status != ReadStatus::Ok
        || !ctx.project_root.root().join(MEMORY_DIR_REL).is_dir()
    {
        return 0;
    }

    let read_only = ctx.mode == ProjectMode::ReadOnly;
    let mut resolver =
        LazyCodeSymbolResolver::new(ctx.project_root, read_only, ctx.readonly_cache_dir);
    let Ok(exported) = export_memory(
        ctx.project_root,
        MemoryExportRequest {
            format: MemoryExportFormat::Json,
            ..Default::default()
        },
        &mut resolver,
    ) else {
        return 0;
    };

    let mut stale_ids = BTreeSet::new();
    let (redactions, omission) =
        attach_memory_notes_to_result(&exported.data.notes, &mut envelope.data, &mut stale_ids);
    envelope.redactions_count += redactions;
    if let Some(om) = omission {
        envelope.omissions.push(om);
    }
    stale_ids.len() as u64
}

/// Attach BLAKE3-verified linked memory notes onto every `ReadStatus::Ok` target in a batch read
/// (zero disk writes; vault is loaded and verified once for the entire batch).
///
/// Returns the number of distinct stale notes surfaced (for Layer 1 telemetry).
pub(crate) fn attach_memory_context_to_batch(
    ctx: &ToolContext<'_>,
    envelope: &mut ProvenanceEnvelope<BatchReadData>,
) -> u64 {
    if !ctx.project_root.root().join(MEMORY_DIR_REL).is_dir()
        || !envelope
            .data
            .targets
            .iter()
            .any(|item| item.result.status == ReadStatus::Ok)
    {
        return 0;
    }

    let read_only = ctx.mode == ProjectMode::ReadOnly;
    let mut resolver =
        LazyCodeSymbolResolver::new(ctx.project_root, read_only, ctx.readonly_cache_dir);
    let Ok(exported) = export_memory(
        ctx.project_root,
        MemoryExportRequest {
            format: MemoryExportFormat::Json,
            ..Default::default()
        },
        &mut resolver,
    ) else {
        return 0;
    };

    let mut stale_ids = BTreeSet::new();
    for item in &mut envelope.data.targets {
        if item.result.status != ReadStatus::Ok {
            continue;
        }
        let (redactions, omission) =
            attach_memory_notes_to_result(&exported.data.notes, &mut item.result, &mut stale_ids);
        item.redactions_count += redactions;
        envelope.redactions_count += redactions;
        if let Some(om) = omission {
            envelope.omissions.push(om);
        }
    }
    stale_ids.len() as u64
}

/// Attach read-only `.klens/memory/` BLAKE3 staleness alerts onto a `klens_impact("diff")`
/// envelope (exact parity with CLI `klens diff-check`, zero disk writes).
pub(crate) fn attach_stale_memory_alerts_to_diff(
    ctx: &ToolContext<'_>,
    envelope: &mut ProvenanceEnvelope<DiffCheckPayload>,
) -> u64 {
    if !ctx.project_root.root().join(MEMORY_DIR_REL).is_dir() {
        return 0;
    }

    let read_only = ctx.mode == ProjectMode::ReadOnly;
    let mut resolver =
        LazyCodeSymbolResolver::new(ctx.project_root, read_only, ctx.readonly_cache_dir);
    let Ok(verify_env) = verify_all_notes(ctx.project_root, &mut resolver) else {
        return 0;
    };

    for warning in verify_env.warnings {
        envelope.warnings.push(warning);
    }
    let stale_count = verify_env.data.stale_notes.len() as u64;
    for stale in verify_env.data.stale_notes {
        let title_red = redact_secrets(&stale.title);
        envelope.redactions_count += title_red.redactions_count;
        let reasons_joined = stale.stale_reasons.join(", ");
        let reasons_red = redact_secrets(&reasons_joined);
        envelope.redactions_count += reasons_red.redactions_count;
        envelope.data.add_alert(DiffAlert {
            kind: DiffAlertKind::StaleMemory,
            severity: CheckSeverity::Warning,
            path: stale.rel_path,
            line: None,
            message: format!(
                "STALE MEMORY: `{}` ({}) — {} (run `klens memory refresh {}`)",
                stale.id, title_red.text, reasons_red.text, stale.id
            ),
        });
    }
    stale_count
}

fn attach_memory_notes_to_result(
    exported_notes: &[ExportedMemoryItem],
    result: &mut ReadResultData,
    stale_ids: &mut BTreeSet<String>,
) -> (usize, Option<Omission>) {
    let mut matched: Vec<ReadMemoryNote> = Vec::new();
    let mut redactions = 0usize;

    for item in exported_notes {
        let linked = item.note.frontmatter.anchors.iter().any(|anchor| {
            anchor_matches_read(
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

        let is_stale = !item.verification.fresh;
        matched.push(ReadMemoryNote {
            id: item.note.frontmatter.id.clone(),
            title: title_red.text,
            kind: item.note.frontmatter.kind.as_str().to_string(),
            trust: item.verification.trust,
            is_stale,
            stale_reasons,
            snippet,
        });
    }

    if matched.is_empty() {
        return (redactions, None);
    }

    // Deterministic order: STALE first, then `feedback`, then note ID ASC.
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

    for note in &matched {
        if note.is_stale {
            stale_ids.insert(note.id.clone());
        }
    }

    let mut bundle = result.context.take().unwrap_or_default();
    bundle.memory = matched;
    bundle.memory_omitted = memory_omitted;
    if !bundle.is_empty() {
        result.context = Some(bundle);
    }

    (redactions, omission)
}

fn anchor_matches_read(
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
    symbol_name_matches(anchor_sym, qname)
        || query
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_some_and(|q| symbol_name_matches(anchor_sym, q))
}

fn symbol_name_matches(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    ["::", ".", " "]
        .iter()
        .any(|sep| a.ends_with(&format!("{sep}{b}")) || b.ends_with(&format!("{sep}{a}")))
}

fn require_string<'a>(args: &'a Value, field: &str) -> Result<&'a str, McpError> {
    args.get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| McpError::InvalidParams(format!("`{field}` must be a non-empty string")))
}

fn optional_non_empty_string(args: &Value, field: &str) -> Result<Option<String>, McpError> {
    match args.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(val) => {
            let s = val
                .as_str()
                .ok_or_else(|| McpError::InvalidParams(format!("`{field}` must be a string")))?;
            let trimmed = s.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
    }
}

fn parse_optional_kind(args: &Value) -> Result<Option<MemoryKind>, McpError> {
    match optional_non_empty_string(args, "kind")? {
        Some(s) => Ok(Some(MemoryKind::parse(&s)?)),
        None => Ok(None),
    }
}

fn parse_optional_string_array(args: &Value, field: &str) -> Result<Option<Vec<String>>, McpError> {
    match args.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(val) => {
            let arr = val.as_array().ok_or_else(|| {
                McpError::InvalidParams(format!("`{field}` must be an array of strings"))
            })?;
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                let s = item.as_str().ok_or_else(|| {
                    McpError::InvalidParams(format!("`{field}` elements must all be strings"))
                })?;
                out.push(s.to_string());
            }
            Ok(Some(out))
        }
    }
}

fn parse_optional_anchors(args: &Value) -> Result<Option<Vec<AnchorSpec>>, McpError> {
    let Some(raw) = parse_optional_string_array(args, "anchors")? else {
        return Ok(None);
    };
    let mut specs = Vec::with_capacity(raw.len());
    for item in &raw {
        specs.push(AnchorSpec::parse(item)?);
    }
    Ok(Some(specs))
}
