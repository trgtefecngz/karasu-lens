use std::fmt::Write as _;
use std::fs;

use klens_core::{
    ProvenanceEnvelope, RawFallback, RelPath, SymbolInfo, SymbolKind, TrustLevel,
    normalize_line_endings, redact_secrets,
};
use serde::{Deserialize, Serialize};

use crate::error::CodeError;
use crate::index::{CodeIndex, FileSyncOutcome, is_binary_bytes};
use crate::read_context::{
    ReadContextBundle, ReadInclude, format_read_context_text, populate_code_context_bundle,
};
use crate::store::ParseStatus;

/// 1-based inclusive line range (`start..=end`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LineRange {
    pub start: usize,
    pub end: usize,
}

impl LineRange {
    /// Create a validated 1-based inclusive line range.
    pub fn new(start: usize, end: usize) -> Result<Self, CodeError> {
        if start == 0 || end == 0 {
            return Err(CodeError::InvalidLineRange {
                spec: format!("{start}:{end}"),
                reason: "line numbers are 1-based and must be >= 1".to_string(),
            });
        }
        if start > end {
            return Err(CodeError::InvalidLineRange {
                spec: format!("{start}:{end}"),
                reason: "start line must be <= end line".to_string(),
            });
        }
        Ok(Self { start, end })
    }

    /// Parse `<start:end>` (or `<start-end>` or `<line>`) into a [`LineRange`].
    pub fn parse(spec: &str) -> Result<Self, CodeError> {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return Err(CodeError::InvalidLineRange {
                spec: spec.to_string(),
                reason: "empty range".to_string(),
            });
        }
        let parts = trimmed.split_once(':').or_else(|| trimmed.split_once('-'));
        match parts {
            Some((a, b)) => {
                let start: usize = a.trim().parse().map_err(|_| CodeError::InvalidLineRange {
                    spec: spec.to_string(),
                    reason: format!("invalid start line `{}`", a.trim()),
                })?;
                let end: usize = b.trim().parse().map_err(|_| CodeError::InvalidLineRange {
                    spec: spec.to_string(),
                    reason: format!("invalid end line `{}`", b.trim()),
                })?;
                Self::new(start, end)
            }
            None => {
                let single: usize = trimmed.parse().map_err(|_| CodeError::InvalidLineRange {
                    spec: spec.to_string(),
                    reason: "expected `<start:end>` or `<line>`".to_string(),
                })?;
                Self::new(single, single)
            }
        }
    }
}

/// Single target specification for surgical or batch reads (`targets: [...]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadTarget {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lines: Option<LineRange>,
}

impl ReadTarget {
    pub fn symbol(path: impl Into<String>, symbol: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            symbol: Some(symbol.into()),
            lines: None,
        }
    }

    pub fn lines(path: impl Into<String>, range: LineRange) -> Self {
        Self {
            path: path.into(),
            symbol: None,
            lines: Some(range),
        }
    }
}

/// Status of a surgical read request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadStatus {
    Ok,
    AmbiguousSymbol,
    NotFound,
    UnparsedFallback,
    Error,
}

/// Disambiguation candidate returned on `AMBIGUOUS_SYMBOL` (Constitution Article 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolCandidate {
    pub qualified_name: String,
    pub kind: SymbolKind,
    pub signature: String,
    pub start_line: usize,
    pub end_line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

/// Payload of a single symbol or line-range read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadResultData {
    pub status: ReadStatus,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualified_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<SymbolKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_lines: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<SymbolCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ReadContextBundle>,
}

/// Single entry inside a batch read response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchReadItem {
    pub trust: TrustLevel,
    pub redactions_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_fallback: Option<RawFallback>,
    #[serde(flatten)]
    pub result: ReadResultData,
}

/// Deterministic batch read response (`targets: [...]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchReadData {
    pub targets: Vec<BatchReadItem>,
}

/// Surgically read a symbol from a file by querying the **untruncated** AST/SQLite index.
///
/// Constitutional invariants enforced:
/// - Never searches token-truncated `outline` output (Article 2).
/// - Never silently picks the first match when >1 candidates exist → `AMBIGUOUS_SYMBOL` (Article 3).
/// - Never guesses with regex on broken syntax / unsupported files → `UNPARSED_FALLBACK` (Article 1).
/// - Redacts secrets at output gate (Article 8).
pub fn read_symbol(
    index: &mut CodeIndex,
    rel: &RelPath,
    symbol_query: &str,
) -> Result<ProvenanceEnvelope<ReadResultData>, CodeError> {
    let query = symbol_query.trim();
    let (abs_path, canonical_rel) = index.project_root().resolve_existing_with_extra(
        rel.as_str(),
        &index.project_config().extra_sensitive_patterns,
    )?;

    let sync_outcome = index.sync_file(&canonical_rel)?;
    if sync_outcome == FileSyncOutcome::SkippedBinary {
        return Err(CodeError::BinaryFile(canonical_rel.as_str().to_string()));
    }

    let project_id = index.project_root().project_id().to_string();
    let Some(record) = index.store().get_file(&canonical_rel)? else {
        return Err(CodeError::NotAFile(canonical_rel.as_str().to_string()));
    };

    if record.parse_status == ParseStatus::Fallback {
        let reason = record.parse_warning.clone().unwrap_or_else(|| {
            format!(
                "file `{}` could not be parsed cleanly; symbol lookup aborted",
                canonical_rel.as_str()
            )
        });
        let data = ReadResultData {
            status: ReadStatus::UnparsedFallback,
            path: canonical_rel.as_str().to_string(),
            query: Some(query.to_string()),
            qualified_name: None,
            kind: None,
            start_line: None,
            end_line: None,
            total_lines: Some(record.line_count),
            content: None,
            candidates: Vec::new(),
            message: Some(reason.clone()),
            context: None,
        };
        return Ok(
            ProvenanceEnvelope::new(TrustLevel::UnparsedFallback, project_id, data)
                .with_warning(format!("{}: {reason}", canonical_rel.as_str()))
                .with_raw_fallback(RawFallback {
                    reason,
                    path: Some(canonical_rel.as_str().to_string()),
                    hint: Some(format!(
                        "Use `klens read {} --lines 1:{}` to inspect raw lines safely.",
                        canonical_rel.as_str(),
                        if record.line_count == 0 {
                            100
                        } else {
                            record.line_count.min(100)
                        }
                    )),
                }),
        );
    }

    let file_trust = if record.parse_status.is_external() {
        TrustLevel::ExternalParser
    } else {
        TrustLevel::VerifiedAst
    };

    // Query the FULL, untruncated symbol table directly from SQLite.
    let all_symbols = index.store().get_symbols_for_file(&canonical_rel)?;
    let matches = resolve_symbol_matches(&all_symbols, query);

    if matches.is_empty() {
        let data = ReadResultData {
            status: ReadStatus::NotFound,
            path: canonical_rel.as_str().to_string(),
            query: Some(query.to_string()),
            qualified_name: None,
            kind: None,
            start_line: None,
            end_line: None,
            total_lines: Some(record.line_count),
            content: None,
            candidates: Vec::new(),
            message: Some(format!(
                "symbol `{query}` not found in `{}`",
                canonical_rel.as_str()
            )),
            context: None,
        };
        return Ok(ProvenanceEnvelope::new(file_trust, project_id, data));
    }

    if matches.len() > 1 {
        let mut redactions_count = 0usize;
        let candidates: Vec<SymbolCandidate> = matches
            .into_iter()
            .map(|s| {
                let redacted = redact_secrets(&s.signature);
                redactions_count += redacted.redactions_count;
                SymbolCandidate {
                    qualified_name: s.qualified_name.clone(),
                    kind: s.kind,
                    signature: redacted.text,
                    start_line: s.start_line,
                    end_line: s.end_line,
                    parent: s.parent.clone(),
                }
            })
            .collect();

        let data = ReadResultData {
            status: ReadStatus::AmbiguousSymbol,
            path: canonical_rel.as_str().to_string(),
            query: Some(query.to_string()),
            qualified_name: None,
            kind: None,
            start_line: None,
            end_line: None,
            total_lines: Some(record.line_count),
            content: None,
            candidates,
            message: Some(format!(
                "ambiguous symbol `{query}` in `{}`; re-run with a qualified_name from candidates",
                canonical_rel.as_str()
            )),
            context: None,
        };
        return Ok(ProvenanceEnvelope::new(file_trust, project_id, data)
            .with_redactions_count(redactions_count));
    }

    let sym = matches[0];
    let (content, total_lines, redactions_count, range_warnings) = slice_numbered_lines(
        &abs_path,
        canonical_rel.as_str(),
        LineRange::new(sym.start_line, sym.end_line)?,
    )?;

    let data = ReadResultData {
        status: ReadStatus::Ok,
        path: canonical_rel.as_str().to_string(),
        query: Some(query.to_string()),
        qualified_name: Some(sym.qualified_name.clone()),
        kind: Some(sym.kind),
        start_line: Some(sym.start_line),
        end_line: Some(sym.end_line),
        total_lines: Some(total_lines),
        content: Some(content),
        candidates: Vec::new(),
        message: None,
        context: None,
    };

    let mut env = ProvenanceEnvelope::new(file_trust, project_id, data)
        .with_redactions_count(redactions_count);
    for w in range_warnings {
        env = env.with_warning(w);
    }
    Ok(env)
}

/// Surgically read an explicit 1-based inclusive line range from a confined file.
pub fn read_lines(
    index: &CodeIndex,
    rel: &RelPath,
    range: LineRange,
) -> Result<ProvenanceEnvelope<ReadResultData>, CodeError> {
    let (abs_path, canonical_rel) = index.project_root().resolve_existing_with_extra(
        rel.as_str(),
        &index.project_config().extra_sensitive_patterns,
    )?;

    let project_id = index.project_root().project_id().to_string();
    let (content, total_lines, redactions_count, warnings) =
        slice_numbered_lines(&abs_path, canonical_rel.as_str(), range)?;

    let effective_end = range.end.min(total_lines);
    let data = ReadResultData {
        status: ReadStatus::Ok,
        path: canonical_rel.as_str().to_string(),
        query: Some(format!("{}:{}", range.start, range.end)),
        qualified_name: None,
        kind: None,
        start_line: Some(range.start.min(total_lines.max(1))),
        end_line: Some(effective_end),
        total_lines: Some(total_lines),
        content: Some(content),
        candidates: Vec::new(),
        message: None,
        context: None,
    };

    let mut env = ProvenanceEnvelope::new(TrustLevel::VerifiedRaw, project_id, data)
        .with_redactions_count(redactions_count);
    for w in warnings {
        env = env.with_warning(w);
    }
    Ok(env)
}

/// Read multiple symbols and/or line ranges in a single deterministic batch call (`targets: [...]`).
pub fn read_batch(
    index: &mut CodeIndex,
    targets: &[ReadTarget],
) -> Result<ProvenanceEnvelope<BatchReadData>, CodeError> {
    let project_id = index.project_root().project_id().to_string();
    let mut items = Vec::with_capacity(targets.len());
    let mut total_redactions = 0usize;
    let mut aggregated_warnings = Vec::new();
    let mut has_fallback = false;
    let mut has_external = false;
    let mut all_verified_ast = !targets.is_empty();

    for target in targets {
        let rel = match RelPath::normalize(&target.path) {
            Ok(r) => r,
            Err(err) => {
                all_verified_ast = false;
                let msg = err.to_string();
                aggregated_warnings.push(format!("{}: {msg}", target.path));
                items.push(BatchReadItem {
                    trust: TrustLevel::UnparsedFallback,
                    redactions_count: 0,
                    warnings: vec![msg.clone()],
                    raw_fallback: None,
                    result: ReadResultData {
                        status: ReadStatus::Error,
                        path: target.path.clone(),
                        query: target
                            .symbol
                            .clone()
                            .or_else(|| target.lines.map(|r| format!("{}:{}", r.start, r.end))),
                        qualified_name: None,
                        kind: None,
                        start_line: None,
                        end_line: None,
                        total_lines: None,
                        content: None,
                        candidates: Vec::new(),
                        message: Some(msg),
                        context: None,
                    },
                });
                has_fallback = true;
                continue;
            }
        };

        let single_res = match (&target.symbol, target.lines) {
            (Some(sym), None) => read_symbol(index, &rel, sym),
            (None, Some(range)) => read_lines(index, &rel, range),
            _ => Err(CodeError::InvalidReadTarget),
        };

        match single_res {
            Ok(env) => {
                if env.trust == TrustLevel::UnparsedFallback {
                    has_fallback = true;
                }
                if env.trust == TrustLevel::ExternalParser {
                    has_external = true;
                }
                if env.trust != TrustLevel::VerifiedAst {
                    all_verified_ast = false;
                }
                total_redactions += env.redactions_count;
                for w in &env.warnings {
                    aggregated_warnings.push(w.clone());
                }
                items.push(BatchReadItem {
                    trust: env.trust,
                    redactions_count: env.redactions_count,
                    warnings: env.warnings,
                    raw_fallback: env.raw_fallback,
                    result: env.data,
                });
            }
            Err(err) => {
                all_verified_ast = false;
                has_fallback = true;
                let msg = err.to_string();
                aggregated_warnings.push(format!("{}: {msg}", rel.as_str()));
                items.push(BatchReadItem {
                    trust: TrustLevel::UnparsedFallback,
                    redactions_count: 0,
                    warnings: vec![msg.clone()],
                    raw_fallback: None,
                    result: ReadResultData {
                        status: ReadStatus::Error,
                        path: rel.as_str().to_string(),
                        query: target
                            .symbol
                            .clone()
                            .or_else(|| target.lines.map(|r| format!("{}:{}", r.start, r.end))),
                        qualified_name: None,
                        kind: None,
                        start_line: None,
                        end_line: None,
                        total_lines: None,
                        content: None,
                        candidates: Vec::new(),
                        message: Some(msg),
                        context: None,
                    },
                });
            }
        }
    }

    let overall_trust = if has_fallback {
        TrustLevel::UnparsedFallback
    } else if has_external {
        TrustLevel::ExternalParser
    } else if all_verified_ast {
        TrustLevel::VerifiedAst
    } else {
        TrustLevel::VerifiedRaw
    };

    let mut env =
        ProvenanceEnvelope::new(overall_trust, project_id, BatchReadData { targets: items })
            .with_redactions_count(total_redactions);
    for w in aggregated_warnings {
        env = env.with_warning(w);
    }
    Ok(env)
}

/// Attach requested `imports` and/or `impact` context onto a single `ReadStatus::Ok` envelope.
pub fn attach_code_context_to_read(
    index: &mut CodeIndex,
    envelope: &mut ProvenanceEnvelope<ReadResultData>,
    includes: &[ReadInclude],
) -> Result<(), CodeError> {
    if envelope.data.status != ReadStatus::Ok {
        return Ok(());
    }
    let (bundle, redactions) = populate_code_context_bundle(
        index,
        &envelope.data.path,
        envelope.data.qualified_name.as_deref(),
        envelope.data.context.take(),
        includes.contains(&ReadInclude::Imports),
        includes.contains(&ReadInclude::Impact),
        &mut envelope.omissions,
    )?;
    envelope.data.context = bundle;
    envelope.redactions_count += redactions;
    Ok(())
}

/// Attach requested `imports` and/or `impact` context onto every `ReadStatus::Ok` batch item.
pub fn attach_code_context_to_batch(
    index: &mut CodeIndex,
    envelope: &mut ProvenanceEnvelope<BatchReadData>,
    includes: &[ReadInclude],
) -> Result<(), CodeError> {
    let want_imports = includes.contains(&ReadInclude::Imports);
    let want_impact = includes.contains(&ReadInclude::Impact);
    if !want_imports && !want_impact {
        return Ok(());
    }
    for item in &mut envelope.data.targets {
        if item.result.status != ReadStatus::Ok {
            continue;
        }
        let (bundle, redactions) = populate_code_context_bundle(
            index,
            &item.result.path,
            item.result.qualified_name.as_deref(),
            item.result.context.take(),
            want_imports,
            want_impact,
            &mut envelope.omissions,
        )?;
        item.result.context = bundle;
        item.redactions_count += redactions;
        envelope.redactions_count += redactions;
    }
    Ok(())
}

/// Render a single read envelope into deterministic plain text.
pub fn format_read_text(envelope: &ProvenanceEnvelope<ReadResultData>) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "[{}] {} ({:?})",
        crate::trust_label(envelope.trust),
        envelope.data.path,
        envelope.data.status
    );
    if let Some(qname) = &envelope.data.qualified_name {
        let _ = write!(out, " `{qname}`");
    }
    if let (Some(s), Some(e)) = (envelope.data.start_line, envelope.data.end_line) {
        let _ = write!(out, " [L{s}-L{e}]");
    }
    let _ = writeln!(out);

    for w in &envelope.warnings {
        let _ = writeln!(out, "WARNING: {w}");
    }

    match envelope.data.status {
        ReadStatus::Ok => {
            if let Some(content) = &envelope.data.content {
                let _ = writeln!(out, "{content}");
            }
            if let Some(ctx) = &envelope.data.context {
                out.push_str(&format_read_context_text(ctx));
            }
        }
        ReadStatus::AmbiguousSymbol => {
            let _ = writeln!(
                out,
                "AMBIGUOUS_SYMBOL: `{}` matched {} symbols (pass exact qualified_name):",
                envelope.data.query.as_deref().unwrap_or(""),
                envelope.data.candidates.len()
            );
            for cand in &envelope.data.candidates {
                let _ = writeln!(
                    out,
                    "  - {} [L{}-L{}] :: {}",
                    cand.qualified_name, cand.start_line, cand.end_line, cand.signature
                );
            }
        }
        ReadStatus::NotFound | ReadStatus::UnparsedFallback | ReadStatus::Error => {
            if let Some(msg) = &envelope.data.message {
                let _ = writeln!(out, "{msg}");
            }
            if let Some(fb) = &envelope.raw_fallback
                && let Some(hint) = &fb.hint
            {
                let _ = writeln!(out, "HINT: {hint}");
            }
        }
    }

    out
}

/// Render a batch read envelope into deterministic plain text.
pub fn format_batch_read_text(envelope: &ProvenanceEnvelope<BatchReadData>) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[{}] batch_targets={}",
        crate::trust_label(envelope.trust),
        envelope.data.targets.len()
    );
    for (idx, item) in envelope.data.targets.iter().enumerate() {
        let _ = writeln!(out, "\n--- target #{}: {} ---", idx + 1, item.result.path);
        let sub_env = ProvenanceEnvelope {
            schema_version: envelope.schema_version,
            trust: item.trust,
            project_id: envelope.project_id.clone(),
            warnings: item.warnings.clone(),
            omissions: Vec::new(),
            redactions_count: item.redactions_count,
            raw_fallback: item.raw_fallback.clone(),
            data: item.result.clone(),
        };
        out.push_str(&format_read_text(&sub_env));
    }
    out
}

fn resolve_symbol_matches<'a>(symbols: &'a [SymbolInfo], query: &str) -> Vec<&'a SymbolInfo> {
    // Tier 1: exact `qualified_name` match.
    let exact_q: Vec<&SymbolInfo> = symbols
        .iter()
        .filter(|s| s.qualified_name == query)
        .collect();
    if !exact_q.is_empty() {
        return exact_q;
    }

    // Tier 2: exact short `name` match.
    let exact_n: Vec<&SymbolInfo> = symbols.iter().filter(|s| s.name == query).collect();
    if !exact_n.is_empty() {
        return exact_n;
    }

    // Tier 3: unambiguous qualified suffix match (e.g. `User::new` -> `impl User::new`).
    let suffix_colon = format!("::{query}");
    let suffix_dot = format!(".{query}");
    let suffix_space = format!(" {query}");
    symbols
        .iter()
        .filter(|s| {
            s.qualified_name.ends_with(&suffix_colon)
                || s.qualified_name.ends_with(&suffix_dot)
                || s.qualified_name.ends_with(&suffix_space)
        })
        .collect()
}

fn slice_numbered_lines(
    abs_path: &std::path::Path,
    display_path: &str,
    range: LineRange,
) -> Result<(String, usize, usize, Vec<String>), CodeError> {
    let meta = fs::metadata(abs_path).map_err(|source| CodeError::Io {
        path: abs_path.to_path_buf(),
        source,
    })?;
    if !meta.is_file() {
        return Err(CodeError::NotAFile(display_path.to_string()));
    }

    let bytes = fs::read(abs_path).map_err(|source| CodeError::Io {
        path: abs_path.to_path_buf(),
        source,
    })?;
    if is_binary_bytes(&bytes) {
        return Err(CodeError::BinaryFile(abs_path.display().to_string()));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| CodeError::BinaryFile(abs_path.display().to_string()))?;
    let normalized = normalize_line_endings(text);
    let lines: Vec<&str> = normalized.lines().collect();
    let total_lines = lines.len();
    let mut warnings = Vec::new();

    if total_lines == 0 {
        warnings.push("file is empty (0 lines)".to_string());
        return Ok((String::new(), 0, 0, warnings));
    }

    if range.start > total_lines {
        return Err(CodeError::InvalidLineRange {
            spec: format!("{}:{}", range.start, range.end),
            reason: format!(
                "start line {} exceeds file length ({total_lines} lines)",
                range.start
            ),
        });
    }

    let clamped_end = if range.end > total_lines {
        warnings.push(format!(
            "requested end line {} clamped to EOF (L{total_lines})",
            range.end
        ));
        total_lines
    } else {
        range.end
    };

    let mut formatted = String::new();
    for (idx, line) in lines[range.start - 1..clamped_end].iter().enumerate() {
        let line_no = range.start + idx;
        if idx > 0 {
            formatted.push('\n');
        }
        let _ = write!(formatted, "L{line_no}| {line}");
    }

    let redacted = redact_secrets(&formatted);
    Ok((
        redacted.text,
        total_lines,
        redacted.redactions_count,
        warnings,
    ))
}
