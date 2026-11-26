use std::collections::BTreeSet;
use std::fmt::Write as _;

use klens_core::{
    Omission, OmissionKind, ProvenanceEnvelope, RawFallback, RelPath, SymbolInfo, SymbolKind,
    TokenBudget, TrustLevel, estimate_tokens, redact_secrets,
};
use serde::{Deserialize, Serialize};

use crate::error::CodeError;
use crate::index::{CodeIndex, FileSyncOutcome};
use crate::store::ParseStatus;

/// AST outline of a single indexed file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOutline {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parser_id: Option<String>,
    pub line_count: usize,
    pub total_symbols: usize,
    pub parse_status: ParseStatus,
    pub symbols: Vec<SymbolInfo>,
}

/// Outline payload supporting either a single file or a directory of files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutlinePayload {
    pub files: Vec<FileOutline>,
    pub total_files: usize,
    pub total_symbols: usize,
}

/// Produce a provenance-wrapped AST outline for a single confined file.
pub fn outline_file(
    index: &mut CodeIndex,
    rel: &RelPath,
    budget_tokens: Option<usize>,
) -> Result<ProvenanceEnvelope<OutlinePayload>, CodeError> {
    let (_, canonical_rel) = index.project_root().resolve_existing_with_extra(
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
                "file `{}` could not be parsed cleanly (fail-closed fallback)",
                canonical_rel.as_str()
            )
        });
        let file_outline = FileOutline {
            path: canonical_rel.as_str().to_string(),
            language_id: record.language_id,
            parser_id: None,
            line_count: record.line_count,
            total_symbols: 0,
            parse_status: ParseStatus::Fallback,
            symbols: Vec::new(),
        };
        let payload = OutlinePayload {
            files: vec![file_outline],
            total_files: 1,
            total_symbols: 0,
        };
        let envelope = ProvenanceEnvelope::new(TrustLevel::UnparsedFallback, project_id, payload)
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
            });
        return Ok(envelope);
    }

    let all_symbols = index.store().get_symbols_for_file(&canonical_rel)?;
    let mut budget = budget_tokens.map(TokenBudget::new);
    let mut redactions_count = 0usize;
    let mut omissions = Vec::new();
    let mut warnings = Vec::new();

    if let Some(w) = record.parse_warning {
        warnings.push(format!("{}: {w}", canonical_rel.as_str()));
    }

    let parser_id = record
        .parse_status
        .is_external()
        .then(|| record.parser_id.clone());
    let file_trust = if record.parse_status.is_external() {
        TrustLevel::ExternalParser
    } else {
        TrustLevel::VerifiedAst
    };

    let file_outline = build_file_outline(
        &canonical_rel,
        record.language_id,
        parser_id,
        record.line_count,
        record.parse_status,
        all_symbols,
        budget.as_mut(),
        &mut redactions_count,
        &mut omissions,
    );

    let total_symbols = file_outline.total_symbols;
    let payload = OutlinePayload {
        files: vec![file_outline],
        total_files: 1,
        total_symbols,
    };

    let mut env = ProvenanceEnvelope::new(file_trust, project_id, payload)
        .with_redactions_count(redactions_count);
    for w in warnings {
        env = env.with_warning(w);
    }
    for om in omissions {
        env = env.with_omission(om);
    }
    Ok(env)
}

/// Produce a provenance-wrapped AST outline for a file or directory inside the project.
///
/// Pass `rel = None` to outline the entire project root.
pub fn outline_path(
    index: &mut CodeIndex,
    rel: Option<&RelPath>,
    budget_tokens: Option<usize>,
) -> Result<ProvenanceEnvelope<OutlinePayload>, CodeError> {
    if let Some(rel_path) = rel {
        let (abs, canonical_rel) = index.project_root().resolve_existing_with_extra(
            rel_path.as_str(),
            &index.project_config().extra_sensitive_patterns,
        )?;
        if abs.is_file() {
            return outline_file(index, &canonical_rel, budget_tokens);
        }
        return outline_directory(index, Some(&canonical_rel), budget_tokens);
    }

    outline_directory(index, None, budget_tokens)
}

fn outline_directory(
    index: &mut CodeIndex,
    subdir: Option<&RelPath>,
    budget_tokens: Option<usize>,
) -> Result<ProvenanceEnvelope<OutlinePayload>, CodeError> {
    let files = index.sync_directory(subdir)?;
    let project_id = index.project_root().project_id().to_string();
    let total_files = files.len();

    // Compute true directory-wide symbol total across ALL synced files so
    // `total_symbols` stays consistent with `total_files` even when token
    // budgeting truncates the rendered file list early (Constitution Article 7).
    let mut total_symbols = 0usize;
    for rel in &files {
        total_symbols += index.store().count_symbols_for_file(rel)?;
    }

    let mut budget = budget_tokens.map(TokenBudget::new);
    let mut redactions_count = 0usize;
    let mut omissions = Vec::new();
    let mut warnings = Vec::new();
    let mut outlined_files = Vec::new();
    let mut builtin_parsed_count = 0usize;
    let mut external_parsed_count = 0usize;
    let mut external_parser_ids: BTreeSet<String> = BTreeSet::new();
    let mut fallback_count = 0usize;

    for (idx, rel) in files.iter().enumerate() {
        let Some(record) = index.store().get_file(rel)? else {
            continue;
        };

        if let Some(b) = budget.as_mut() {
            let header_cost = estimate_tokens(&format!("## {}\n", rel.as_str()));
            if !b.try_consume(header_cost) {
                let remaining = files.len().saturating_sub(idx);
                if remaining > 0 {
                    omissions.push(Omission::items(remaining, "token_budget_exceeded"));
                }
                break;
            }
        }

        if record.parse_status == ParseStatus::Fallback {
            fallback_count += 1;
            if let Some(warn) = &record.parse_warning {
                // Only warn loudly for known languages with syntax errors or keep concise note.
                if record.language_id.is_some() {
                    warnings.push(format!("{}: {warn}", rel.as_str()));
                }
            }
            outlined_files.push(FileOutline {
                path: rel.as_str().to_string(),
                language_id: record.language_id,
                parser_id: None,
                line_count: record.line_count,
                total_symbols: 0,
                parse_status: ParseStatus::Fallback,
                symbols: Vec::new(),
            });
            continue;
        }

        let ext_parser_id = if record.parse_status.is_external() {
            external_parsed_count += 1;
            external_parser_ids.insert(record.parser_id.clone());
            Some(record.parser_id.clone())
        } else {
            builtin_parsed_count += 1;
            None
        };
        let all_symbols = index.store().get_symbols_for_file(rel)?;

        let file_outline = build_file_outline(
            rel,
            record.language_id,
            ext_parser_id,
            record.line_count,
            record.parse_status,
            all_symbols,
            budget.as_mut(),
            &mut redactions_count,
            &mut omissions,
        );
        outlined_files.push(file_outline);

        if let Some(b) = budget.as_ref()
            && b.is_exhausted()
        {
            let remaining = files.len().saturating_sub(idx + 1);
            if remaining > 0 {
                omissions.push(Omission::items(remaining, "token_budget_exceeded"));
            }
            break;
        }
    }

    let parsed_count = builtin_parsed_count + external_parsed_count;
    let trust = if parsed_count == 0 && fallback_count > 0 {
        TrustLevel::UnparsedFallback
    } else if external_parsed_count > 0 {
        let ids: Vec<String> = external_parser_ids.into_iter().collect();
        warnings.push(format!(
            "{external_parsed_count} file(s) parsed via external language sidecar(s) [{}]; trust downgraded from VERIFIED_AST to EXTERNAL_PARSER",
            ids.join(", ")
        ));
        TrustLevel::ExternalParser
    } else {
        TrustLevel::VerifiedAst
    };

    if fallback_count > 0 && parsed_count > 0 {
        warnings.push(format!(
            "{fallback_count} file(s) had unsupported extensions or syntax errors and were marked UNPARSED_FALLBACK"
        ));
    }

    let payload = OutlinePayload {
        files: outlined_files,
        total_files,
        total_symbols,
    };

    let mut env =
        ProvenanceEnvelope::new(trust, project_id, payload).with_redactions_count(redactions_count);
    for w in warnings {
        env = env.with_warning(w);
    }
    for om in omissions {
        env = env.with_omission(om);
    }
    if trust == TrustLevel::UnparsedFallback && total_files > 0 {
        env = env.with_raw_fallback(RawFallback {
            reason: "no files in target could be parsed with an AST analyzer".to_string(),
            path: subdir.map(|s| s.as_str().to_string()),
            hint: Some("Use `klens read <file> --lines <start:end>` for raw inspection.".into()),
        });
    }

    Ok(env)
}

#[allow(clippy::too_many_arguments)]
fn build_file_outline(
    rel: &RelPath,
    language_id: Option<String>,
    parser_id: Option<String>,
    line_count: usize,
    parse_status: ParseStatus,
    all_symbols: Vec<SymbolInfo>,
    mut budget: Option<&mut TokenBudget>,
    redactions_count: &mut usize,
    omissions: &mut Vec<Omission>,
) -> FileOutline {
    let total_symbols = all_symbols.len();
    let mut kept_symbols = Vec::with_capacity(total_symbols);
    let mut omitted_start_line: Option<usize> = None;
    let mut omitted_end_line: Option<usize> = None;
    let mut omitted_count = 0usize;

    let mut body_lines_omitted = 0usize;
    let mut first_body_line: Option<usize> = None;
    let mut last_body_line: Option<usize> = None;

    for mut sym in all_symbols {
        let redacted = redact_secrets(&sym.signature);
        if redacted.redactions_count > 0 {
            *redactions_count += redacted.redactions_count;
            sym.signature = redacted.text;
        }

        let line_cost = estimate_tokens(&format_symbol_line(&sym));
        let fits = match budget.as_deref_mut() {
            Some(b) => b.try_consume(line_cost),
            None => true,
        };

        if fits {
            if sym.end_line > sym.start_line {
                body_lines_omitted += sym.end_line - sym.start_line;
                first_body_line = Some(
                    first_body_line.map_or(sym.start_line + 1, |cur| cur.min(sym.start_line + 1)),
                );
                last_body_line =
                    Some(last_body_line.map_or(sym.end_line, |cur| cur.max(sym.end_line)));
            }
            kept_symbols.push(sym);
        } else {
            omitted_count += 1;
            omitted_start_line =
                Some(omitted_start_line.map_or(sym.start_line, |cur| cur.min(sym.start_line)));
            omitted_end_line =
                Some(omitted_end_line.map_or(sym.end_line, |cur| cur.max(sym.end_line)));
        }
    }

    if omitted_count > 0 {
        omissions.push(Omission {
            kind: OmissionKind::Symbols,
            path: Some(rel.as_str().to_string()),
            start_line: omitted_start_line,
            end_line: omitted_end_line,
            count: omitted_count,
            reason: "token_budget_exceeded".to_string(),
        });
    } else if body_lines_omitted > 0 {
        omissions.push(Omission {
            kind: OmissionKind::Lines,
            path: Some(rel.as_str().to_string()),
            start_line: first_body_line,
            end_line: last_body_line,
            count: body_lines_omitted,
            reason: "outline_body_omitted".to_string(),
        });
    }

    FileOutline {
        path: rel.as_str().to_string(),
        language_id,
        parser_id,
        line_count,
        total_symbols,
        parse_status,
        symbols: kept_symbols,
    }
}

/// Format a single outline symbol line deterministically.
pub fn format_symbol_line(sym: &SymbolInfo) -> String {
    let indent = if sym.parent.is_some() { "  " } else { "" };
    let kind_tag = short_kind_tag(sym.kind);
    format!(
        "{indent}L{}-L{} [{kind_tag}] {} :: {}",
        sym.start_line, sym.end_line, sym.qualified_name, sym.signature
    )
}

/// Render an outline envelope into deterministic, human- and AI-friendly plain text.
pub fn format_outline_text(envelope: &ProvenanceEnvelope<OutlinePayload>) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[{}] files={} symbols={}",
        crate::trust_label(envelope.trust),
        envelope.data.total_files,
        envelope.data.total_symbols
    );

    for warning in &envelope.warnings {
        let _ = writeln!(out, "WARNING: {warning}");
    }

    for file in &envelope.data.files {
        let lang = file.language_id.as_deref().unwrap_or("unknown");
        let _ = writeln!(
            out,
            "\n# {} ({lang}, {} lines, {} symbols)",
            file.path, file.line_count, file.total_symbols
        );

        if file.parse_status == ParseStatus::Fallback {
            let _ = writeln!(out, "  // [UNPARSED_FALLBACK: no AST symbols extracted]");
            continue;
        }

        for sym in &file.symbols {
            let _ = writeln!(out, "{}", format_symbol_line(sym));
        }

        for om in &envelope.omissions {
            if om.path.as_deref() == Some(file.path.as_str()) && om.kind == OmissionKind::Symbols {
                let range = match (om.start_line, om.end_line) {
                    (Some(s), Some(e)) => format!("L{s}-L{e}"),
                    _ => "unknown range".to_string(),
                };
                let _ = writeln!(
                    out,
                    "// ... [omitted {} symbols: {range} ({})]",
                    om.count, om.reason
                );
            }
        }
    }

    for om in &envelope.omissions {
        if om.kind == OmissionKind::Items {
            let _ = writeln!(out, "\n// ... [omitted {} files ({})]", om.count, om.reason);
        }
    }

    if let Some(fb) = &envelope.raw_fallback
        && let Some(hint) = &fb.hint
    {
        let _ = writeln!(out, "HINT: {hint}");
    }

    out
}

fn short_kind_tag(kind: SymbolKind) -> &'static str {
    match kind {
        SymbolKind::Function => "fn",
        SymbolKind::Method => "method",
        SymbolKind::Struct => "struct",
        SymbolKind::Enum => "enum",
        SymbolKind::Trait => "trait",
        SymbolKind::Interface => "interface",
        SymbolKind::Class => "class",
        SymbolKind::TypeAlias => "type",
        SymbolKind::Const => "const",
        SymbolKind::Static => "static",
        SymbolKind::Module => "mod",
        SymbolKind::Macro => "macro",
        SymbolKind::Variable => "var",
        SymbolKind::Other => "item",
    }
}
